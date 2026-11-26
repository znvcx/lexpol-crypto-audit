/**
 * Cycle de vie du coffre chiffré du Studio (création, déverrouillage, changement de mot de passe,
 * réinitialisation de la phrase, migration de l'ancien schéma).
 *
 * Réglage PocketBase `user_settings` (clé `crypto`, voir `StudioCryptoDocument`). Il ne contient
 * que des enveloppes chiffrées et des paramètres publics. La phrase de récupération et le mot de
 * passe ne quittent jamais l'appareil et ne sont conservés que le temps d'un appel.
 */
import { AuthError, AuthUser, auth, verifyCurrentPassword } from './pocketbase';
import {
  createUserSetting,
  deleteDocument,
  deleteUserSetting,
  getDocument,
  getUserSetting,
  listDocuments,
  setDocument,
  setUserSetting,
} from './pbStore';
import { cleanStoredObject } from './dossiers';
import { AnalysisRecord, Dossier, ReformulationRecord } from '../types';
import {
  StudioCryptoDocument,
  StudioDek,
  UnlockedKeys,
  VaultCryptoError,
  RecordKeys,
  DeviceWrappedDek,
  assertCryptoDocument,
  checkRecoveryPhraseInput,
  createCryptoDocument,
  StoredFieldNote,
  decryptAnalysisFromStorage,
  decryptDossierFromStorage,
  decryptFieldNoteFromStorage,
  decryptLandmarkFromStorage,
  decryptReformulationFromStorage,
  encryptAnalysisForStorage,
  encryptDossierForStorage,
  encryptFieldNoteForStorage,
  encryptLandmarkForStorage,
  encryptReformulationForStorage,
  finalizeKeyRotation,
  generateDek,
  generateRecoveryPhrase,
  mnemonicToEntropy,
  needsReencryption,
  pickConfirmationPositions,
  prepareKeyRotation,
  rewrapPasswordEnvelope,
  unlockCryptoDocument,
  unwrapDek,
  unwrapDekFromDevice,
  wrapDekForDevice,
} from '../utils/studioE2ee';
import { REMEMBERED_DEK_PREFIX, purgeSensitiveStudioStorage } from '../utils/studioCrypto';
import { deviceStoreDelete, deviceStoreGet, deviceStoreSet } from '../utils/vaultDeviceStore';
import {
  enrollBiometricVaultUnlock,
  hasBiometricVaultEnrollment,
  isBiometricUnlockSupported,
  removeBiometricVaultUnlock,
  unlockDekWithBiometrics,
} from '../utils/webauthnVault';
import {
  StudioVaultLockedError,
  getRecordKeys,
  getStudioVaultState,
  lockStudioSession,
  setSessionKeys,
  setStudioVaultState,
} from './studioVaultSession';
import {
  hasValidTwoFactorSession,
  isTwoFactorSessionPending,
  TWO_FACTOR_SESSION_EVENT,
} from './twoFactorSession';

export type StudioVaultErrorCode =
  | 'wrong-password'
  | 'wrong-phrase'
  | 'invalid-phrase'
  | 'not-signed-in'
  | 'already-exists'
  | 'no-vault'
  | 'locked'
  | 'password-required'
  | 'network'
  | 'unknown';

export class StudioVaultError extends Error {
  readonly code: StudioVaultErrorCode;
  constructor(code: StudioVaultErrorCode) {
    super(code);
    this.name = 'StudioVaultError';
    this.code = code;
  }
}

/** Taille des lots de rechiffrement (chaque document est relu juste avant d'être réécrit). */
const REENCRYPT_TX_SIZE = 100;
const CRYPTO_SETTING_KEY = 'crypto';
/** Préfixe des repères du document du coffre, conservés sur l'appareil (non purgés à la déconnexion). */
const VAULT_PIN_PREFIX = 'vault-pin:';

let currentDoc: StudioCryptoDocument | null = null;
let initToken = 0;
let authListenerStarted = false;

function rememberKey(uid: string): string {
  return `${REMEMBERED_DEK_PREFIX}${uid}`;
}

/**
 * Tous les comptes PocketBase s'ouvrent par e-mail et mot de passe. Les anciens comptes Google
 * sans enveloppe « mot de passe » déverrouillent avec leur phrase, puis reconstruisent l'enveloppe
 * (même parcours qu'après une réinitialisation du mot de passe).
 */
export function isPasswordAccount(user: AuthUser | null | undefined): boolean {
  return Boolean(user?.email);
}

function requireUser(): AuthUser {
  const user = auth.currentUser;
  if (!user) throw new StudioVaultError('not-signed-in');
  return user;
}

function mapAuthError(err: any): StudioVaultError {
  if (err instanceof StudioVaultError) return err;
  if (err instanceof VaultCryptoError) {
    return new StudioVaultError(err.code === 'invalid-phrase' ? 'invalid-phrase' : 'unknown');
  }
  const code = err instanceof AuthError ? err.code : String(err?.code || '');
  if (code === 'auth/wrong-password' || code === 'auth/invalid-credential')
    return new StudioVaultError('wrong-password');
  if (code === 'auth/network-request-failed') return new StudioVaultError('network');
  return new StudioVaultError('unknown');
}

/** Vérifie le mot de passe du compte avant de l'utiliser pour une enveloppe. */
async function verifyAccountPassword(user: AuthUser, password: string): Promise<void> {
  if (!user.email) throw new StudioVaultError('password-required');
  try {
    await verifyCurrentPassword(password);
  } catch (err) {
    throw mapAuthError(err);
  }
}

/**
 * Repère conservé sur l'appareil (IndexedDB, jamais effacé à la déconnexion) : le document du coffre vient
 * d'un serveur qui n'authentifie pas ses champs en clair. Une fois vu, le mode strict ne se désactive plus,
 * et un document plus ancien que le dernier vu (retour arrière) est refusé.
 */
interface VaultPin {
  strict: boolean;
  legacyMigratedAt?: string;
  updatedAt: string;
}

function pinKey(uid: string): string {
  return `${VAULT_PIN_PREFIX}${uid}`;
}

async function applyVaultPin(
  uid: string,
  doc: StudioCryptoDocument
): Promise<StudioCryptoDocument> {
  let pin: VaultPin | undefined;
  try {
    pin = await deviceStoreGet<VaultPin>(pinKey(uid));
  } catch {
    pin = undefined;
  }
  let result = doc;
  if (pin) {
    if (Date.parse(doc.updatedAt) < Date.parse(pin.updatedAt)) {
      throw new VaultCryptoError('corrupted', 'Crypto document older than the last one seen');
    }
    if (pin.strict && !doc.legacyMigratedAt) {
      result = { ...doc, legacyMigratedAt: pin.legacyMigratedAt || pin.updatedAt };
    }
  }
  await rememberVaultPin(uid, result);
  return result;
}

async function rememberVaultPin(uid: string, doc: StudioCryptoDocument): Promise<void> {
  try {
    const previous = await deviceStoreGet<VaultPin>(pinKey(uid));
    const next: VaultPin = {
      strict: Boolean(previous?.strict || doc.legacyMigratedAt),
      legacyMigratedAt: previous?.legacyMigratedAt || doc.legacyMigratedAt,
      updatedAt:
        previous && Date.parse(previous.updatedAt) > Date.parse(doc.updatedAt)
          ? previous.updatedAt
          : doc.updatedAt,
    };
    await deviceStoreSet(pinKey(uid), next);
  } catch {
    // Sans IndexedDB, la protection se limite à la session en cours.
  }
}

async function readCryptoDoc(uid: string): Promise<StudioCryptoDocument | null> {
  const data = await getUserSetting<unknown>(uid, CRYPTO_SETTING_KEY);
  if (!data) return null;
  assertCryptoDocument(data);
  return applyVaultPin(uid, data);
}

async function writeCryptoDoc(uid: string, data: StudioCryptoDocument): Promise<void> {
  await setUserSetting(uid, CRYPTO_SETTING_KEY, cleanStoredObject(data as any));
  currentDoc = data;
  await rememberVaultPin(uid, data);
}

function publishUnlocked(uid: string, unlocked: UnlockedKeys, doc: StudioCryptoDocument): void {
  setSessionKeys(uid, unlocked.active, unlocked.ring, Boolean(doc.legacyMigratedAt));
  currentDoc = doc;
  setStudioVaultState({
    status: 'unlocked',
    uid,
    hasPasswordEnvelope: Boolean(doc.wrappedDekPassword),
    rotationPending: Boolean(doc.rotation),
    errorCode: undefined,
  });
}

// ---------------------------------------------------------------------------
// Initialisation liée à l'authentification
// ---------------------------------------------------------------------------

export async function initStudioVaultForUser(user: AuthUser | null): Promise<void> {
  const token = ++initToken;
  const previousUid = getStudioVaultState().uid;
  if (!user) {
    lockStudioVaultOnSignOut();
    return;
  }
  if (previousUid === user.uid && getStudioVaultState().status === 'unlocked') return;

  currentDoc = null;
  wipeDraft(setupDraft);
  wipeDraft(rotationDraft);
  setupDraft = null;
  rotationDraft = null;
  lockStudioSession('loading');
  setStudioVaultState({
    uid: user.uid,
    isPasswordAccount: isPasswordAccount(user),
    rememberDevice: false,
  });
  // Code 2FA non saisi dans cet onglet : le relais refuserait la lecture. Le coffre reste en
  // chargement et l'initialisation reprend dès que la session 2FA est établie.
  if (isTwoFactorSessionPending(user.uid)) return;

  try {
    const cryptoDoc = await readCryptoDoc(user.uid);
    if (token !== initToken) return;
    if (!cryptoDoc) {
      setStudioVaultState({
        status: 'needs-setup',
        hasPasswordEnvelope: false,
        rotationPending: false,
      });
      return;
    }
    currentDoc = cryptoDoc;
    setStudioVaultState({
      hasPasswordEnvelope: Boolean(cryptoDoc.wrappedDekPassword),
      rotationPending: Boolean(cryptoDoc.rotation),
    });

    const remembered = await deviceStoreGet<DeviceWrappedDek>(rememberKey(user.uid));
    if (token !== initToken) return;
    if (remembered) {
      try {
        const dek = await unwrapDekFromDevice(remembered, user.uid, Boolean(cryptoDoc.rotation));
        const unlocked = await expandRememberedKey(cryptoDoc, user.uid, dek);
        if (token !== initToken) return;
        setStudioVaultState({ rememberDevice: true });
        publishUnlocked(user.uid, unlocked, cryptoDoc);
        void runPostUnlockMaintenance();
        return;
      } catch {
        await deviceStoreDelete(rememberKey(user.uid));
      }
    }
    setStudioVaultState({ status: 'locked' });
  } catch (err) {
    if (token !== initToken) return;
    setStudioVaultState({
      status: 'error',
      errorCode: err instanceof VaultCryptoError ? 'unknown' : 'network',
    });
  }
}

/** Une DEK mémorisée sur l'appareil ne vaut que si elle correspond encore au document enregistré. */
async function expandRememberedKey(
  cryptoDoc: StudioCryptoDocument,
  uid: string,
  dek: StudioDek
): Promise<UnlockedKeys> {
  const ring = new Map([[dek.keyId, dek.key]]);
  if (cryptoDoc.rotation) {
    if (dek.keyId === cryptoDoc.keyId) {
      const next = await unwrapDek(
        cryptoDoc.rotation.wrappedNextDekByCurrent,
        dek.key,
        uid,
        'dek-cross',
        cryptoDoc.rotation.next.keyId
      );
      ring.set(next.keyId, next.key);
      return { active: next, ring };
    }
    if (dek.keyId === cryptoDoc.rotation.next.keyId) {
      const current = await unwrapDek(
        cryptoDoc.rotation.wrappedCurrentDekByNext,
        dek.key,
        uid,
        'dek-cross',
        cryptoDoc.keyId
      );
      ring.set(current.keyId, current.key);
      return { active: dek, ring };
    }
  } else if (dek.keyId === cryptoDoc.keyId) {
    return { active: dek, ring };
  }
  throw new StudioVaultError('wrong-phrase');
}

export function startStudioVaultAuthListener(): () => void {
  if (authListenerStarted) return () => {};
  authListenerStarted = true;
  const unsub = auth.onAuthStateChanged((user) => {
    void initStudioVaultForUser(user);
  });
  const handleTwoFactorSession = () => {
    const user = auth.currentUser;
    if (user && hasValidTwoFactorSession(user.uid)) void initStudioVaultForUser(user);
  };
  window.addEventListener(TWO_FACTOR_SESSION_EVENT, handleTwoFactorSession);
  return () => {
    authListenerStarted = false;
    unsub();
    window.removeEventListener(TWO_FACTOR_SESSION_EVENT, handleTwoFactorSession);
  };
}

/** Relance la lecture du document (par exemple après une erreur réseau). */
export function retryStudioVaultInit(): Promise<void> {
  return initStudioVaultForUser(auth.currentUser);
}

// ---------------------------------------------------------------------------
// Création du coffre
// ---------------------------------------------------------------------------

interface PhraseDraft {
  uid: string;
  dek: StudioDek;
  entropy: Uint8Array;
  confirmPositions: number[];
}

let setupDraft: PhraseDraft | null = null;
let rotationDraft: PhraseDraft | null = null;

function wipeDraft(draft: PhraseDraft | null): void {
  if (draft) draft.entropy.fill(0);
}

export interface PhraseDraftView {
  words: string[];
  /** Positions (0-indexées) des mots à confirmer. */
  confirmPositions: number[];
}

async function newDraft(uid: string): Promise<{ draft: PhraseDraft; view: PhraseDraftView }> {
  const [dek, phrase] = await Promise.all([generateDek(), generateRecoveryPhrase()]);
  const confirmPositions = pickConfirmationPositions(3);
  return {
    draft: { uid, dek, entropy: phrase.entropy, confirmPositions },
    view: { words: phrase.words, confirmPositions },
  };
}

/**
 * Génère une DEK et une phrase de 24 mots. Rien n'est écrit tant que `commitStudioVaultSetup`
 * n'est pas appelée après la confirmation des 3 mots.
 */
export async function beginStudioVaultSetup(): Promise<PhraseDraftView> {
  const user = requireUser();
  wipeDraft(setupDraft);
  const { draft, view } = await newDraft(user.uid);
  setupDraft = draft;
  return view;
}

export function cancelStudioVaultSetup(): void {
  wipeDraft(setupDraft);
  setupDraft = null;
}

/** Vérifie les 3 mots saisis (comparaison stricte après normalisation). */
export function verifyConfirmationWords(
  view: PhraseDraftView,
  answers: Record<number, string>
): boolean {
  return view.confirmPositions.every(
    (pos) => (answers[pos] || '').trim().toLowerCase() === view.words[pos]
  );
}

export async function commitStudioVaultSetup(options: {
  password?: string;
  rememberDevice?: boolean;
}): Promise<void> {
  const user = requireUser();
  const draft = setupDraft;
  if (!draft || draft.uid !== user.uid) throw new StudioVaultError('unknown');
  const passwordAccount = isPasswordAccount(user);
  if (passwordAccount) {
    if (!options.password) throw new StudioVaultError('password-required');
    await verifyAccountPassword(user, options.password);
  }

  const cryptoDoc = await createCryptoDocument({
    uid: user.uid,
    dek: draft.dek,
    phraseEntropy: draft.entropy,
    password: passwordAccount ? options.password : null,
  });

  try {
    // La création échoue si le coffre existe déjà (identifiant déterministe) : jamais d'écrasement.
    const created = await createUserSetting(
      user.uid,
      CRYPTO_SETTING_KEY,
      cleanStoredObject(cryptoDoc as any)
    );
    if (!created) throw new StudioVaultError('already-exists');
  } catch (err) {
    throw mapAuthError(err);
  }

  wipeDraft(draft);
  setupDraft = null;
  publishUnlocked(
    user.uid,
    { active: draft.dek, ring: new Map([[draft.dek.keyId, draft.dek.key]]) },
    cryptoDoc
  );
  await setStudioVaultRememberDevice(Boolean(options.rememberDevice));
  void runPostUnlockMaintenance();
}

// ---------------------------------------------------------------------------
// Déverrouillage
// ---------------------------------------------------------------------------

async function ensureDoc(uid: string): Promise<StudioCryptoDocument> {
  if (currentDoc) return currentDoc;
  const fetched = await readCryptoDoc(uid);
  if (!fetched) throw new StudioVaultError('no-vault');
  currentDoc = fetched;
  return fetched;
}

export async function unlockStudioVaultWithPassword(
  password: string,
  options: { rememberDevice?: boolean } = {}
): Promise<void> {
  const user = requireUser();
  const cryptoDoc = await ensureDoc(user.uid);
  let unlocked: UnlockedKeys;
  try {
    unlocked = await unlockCryptoDocument(cryptoDoc, user.uid, { password });
  } catch {
    throw new StudioVaultError('wrong-password');
  }
  publishUnlocked(user.uid, unlocked, cryptoDoc);
  await setStudioVaultRememberDevice(Boolean(options.rememberDevice));
  void runPostUnlockMaintenance();
}

/**
 * Déverrouille avec la phrase. Si `newPassword` est fourni (mot de passe réinitialisé par e-mail),
 * il est vérifié auprès de PocketBase puis `wrappedDekPassword` est reconstruite.
 */
export async function unlockStudioVaultWithPhrase(
  phraseInput: string,
  options: { rememberDevice?: boolean; newPassword?: string } = {}
): Promise<void> {
  const user = requireUser();
  const check = await checkRecoveryPhraseInput(phraseInput);
  if (!check.ok) throw new StudioVaultError('invalid-phrase');
  const cryptoDoc = await ensureDoc(user.uid);
  const entropy = await mnemonicToEntropy(check.words);
  let unlocked: UnlockedKeys;
  try {
    unlocked = await unlockCryptoDocument(cryptoDoc, user.uid, { phraseEntropy: entropy });
  } catch {
    throw new StudioVaultError('wrong-phrase');
  } finally {
    entropy.fill(0);
  }

  let finalDoc = cryptoDoc;
  if (options.newPassword && isPasswordAccount(user)) {
    await verifyAccountPassword(user, options.newPassword);
    finalDoc = await rewrapPasswordEnvelope(cryptoDoc, user.uid, unlocked, options.newPassword);
    await writeCryptoDoc(user.uid, finalDoc);
  }
  publishUnlocked(user.uid, unlocked, finalDoc);
  await setStudioVaultRememberDevice(Boolean(options.rememberDevice));
  void runPostUnlockMaintenance();
}

export type SilentUnlockResult =
  'unlocked' | 'already-unlocked' | 'no-vault' | 'password-mismatch' | 'failed';

/**
 * Appelée juste après une connexion e-mail réussie : le mot de passe vient d'être validé par PocketBase.
 * Un échec signifie que l'enveloppe date d'un ancien mot de passe (réinitialisation par e-mail) ;
 * l'utilisateur devra alors déverrouiller avec sa phrase et reconstruire l'accès par mot de passe.
 */
export async function tryUnlockAfterPasswordSignIn(
  user: AuthUser,
  password: string
): Promise<SilentUnlockResult> {
  try {
    if (getRecordKeys(user.uid)) return 'already-unlocked';
    const cryptoDoc =
      currentDoc && getStudioVaultState().uid === user.uid
        ? currentDoc
        : await readCryptoDoc(user.uid);
    if (!cryptoDoc) return 'no-vault';
    if (!cryptoDoc.wrappedDekPassword) return 'password-mismatch';
    try {
      const unlocked = await unlockCryptoDocument(cryptoDoc, user.uid, { password });
      initToken++; // l'initialisation en cours ne doit pas reverrouiller la session
      setStudioVaultState({ uid: user.uid, isPasswordAccount: true });
      publishUnlocked(user.uid, unlocked, cryptoDoc);
      void runPostUnlockMaintenance();
      return 'unlocked';
    } catch {
      currentDoc = cryptoDoc;
      return 'password-mismatch';
    }
  } catch {
    return 'failed';
  }
}

// ---------------------------------------------------------------------------
// Mot de passe
// ---------------------------------------------------------------------------

/**
 * À appeler après `updatePassword` : rechiffre seulement `wrappedDekPassword`. Aucun dossier n'est
 * touché. Si le coffre est verrouillé, l'ancien mot de passe sert à l'ouvrir le temps de l'opération.
 */
export async function rewrapStudioVaultAfterPasswordChange(
  currentPassword: string,
  newPassword: string
): Promise<'updated' | 'no-vault' | 'skipped'> {
  const user = requireUser();
  const cryptoDoc =
    currentDoc && getStudioVaultState().uid === user.uid
      ? currentDoc
      : await readCryptoDoc(user.uid);
  if (!cryptoDoc) return 'no-vault';
  let unlocked: UnlockedKeys | null = null;
  const session = getRecordKeys(user.uid);
  if (session && session.active.key.extractable) {
    unlocked = { active: session.active, ring: new Map(session.ring) };
  } else {
    try {
      unlocked = await unlockCryptoDocument(cryptoDoc, user.uid, { password: currentPassword });
    } catch {
      return 'skipped';
    }
  }
  const updated = await rewrapPasswordEnvelope(cryptoDoc, user.uid, unlocked, newPassword);
  await writeCryptoDoc(user.uid, updated);
  setStudioVaultState({ hasPasswordEnvelope: true });
  if (!session) unlocked.ring.clear();
  return 'updated';
}

// ---------------------------------------------------------------------------
// Mémorisation sur l'appareil (optionnelle)
// ---------------------------------------------------------------------------

export async function setStudioVaultRememberDevice(enabled: boolean): Promise<void> {
  const uid = getStudioVaultState().uid;
  if (!uid) return;
  const keys = getRecordKeys(uid);
  if (enabled && keys) {
    await deviceStoreSet(rememberKey(uid), await wrapDekForDevice(keys.active, uid));
    setStudioVaultState({ rememberDevice: true });
  } else {
    await deviceStoreDelete(rememberKey(uid));
    setStudioVaultState({ rememberDevice: false });
  }
}

/** Verrouillage manuel : oublie la DEK en mémoire et sur l'appareil (conserve l'enrôlement biométrique WebAuthn s'il est configuré). */
export async function lockStudioVault(): Promise<void> {
  const uid = getStudioVaultState().uid;
  if (uid) await deviceStoreDelete(rememberKey(uid));
  setStudioVaultState({ rememberDevice: false });
  lockStudioSession(getStudioVaultState().status === 'signed-out' ? 'signed-out' : 'locked');
}

// ---------------------------------------------------------------------------
// Déverrouillage biométrique local (WebAuthn / TouchID / FaceID / Windows Hello)
// ---------------------------------------------------------------------------

export { isBiometricUnlockSupported, hasBiometricVaultEnrollment };

/** Active ou désactive le déverrouillage biométrique (TouchID / FaceID / Windows Hello) sur cet appareil. */
export async function setStudioVaultBiometricUnlock(enabled: boolean): Promise<boolean> {
  const user = requireUser();
  if (!enabled) {
    await removeBiometricVaultUnlock(user.uid);
    return false;
  }
  const keys = getRecordKeys(user.uid);
  if (!keys) throw new StudioVaultLockedError();
  return enrollBiometricVaultUnlock(user.uid, user.email || user.uid, keys.active);
}

/** Déverrouille le coffre E2EE par empreinte digitale / FaceID / Windows Hello sur cet appareil. */
export async function unlockStudioVaultWithBiometrics(): Promise<void> {
  const user = requireUser();
  const cryptoDoc = await ensureDoc(user.uid);
  let unlocked: UnlockedKeys;
  try {
    const dek = await unlockDekWithBiometrics(user.uid, Boolean(cryptoDoc.rotation));
    unlocked = await expandRememberedKey(cryptoDoc, user.uid, dek);
  } catch {
    throw new StudioVaultError('wrong-password');
  }
  publishUnlocked(user.uid, unlocked, cryptoDoc);
  void runPostUnlockMaintenance();
}

/** Déconnexion : verrouille la session (les caches et IndexedDB sont purgés par purgeSensitiveStudioStorage). */
export function lockStudioVaultOnSignOut(): void {
  initToken++;
  currentDoc = null;
  wipeDraft(setupDraft);
  wipeDraft(rotationDraft);
  setupDraft = null;
  rotationDraft = null;
  lockStudioSession('signed-out');
  setStudioVaultState({
    uid: null,
    rememberDevice: false,
    rotationPending: false,
    hasPasswordEnvelope: false,
  });
}

// ---------------------------------------------------------------------------
// Rechiffrement (migration de l'ancien schéma et réinitialisation de la phrase)
// ---------------------------------------------------------------------------

export interface ReencryptResult {
  rewritten: number;
  skipped: number;
  total: number;
}

let maintenancePromise: Promise<void> | null = null;

type RecordKind = 'dossier' | 'note' | 'reformulation' | 'analysis' | 'landmark';

const RECORD_COLLECTIONS = {
  dossier: 'dossiers',
  note: 'field_notes',
  reformulation: 'reformulations',
  analysis: 'analyses',
  landmark: 'landmarks',
} as const;

async function reencryptRecord(
  raw: unknown,
  kind: RecordKind,
  keys: RecordKeys
): Promise<'skip' | 'keep' | any> {
  if (kind === 'note') {
    const { value, stats } = await decryptFieldNoteFromStorage(raw as StoredFieldNote, keys);
    if (!value || stats.failed > 0) return 'skip';
    return needsReencryption(stats)
      ? cleanStoredObject((await encryptFieldNoteForStorage(value, keys)) as any)
      : 'keep';
  }
  if (kind === 'dossier') {
    const { value, stats } = await decryptDossierFromStorage(raw as Dossier, keys);
    if (stats.failed > 0) return 'skip';
    return needsReencryption(stats)
      ? cleanStoredObject(await encryptDossierForStorage(value, keys))
      : 'keep';
  }
  if (kind === 'analysis') {
    const { value, stats } = await decryptAnalysisFromStorage(raw as AnalysisRecord, keys);
    if (!value || stats.failed > 0) return 'skip';
    return needsReencryption(stats)
      ? cleanStoredObject((await encryptAnalysisForStorage(value, keys)) as any)
      : 'keep';
  }
  if (kind === 'landmark') {
    const { value, stats } = await decryptLandmarkFromStorage(raw as Record<string, any>, keys);
    if (!value || stats.failed > 0) return 'skip';
    return needsReencryption(stats)
      ? cleanStoredObject((await encryptLandmarkForStorage(value, keys)) as any)
      : 'keep';
  }
  const { value, stats } = await decryptReformulationFromStorage(raw as ReformulationRecord, keys);
  if (stats.failed > 0) return 'skip';
  return needsReencryption(stats)
    ? cleanStoredObject((await encryptReformulationForStorage(value, keys)) as any)
    : 'keep';
}

/**
 * Parcourt tous les dossiers, notes de terrain, reformulations, analyses et repères du compte, et réécrit ceux qui contiennent encore des
 * champs de l'ancien schéma, en clair, ou chiffrés avec la clé remplacée. Les enregistrements dont un
 * champ est illisible ne sont jamais réécrits (ils sont comptés dans `skipped`).
 *
 * Chaque document candidat est relu juste avant d'être réécrit, et la réécriture part de cette
 * version fraîche : une modification faite entre-temps par l'utilisateur n'est pas écrasée par une
 * copie périmée.
 */
export async function reencryptStudioRecords(
  keys: RecordKeys,
  kind: 'migration' | 'rotation'
): Promise<ReencryptResult> {
  const uid = keys.uid;
  const [dossierDocs, noteDocs, reformulationDocs, analysisDocs, landmarkDocs] = await Promise.all([
    listDocuments('dossiers', { ownerId: uid }),
    listDocuments('field_notes', { ownerId: uid }),
    listDocuments('reformulations', { ownerId: uid }),
    listDocuments('analyses', { ownerId: uid }),
    listDocuments('landmarks', { ownerId: uid }),
  ]);
  const all: Array<{ id: string; data: unknown; kind: RecordKind }> = [
    ...dossierDocs.map((d) => ({ id: d.id, data: d.data, kind: 'dossier' as const })),
    ...noteDocs.map((d) => ({ id: d.id, data: d.data, kind: 'note' as const })),
    ...reformulationDocs.map((d) => ({ id: d.id, data: d.data, kind: 'reformulation' as const })),
    ...analysisDocs.map((d) => ({ id: d.id, data: d.data, kind: 'analysis' as const })),
    ...landmarkDocs.map((d) => ({ id: d.id, data: d.data, kind: 'landmark' as const })),
  ];
  const progress = { kind, done: 0, total: all.length, skipped: 0, running: true };
  setStudioVaultState({ progress: { ...progress } });

  // Premier passage, hors transaction : repérer les enregistrements à réécrire.
  const candidates: typeof all = [];
  for (const item of all) {
    const outcome = await reencryptRecord(item.data, item.kind, keys);
    if (outcome === 'skip') progress.skipped++;
    else if (outcome !== 'keep') candidates.push(item);
    else progress.done++;
  }
  setStudioVaultState({ progress: { ...progress } });

  let rewritten = 0;
  for (let i = 0; i < candidates.length; i += REENCRYPT_TX_SIZE) {
    const chunk = candidates.slice(i, i + REENCRYPT_TX_SIZE);
    let written = 0;
    for (const item of chunk) {
      const collectionName = RECORD_COLLECTIONS[item.kind];
      const fresh = await getDocument(collectionName, item.id);
      if (!fresh) continue;
      const outcome = await reencryptRecord(fresh, item.kind, keys);
      if (outcome === 'skip' || outcome === 'keep') continue;
      await setDocument(collectionName, item.id, uid, outcome);
      written++;
    }
    rewritten += written;
    progress.done += chunk.length;
    setStudioVaultState({ progress: { ...progress } });
  }
  setStudioVaultState({ progress: { ...progress, running: false } });
  return { rewritten, skipped: progress.skipped, total: all.length };
}

/** Après chaque déverrouillage : reprend une rotation interrompue, puis migre l'ancien schéma. */
export function runPostUnlockMaintenance(): Promise<void> {
  if (maintenancePromise) return maintenancePromise;
  maintenancePromise = (async () => {
    try {
      const keys = getRecordKeys();
      if (!keys || !currentDoc) return;
      if (currentDoc.rotation) {
        await completeKeyRotation(keys);
        return;
      }
      if (
        !currentDoc.legacyMigratedAt ||
        !currentDoc.stylePromptMigratedAt ||
        !currentDoc.recordBindingMigratedAt
      ) {
        const result = await reencryptStudioRecords(keys, 'migration');
        if (result.skipped === 0 && getRecordKeys(keys.uid)) {
          const nowIso = new Date().toISOString();
          await writeCryptoDoc(keys.uid, {
            ...currentDoc,
            legacyMigratedAt: currentDoc.legacyMigratedAt || nowIso,
            stylePromptMigratedAt: nowIso,
            recordBindingMigratedAt: nowIso,
          });
        }
      }
    } catch (err) {
      console.warn(
        '[studioVault] Rechiffrement interrompu, reprise au prochain déverrouillage.',
        (err as any)?.code || ''
      );
    } finally {
      maintenancePromise = null;
    }
  })();
  return maintenancePromise;
}

async function completeKeyRotation(keys: RecordKeys): Promise<ReencryptResult> {
  const result = await reencryptStudioRecords(keys, 'rotation');
  if (!currentDoc?.rotation || !getRecordKeys(keys.uid)) return result;
  // A skipped record may still hold readable fields under the old key: finalizing would drop that
  // key and lose them. Keep both keys (rotation pending) until every record has been rewritten.
  if (result.skipped > 0) return result;
  const finalized = finalizeKeyRotation({
    ...currentDoc,
    legacyMigratedAt: currentDoc.legacyMigratedAt || new Date().toISOString(),
    stylePromptMigratedAt: currentDoc.stylePromptMigratedAt || new Date().toISOString(),
    recordBindingMigratedAt: currentDoc.recordBindingMigratedAt || new Date().toISOString(),
  });
  await writeCryptoDoc(keys.uid, finalized);
  const active = keys.active;
  setSessionKeys(
    keys.uid,
    active,
    new Map([[active.keyId, active.key]]),
    Boolean(finalized.legacyMigratedAt)
  );
  setStudioVaultState({
    rotationPending: false,
    hasPasswordEnvelope: Boolean(finalized.wrappedDekPassword),
  });
  if (getStudioVaultState().rememberDevice) await setStudioVaultRememberDevice(true);
  return result;
}

/** Réinitialisation volontaire de la phrase : étape 1, génère la nouvelle phrase (rien n'est écrit). */
export async function beginRecoveryPhraseRotation(): Promise<PhraseDraftView> {
  const user = requireUser();
  if (!getRecordKeys(user.uid)) throw new StudioVaultLockedError();
  if (currentDoc?.rotation) throw new StudioVaultError('unknown');
  wipeDraft(rotationDraft);
  const { draft, view } = await newDraft(user.uid);
  rotationDraft = draft;
  return view;
}

export function cancelRecoveryPhraseRotation(): void {
  wipeDraft(rotationDraft);
  rotationDraft = null;
}

/**
 * Étape 2, après confirmation des 3 mots :
 * 1. écrit les nouvelles enveloppes à côté des actuelles, avec les deux clés croisées
 *    (l'ancien comme le nouveau secret ouvrent le coffre pendant l'opération) ;
 * 2. rechiffre tous les enregistrements par lots, avec progression visible ;
 * 3. remplace les enveloppes. Une interruption est reprise au prochain déverrouillage.
 */
export async function commitRecoveryPhraseRotation(
  options: { password?: string } = {}
): Promise<ReencryptResult> {
  const user = requireUser();
  const draft = rotationDraft;
  const keys = getRecordKeys(user.uid);
  if (!keys) throw new StudioVaultLockedError();
  if (!draft || draft.uid !== user.uid || !currentDoc) throw new StudioVaultError('unknown');
  const passwordAccount = isPasswordAccount(user);
  if (passwordAccount) {
    if (!options.password) throw new StudioVaultError('password-required');
    await verifyAccountPassword(user, options.password);
  }

  let currentKey = keys.active;
  if (!currentKey.key.extractable && options.password) {
    const freshUnlocked = await unlockCryptoDocument(currentDoc, user.uid, {
      password: options.password,
    });
    currentKey = freshUnlocked.active;
  }

  const prepared = await prepareKeyRotation({
    doc: currentDoc,
    uid: user.uid,
    current: currentKey,
    next: draft.dek,
    nextPhraseEntropy: draft.entropy,
    password: passwordAccount ? options.password : null,
  });
  await writeCryptoDoc(user.uid, prepared);
  wipeDraft(draft);
  rotationDraft = null;

  const ring = new Map(keys.ring);
  ring.set(draft.dek.keyId, draft.dek.key);
  setSessionKeys(user.uid, draft.dek, ring, Boolean(currentDoc?.legacyMigratedAt));
  setStudioVaultState({ rotationPending: true });

  const result = await completeKeyRotation(getRecordKeys(user.uid)!);
  return result;
}

// ---------------------------------------------------------------------------
// Perte de la phrase ET du mot de passe : seule issue, repartir de zéro
// ---------------------------------------------------------------------------

/**
 * Supprime définitivement les dossiers, notes de terrain, reformulations et enveloppes du compte, puis repasse en
 * création de coffre. Irréversible : l'interface exige une confirmation explicite.
 */
export async function destroyStudioVaultAndData(): Promise<void> {
  const user = requireUser();
  const uid = user.uid;
  for (const name of [
    'dossiers',
    'field_notes',
    'reformulations',
    'analyses',
    'landmarks',
  ] as const) {
    const docs = await listDocuments(name, { ownerId: uid });
    for (const d of docs) {
      await deleteDocument(name, d.id);
    }
  }
  await deleteUserSetting(uid, CRYPTO_SETTING_KEY);
  currentDoc = null;
  await purgeSensitiveStudioStorage();
  lockStudioSession('needs-setup');
  setStudioVaultState({
    uid,
    rememberDevice: false,
    rotationPending: false,
    hasPasswordEnvelope: false,
  });
}

/** Phrase saisie : contrôle de forme et de somme de contrôle, pour un retour immédiat dans l'interface. */
export { checkRecoveryPhraseInput };
