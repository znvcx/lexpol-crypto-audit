/**
 * Chiffrement de bout en bout du Mode Studio (schéma v2).
 *
 * - Chaque utilisateur possède une clé maîtresse aléatoire (DEK, AES-GCM 256 bits) générée
 *   sur son appareil. Elle n'est jamais envoyée en clair au serveur.
 * - La DEK est stockée dans PocketBase uniquement sous forme d'enveloppes chiffrées :
 *     · `wrappedDekPassword` : clé dérivée du mot de passe (PBKDF2-SHA256, ≥ 600 000 itérations) ;
 *     · `wrappedDekPhrase`   : clé dérivée de la phrase de récupération BIP-39 (HKDF-SHA256).
 * - Chaque champ sensible est chiffré en AES-GCM avec un IV aléatoire de 12 octets et des données
 *   associées liant le texte chiffré au compte (`uid`), à la version du schéma et à la clé.
 *
 * Toutes les opérations passent par WebCrypto (`crypto.subtle`). Ce module est pur : il ne
 * touche ni la base de données, ni le stockage du navigateur, et ne journalise jamais de secret.
 */
import {
  AnalysisRecord,
  Dossier,
  FieldNote,
  InvolvedEntity,
  ReformulationRecord,
  SavedLocation,
} from '../types';
import { BIP39_ENGLISH_WORDLIST } from './bip39English';
import { decryptLegacyString, isLegacyCiphertext } from './studioCryptoLegacy';

export const E2EE_SCHEME_VERSION = 2;
export const RECORD_PREFIX = 'ENCv2:';
export const PBKDF2_MIN_ITERATIONS = 600_000;
export const RECOVERY_PHRASE_WORD_COUNT = 24;
export const UNREADABLE_PLACEHOLDER = '[Données chiffrées illisibles]';

const AAD_NAMESPACE = 'lexpol.ch/studio-e2ee';
const PHRASE_HKDF_INFO = 'lexpol-studio-phrase-kek-v2';
const DEK_USAGES: KeyUsage[] = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];

export type VaultCryptoErrorCode = 'invalid-phrase' | 'wrong-secret' | 'corrupted' | 'kdf-params';

/** Erreur cryptographique. Le message ne contient jamais de secret. */
export class VaultCryptoError extends Error {
  readonly code: VaultCryptoErrorCode;
  constructor(code: VaultCryptoErrorCode, message?: string) {
    super(message || code);
    this.name = 'VaultCryptoError';
    this.code = code;
  }
}

export interface StudioDek {
  key: CryptoKey;
  /** Identifiant public aléatoire de la génération de clé (permet de reconnaître la clé d'un texte chiffré). */
  keyId: string;
}

export interface WrappedKeyBlob {
  iv: string;
  ct: string;
}

export interface PasswordKdfParams {
  name: 'PBKDF2';
  hash: 'SHA-256';
  iterations: number;
  salt: string;
}

export interface PhraseKdfParams {
  name: 'HKDF';
  hash: 'SHA-256';
  salt: string;
  info: string;
}

export interface StudioKeyEnvelopes {
  keyId: string;
  kdf: { password?: PasswordKdfParams; phrase: PhraseKdfParams };
  wrappedDekPassword?: WrappedKeyBlob;
  wrappedDekPhrase: WrappedKeyBlob;
}

/** Rechiffrement en cours après une réinitialisation de la phrase de récupération. */
export interface StudioKeyRotation {
  startedAt: string;
  next: StudioKeyEnvelopes;
  /** Nouvelle DEK chiffrée par l'actuelle, et inversement : l'un ou l'autre secret suffit à reprendre. */
  wrappedNextDekByCurrent: WrappedKeyBlob;
  wrappedCurrentDekByNext: WrappedKeyBlob;
}

/** Contenu de `users/{uid}/settings/crypto` : uniquement des données chiffrées ou publiques. */
export interface StudioCryptoDocument extends StudioKeyEnvelopes {
  version: typeof E2EE_SCHEME_VERSION;
  createdAt: string;
  updatedAt: string;
  legacyMigratedAt?: string;
  rotation?: StudioKeyRotation;
}

// ---------------------------------------------------------------------------
// Encodages
// ---------------------------------------------------------------------------

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    throw new VaultCryptoError('corrupted', 'Invalid base64 payload');
  }
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

function aad(uid: string, purpose: string): Uint8Array {
  if (!uid) throw new VaultCryptoError('corrupted', 'Missing account identifier');
  return utf8Encoder.encode(`${AAD_NAMESPACE}|v${E2EE_SCHEME_VERSION}|${uid}|${purpose}`);
}

// ---------------------------------------------------------------------------
// Clé maîtresse (DEK)
// ---------------------------------------------------------------------------

/** Génère une DEK aléatoire de 256 bits (`crypto.getRandomValues`). */
export async function generateDek(): Promise<StudioDek> {
  const raw = randomBytes(32);
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      raw as BufferSource,
      { name: 'AES-GCM' },
      true,
      DEK_USAGES
    );
    return { key, keyId: bytesToHex(randomBytes(8)) };
  } finally {
    raw.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Phrase de récupération BIP-39 (24 mots, 256 bits d'entropie + 8 bits de somme de contrôle)
// ---------------------------------------------------------------------------

const WORD_INDEX = new Map<string, number>(BIP39_ENGLISH_WORDLIST.map((w, i) => [w, i]));

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

export async function entropyToMnemonic(entropy: Uint8Array): Promise<string[]> {
  if (entropy.length !== 32)
    throw new VaultCryptoError('invalid-phrase', 'Entropy must be 256 bits');
  const checksum = (await sha256(entropy))[0];
  const bits: number[] = [];
  for (const byte of entropy) for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
  for (let i = 7; i >= 0; i--) bits.push((checksum >> i) & 1);
  const words: string[] = [];
  for (let w = 0; w < RECOVERY_PHRASE_WORD_COUNT; w++) {
    let index = 0;
    for (let b = 0; b < 11; b++) index = (index << 1) | bits[w * 11 + b];
    words.push(BIP39_ENGLISH_WORDLIST[index]);
  }
  return words;
}

export async function mnemonicToEntropy(words: readonly string[]): Promise<Uint8Array> {
  if (words.length !== RECOVERY_PHRASE_WORD_COUNT) {
    throw new VaultCryptoError('invalid-phrase', 'A recovery phrase has 24 words');
  }
  const bits: number[] = [];
  for (const word of words) {
    const index = WORD_INDEX.get(word);
    if (index === undefined)
      throw new VaultCryptoError('invalid-phrase', 'Unknown word in recovery phrase');
    for (let b = 10; b >= 0; b--) bits.push((index >> b) & 1);
  }
  const entropy = new Uint8Array(32);
  for (let i = 0; i < 256; i++) entropy[i >> 3] |= bits[i] << (7 - (i & 7));
  let checksum = 0;
  for (let i = 256; i < 264; i++) checksum = (checksum << 1) | bits[i];
  if ((await sha256(entropy))[0] !== checksum) {
    entropy.fill(0);
    throw new VaultCryptoError('invalid-phrase', 'Recovery phrase checksum mismatch');
  }
  return entropy;
}

export interface GeneratedRecoveryPhrase {
  words: string[];
  entropy: Uint8Array;
}

export async function generateRecoveryPhrase(): Promise<GeneratedRecoveryPhrase> {
  const entropy = randomBytes(32);
  return { words: await entropyToMnemonic(entropy), entropy };
}

/** Résout un mot saisi : mot exact, ou préfixe d'au moins 4 lettres (unique dans la liste BIP-39). */
function resolveWord(token: string): string | null {
  if (WORD_INDEX.has(token)) return token;
  if (token.length < 4) return null;
  const prefix = token.slice(0, 4);
  const match = BIP39_ENGLISH_WORDLIST.find((w) => w.startsWith(prefix));
  return match && (match === token || match.startsWith(token)) ? match : null;
}

export interface PhraseInputCheck {
  ok: boolean;
  words: string[];
  reason?: 'length' | 'unknown-word' | 'checksum';
  /** Positions (1 à 24) des mots non reconnus. */
  unknownPositions?: number[];
}

/** Normalise une saisie libre (espaces, retours à la ligne, numérotation « 1. », majuscules). */
export function tokenizeRecoveryPhrase(input: string): string[] {
  return (input || '')
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z\s]/g, ' ')
    .split(/\s+/)
    .filter(Boolean);
}

export async function checkRecoveryPhraseInput(input: string): Promise<PhraseInputCheck> {
  const tokens = tokenizeRecoveryPhrase(input);
  const resolved = tokens.map(resolveWord);
  const unknownPositions = resolved.flatMap((w, i) => (w ? [] : [i + 1]));
  const words = resolved.map((w, i) => w || tokens[i]);
  if (unknownPositions.length > 0)
    return { ok: false, words, reason: 'unknown-word', unknownPositions };
  if (words.length !== RECOVERY_PHRASE_WORD_COUNT) return { ok: false, words, reason: 'length' };
  try {
    const entropy = await mnemonicToEntropy(words);
    entropy.fill(0);
    return { ok: true, words };
  } catch {
    return { ok: false, words, reason: 'checksum' };
  }
}

/** Tire `count` positions distinctes (0-indexées) pour la confirmation de la phrase. */
export function pickConfirmationPositions(count = 3, total = RECOVERY_PHRASE_WORD_COUNT): number[] {
  const picked = new Set<number>();
  const buf = new Uint32Array(1);
  while (picked.size < Math.min(count, total)) {
    crypto.getRandomValues(buf);
    picked.add(buf[0] % total);
  }
  return Array.from(picked).sort((a, b) => a - b);
}

// ---------------------------------------------------------------------------
// Clés d'enveloppe (KEK)
// ---------------------------------------------------------------------------

export async function derivePasswordKek(
  password: string,
  params: PasswordKdfParams
): Promise<CryptoKey> {
  if (
    params.name !== 'PBKDF2' ||
    params.hash !== 'SHA-256' ||
    !(params.iterations >= PBKDF2_MIN_ITERATIONS)
  ) {
    throw new VaultCryptoError('kdf-params', 'Password KDF parameters below the required minimum');
  }
  const base = await crypto.subtle.importKey(
    'raw',
    utf8Encoder.encode(password.normalize('NFC')) as BufferSource,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: base64ToBytes(params.salt) as BufferSource,
      iterations: params.iterations,
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export async function derivePhraseKek(
  entropy: Uint8Array,
  params: PhraseKdfParams
): Promise<CryptoKey> {
  if (params.name !== 'HKDF' || params.hash !== 'SHA-256') {
    throw new VaultCryptoError('kdf-params', 'Unsupported phrase KDF');
  }
  const base = await crypto.subtle.importKey('raw', entropy as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: base64ToBytes(params.salt) as BufferSource,
      info: utf8Encoder.encode(params.info) as BufferSource,
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export function newPasswordKdfParams(): PasswordKdfParams {
  return {
    name: 'PBKDF2',
    hash: 'SHA-256',
    iterations: PBKDF2_MIN_ITERATIONS,
    salt: bytesToBase64(randomBytes(16)),
  };
}

export function newPhraseKdfParams(): PhraseKdfParams {
  return {
    name: 'HKDF',
    hash: 'SHA-256',
    salt: bytesToBase64(randomBytes(16)),
    info: PHRASE_HKDF_INFO,
  };
}

export async function wrapDek(
  dek: StudioDek,
  kek: CryptoKey,
  uid: string,
  purpose: string
): Promise<WrappedKeyBlob> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.wrapKey('raw', dek.key, kek, {
    name: 'AES-GCM',
    iv: iv as BufferSource,
    additionalData: aad(uid, `${purpose}|${dek.keyId}`) as BufferSource,
  });
  return { iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)) };
}

export async function unwrapDek(
  blob: WrappedKeyBlob,
  kek: CryptoKey,
  uid: string,
  purpose: string,
  keyId: string,
  extractable = true
): Promise<StudioDek> {
  let key: CryptoKey;
  try {
    key = await crypto.subtle.unwrapKey(
      'raw',
      base64ToBytes(blob.ct) as BufferSource,
      kek,
      {
        name: 'AES-GCM',
        iv: base64ToBytes(blob.iv) as BufferSource,
        additionalData: aad(uid, `${purpose}|${keyId}`) as BufferSource,
      },
      { name: 'AES-GCM' },
      extractable,
      extractable ? DEK_USAGES : ['encrypt', 'decrypt']
    );
  } catch {
    throw new VaultCryptoError('wrong-secret', 'Unable to open the key envelope');
  }
  return { key, keyId };
}

// ---------------------------------------------------------------------------
// Enveloppes et document du coffre (réglage `crypto`)
// ---------------------------------------------------------------------------

export async function createKeyEnvelopes(options: {
  uid: string;
  dek: StudioDek;
  phraseEntropy: Uint8Array;
  password?: string | null;
}): Promise<StudioKeyEnvelopes> {
  const { uid, dek, phraseEntropy, password } = options;
  const phraseParams = newPhraseKdfParams();
  const envelopes: StudioKeyEnvelopes = {
    keyId: dek.keyId,
    kdf: { phrase: phraseParams },
    wrappedDekPhrase: await wrapDek(
      dek,
      await derivePhraseKek(phraseEntropy, phraseParams),
      uid,
      'dek-phrase'
    ),
  };
  if (password) {
    const passwordParams = newPasswordKdfParams();
    envelopes.kdf.password = passwordParams;
    envelopes.wrappedDekPassword = await wrapDek(
      dek,
      await derivePasswordKek(password, passwordParams),
      uid,
      'dek-password'
    );
  }
  return envelopes;
}

export async function createCryptoDocument(options: {
  uid: string;
  dek: StudioDek;
  phraseEntropy: Uint8Array;
  password?: string | null;
  now?: string;
}): Promise<StudioCryptoDocument> {
  const now = options.now || new Date().toISOString();
  return {
    version: E2EE_SCHEME_VERSION,
    createdAt: now,
    updatedAt: now,
    ...(await createKeyEnvelopes(options)),
  };
}

export type UnlockSecret = { password: string } | { phraseEntropy: Uint8Array };

async function openEnvelopes(
  envelopes: StudioKeyEnvelopes,
  uid: string,
  secret: UnlockSecret
): Promise<StudioDek> {
  if ('password' in secret) {
    if (!envelopes.wrappedDekPassword || !envelopes.kdf.password) {
      throw new VaultCryptoError('wrong-secret', 'No password envelope for this account');
    }
    const kek = await derivePasswordKek(secret.password, envelopes.kdf.password);
    return unwrapDek(envelopes.wrappedDekPassword, kek, uid, 'dek-password', envelopes.keyId);
  }
  const kek = await derivePhraseKek(secret.phraseEntropy, envelopes.kdf.phrase);
  return unwrapDek(envelopes.wrappedDekPhrase, kek, uid, 'dek-phrase', envelopes.keyId);
}

export interface UnlockedKeys {
  /** Clé à utiliser pour tout nouvel enregistrement. */
  active: StudioDek;
  /** Clés acceptées en lecture (clé active + clé en cours de remplacement pendant un rechiffrement). */
  ring: Map<string, CryptoKey>;
}

/**
 * Ouvre la DEK avec le mot de passe ou la phrase. Si un rechiffrement est en cours, l'ancien
 * comme le nouveau secret fonctionnent, et les deux clés sont renvoyées dans le trousseau.
 */
export async function unlockCryptoDocument(
  doc: StudioCryptoDocument,
  uid: string,
  secret: UnlockSecret
): Promise<UnlockedKeys> {
  assertCryptoDocument(doc);
  let current: StudioDek | null = null;
  let next: StudioDek | null = null;
  try {
    current = await openEnvelopes(doc, uid, secret);
  } catch (err) {
    if (!doc.rotation) throw err;
    next = await openEnvelopes(doc.rotation.next, uid, secret);
  }
  if (doc.rotation) {
    if (current) {
      next = await unwrapDek(
        doc.rotation.wrappedNextDekByCurrent,
        current.key,
        uid,
        'dek-cross',
        doc.rotation.next.keyId
      );
    } else if (next) {
      current = await unwrapDek(
        doc.rotation.wrappedCurrentDekByNext,
        next.key,
        uid,
        'dek-cross',
        doc.keyId
      );
    }
  }
  const active = next || current!;
  const ring = new Map<string, CryptoKey>([[current!.keyId, current!.key]]);
  if (next) ring.set(next.keyId, next.key);
  return { active, ring };
}

/** Rechiffre uniquement l'enveloppe mot de passe (changement ou réinitialisation du mot de passe). */
export async function rewrapPasswordEnvelope(
  doc: StudioCryptoDocument,
  uid: string,
  keys: UnlockedKeys,
  newPassword: string,
  now = new Date().toISOString()
): Promise<StudioCryptoDocument> {
  assertCryptoDocument(doc);
  const rewrap = async (envelopes: StudioKeyEnvelopes): Promise<StudioKeyEnvelopes> => {
    const key = keys.ring.get(envelopes.keyId);
    if (!key) throw new VaultCryptoError('wrong-secret', 'Key not available for this envelope');
    const params = newPasswordKdfParams();
    const kek = await derivePasswordKek(newPassword, params);
    return {
      ...envelopes,
      kdf: { ...envelopes.kdf, password: params },
      wrappedDekPassword: await wrapDek({ key, keyId: envelopes.keyId }, kek, uid, 'dek-password'),
    };
  };
  const updated: StudioCryptoDocument = { ...doc, ...(await rewrap(doc)), updatedAt: now };
  if (doc.rotation) {
    updated.rotation = { ...doc.rotation, next: await rewrap(doc.rotation.next) };
  }
  return updated;
}

/** Prépare la réinitialisation de la phrase : nouvelle DEK, nouvelles enveloppes et clés croisées. */
export async function prepareKeyRotation(options: {
  doc: StudioCryptoDocument;
  uid: string;
  current: StudioDek;
  next: StudioDek;
  nextPhraseEntropy: Uint8Array;
  password?: string | null;
  now?: string;
}): Promise<StudioCryptoDocument> {
  const { doc, uid, current, next, nextPhraseEntropy, password } = options;
  assertCryptoDocument(doc);
  const now = options.now || new Date().toISOString();
  return {
    ...doc,
    updatedAt: now,
    rotation: {
      startedAt: now,
      next: await createKeyEnvelopes({
        uid,
        dek: next,
        phraseEntropy: nextPhraseEntropy,
        password,
      }),
      wrappedNextDekByCurrent: await wrapDek(next, current.key, uid, 'dek-cross'),
      wrappedCurrentDekByNext: await wrapDek(current, next.key, uid, 'dek-cross'),
    },
  };
}

/** Termine la rotation : seules les nouvelles enveloppes subsistent. */
export function finalizeKeyRotation(
  doc: StudioCryptoDocument,
  now = new Date().toISOString()
): StudioCryptoDocument {
  if (!doc.rotation) return doc;
  const { rotation, wrappedDekPassword: _p, ...rest } = doc;
  void _p;
  const next = rotation.next;
  const finalized: StudioCryptoDocument = {
    ...rest,
    keyId: next.keyId,
    kdf: next.kdf,
    wrappedDekPhrase: next.wrappedDekPhrase,
    updatedAt: now,
  };
  if (next.wrappedDekPassword) finalized.wrappedDekPassword = next.wrappedDekPassword;
  return finalized;
}

export function assertCryptoDocument(doc: unknown): asserts doc is StudioCryptoDocument {
  const d = doc as StudioCryptoDocument | null;
  if (
    !d ||
    d.version !== E2EE_SCHEME_VERSION ||
    typeof d.keyId !== 'string' ||
    !d.wrappedDekPhrase ||
    typeof d.wrappedDekPhrase.iv !== 'string' ||
    typeof d.wrappedDekPhrase.ct !== 'string' ||
    !d.kdf?.phrase
  ) {
    throw new VaultCryptoError('corrupted', 'Invalid Studio crypto document');
  }
}

// ---------------------------------------------------------------------------
// Mémorisation optionnelle sur l'appareil (clé non extractible conservée dans IndexedDB)
// ---------------------------------------------------------------------------

export interface DeviceWrappedDek {
  kek: CryptoKey;
  blob: WrappedKeyBlob;
  keyId: string;
}

export async function wrapDekForDevice(dek: StudioDek, uid: string): Promise<DeviceWrappedDek> {
  const kek = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'wrapKey',
    'unwrapKey',
  ])) as CryptoKey;
  return { kek, blob: await wrapDek(dek, kek, uid, 'dek-device'), keyId: dek.keyId };
}

export async function unwrapDekFromDevice(
  stored: DeviceWrappedDek,
  uid: string,
  extractable = false
): Promise<StudioDek> {
  return unwrapDek(stored.blob, stored.kek, uid, 'dek-device', stored.keyId, extractable);
}

// ---------------------------------------------------------------------------
// Chiffrement des enregistrements : ENCv2:<keyId>:<base64(IV || CT || tag)>
// ---------------------------------------------------------------------------

export async function encryptRecordString(
  value: string,
  dek: StudioDek,
  uid: string
): Promise<string> {
  if (!value) return value;
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        additionalData: aad(uid, `record|${dek.keyId}`) as BufferSource,
      },
      dek.key,
      utf8Encoder.encode(value) as BufferSource
    )
  );
  const payload = new Uint8Array(iv.length + ct.length);
  payload.set(iv, 0);
  payload.set(ct, iv.length);
  return `${RECORD_PREFIX}${dek.keyId}:${bytesToBase64(payload)}`;
}

export type RecordSource = 'v2' | 'legacy' | 'plain' | 'failed';

export interface DecryptedValue {
  text: string;
  source: RecordSource;
  keyId?: string;
}

export async function decryptRecordString(
  value: string,
  ring: Map<string, CryptoKey>,
  uid: string
): Promise<DecryptedValue> {
  if (typeof value !== 'string' || !value) return { text: value, source: 'v2' };
  if (value.startsWith(RECORD_PREFIX)) {
    const rest = value.slice(RECORD_PREFIX.length);
    const sep = rest.indexOf(':');
    const keyId = sep > 0 ? rest.slice(0, sep) : '';
    const key = ring.get(keyId);
    if (!key) return { text: UNREADABLE_PLACEHOLDER, source: 'failed', keyId };
    try {
      const payload = base64ToBytes(rest.slice(sep + 1));
      const plain = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: payload.subarray(0, 12) as BufferSource,
          additionalData: aad(uid, `record|${keyId}`) as BufferSource,
        },
        key,
        payload.subarray(12) as BufferSource
      );
      return { text: utf8Decoder.decode(plain), source: 'v2', keyId };
    } catch {
      return { text: UNREADABLE_PLACEHOLDER, source: 'failed', keyId };
    }
  }
  if (isLegacyCiphertext(value)) {
    // Lecture de compatibilité de l'ancien schéma (voir studioCryptoLegacy.ts, point de retrait).
    const plain = await decryptLegacyString(value, uid);
    return plain === null
      ? { text: UNREADABLE_PLACEHOLDER, source: 'failed' }
      : { text: plain, source: 'legacy' };
  }
  return { text: value, source: 'plain' };
}

// ---------------------------------------------------------------------------
// Champs sensibles des dossiers, entités et reformulations
// ---------------------------------------------------------------------------

type StringMapper = (value: string) => Promise<string>;

async function mapOptional(
  value: string | undefined,
  fn: StringMapper
): Promise<string | undefined> {
  return value ? fn(value) : value;
}

export async function mapEntitiesSensitiveFields(
  entities: InvolvedEntity[] | undefined,
  fn: StringMapper
): Promise<InvolvedEntity[] | undefined> {
  if (!Array.isArray(entities)) return undefined;
  return Promise.all(
    entities.map(async (e) =>
      e && typeof e === 'object' ? { ...e, realName: await fn(String(e.realName || '')) } : e
    )
  );
}

export async function mapDossierSensitiveFields(
  dossier: Dossier,
  fn: StringMapper
): Promise<Dossier> {
  if (!dossier || typeof dossier !== 'object') return dossier;
  const [title, description, facts, content, location, tasks, logs, reports, customFields, tags] =
    await Promise.all([
      fn(dossier.title),
      dossier.description ? fn(dossier.description) : Promise.resolve(''),
      mapOptional(dossier.facts, fn),
      mapOptional(dossier.content, fn),
      mapOptional(dossier.location, fn),
      Promise.all(
        (Array.isArray(dossier.tasks) ? dossier.tasks : []).map(async (t) => ({
          ...t,
          title: await fn(t.title),
        }))
      ),
      Promise.all(
        (Array.isArray(dossier.logs) ? dossier.logs : []).map(async (l) => ({
          ...l,
          content: await fn(l.content),
          ...(l.authorName ? { authorName: await fn(l.authorName) } : {}),
        }))
      ),
      Promise.all(
        (Array.isArray(dossier.reports) ? dossier.reports : []).map(async (r) => ({
          ...r,
          title: await fn(r.title),
          text: await fn(r.text),
          ...(r.summary ? { summary: await fn(r.summary) } : {}),
          ...(r.involvedEntities
            ? { involvedEntities: await mapEntitiesSensitiveFields(r.involvedEntities, fn) }
            : {}),
        }))
      ),
      Array.isArray(dossier.customFields)
        ? Promise.all(
            dossier.customFields.map(async (cf) => ({
              ...cf,
              label: cf.label ? await fn(cf.label) : cf.label,
              value: cf.value ? await fn(cf.value) : cf.value,
            }))
          )
        : Promise.resolve(undefined),
      Array.isArray(dossier.tags)
        ? Promise.all(dossier.tags.map(async (tag) => (tag ? await fn(String(tag)) : tag)))
        : Promise.resolve(undefined),
    ]);

  let analysisSnapshot = dossier.analysisSnapshot;
  if (analysisSnapshot) {
    if (typeof analysisSnapshot === 'object') {
      try {
        const encryptedStr = await fn(JSON.stringify(analysisSnapshot));
        analysisSnapshot = encryptedStr as any;
      } catch (err) {
        console.warn('[E2EE] Could not encrypt analysisSnapshot:', err);
      }
    } else if (typeof analysisSnapshot === 'string') {
      try {
        const decryptedStr = await fn(analysisSnapshot);
        if (decryptedStr) {
          analysisSnapshot = JSON.parse(decryptedStr);
        }
      } catch (err) {
        console.warn('[E2EE] Could not decrypt analysisSnapshot:', err);
      }
    }
  }

  return {
    ...dossier,
    title,
    description,
    ...(facts ? { facts } : {}),
    ...(content ? { content } : {}),
    ...(location ? { location } : {}),
    tasks,
    logs,
    reports,
    ...(customFields ? { customFields } : {}),
    ...(tags ? { tags } : {}),
    ...(analysisSnapshot !== undefined ? { analysisSnapshot } : {}),
  };
}

export async function mapReformulationSensitiveFields(
  record: ReformulationRecord,
  fn: StringMapper
): Promise<ReformulationRecord> {
  if (!record || typeof record !== 'object') return record;
  return {
    ...record,
    originalText: await fn(record.originalText),
    reformulatedText: await fn(record.reformulatedText),
    ...(record.title ? { title: await fn(record.title) } : {}),
    ...(record.summary ? { summary: await fn(record.summary) } : {}),
    ...(record.involvedEntities
      ? { involvedEntities: await mapEntitiesSensitiveFields(record.involvedEntities, fn) }
      : {}),
  };
}

export interface RecordKeys {
  uid: string;
  active: StudioDek;
  ring: Map<string, CryptoKey>;
}

export interface DecryptStats {
  v2: number;
  legacy: number;
  plain: number;
  failed: number;
  /** Champs chiffrés avec une autre clé que la clé active (rotation en cours). */
  staleKey: number;
}

function newStats(): DecryptStats {
  return { v2: 0, legacy: 0, plain: 0, failed: 0, staleKey: 0 };
}

/** Indique si l'enregistrement doit être réécrit avec la clé active (migration ou rotation). */
export function needsReencryption(stats: DecryptStats): boolean {
  return stats.failed === 0 && stats.legacy + stats.plain + stats.staleKey > 0;
}

function decryptingMapper(keys: RecordKeys, stats: DecryptStats): StringMapper {
  return async (value) => {
    const res = await decryptRecordString(value, keys.ring, keys.uid);
    if (value) stats[res.source]++;
    if (res.source === 'v2' && res.keyId && res.keyId !== keys.active.keyId) stats.staleKey++;
    return res.text;
  };
}

function encryptingMapper(keys: RecordKeys): StringMapper {
  return (value) => encryptRecordString(value, keys.active, keys.uid);
}

export async function encryptDossierForStorage(
  dossier: Dossier,
  keys: RecordKeys
): Promise<Dossier> {
  const bounded: Dossier = {
    ...dossier,
    reports: (dossier.reports || []).map((r) =>
      r.involvedEntities
        ? {
            ...r,
            involvedEntities: r.involvedEntities.map((e) => ({
              ...e,
              realName: String(e.realName || '').slice(0, 80),
            })),
          }
        : r
    ),
  };
  return mapDossierSensitiveFields(bounded, encryptingMapper(keys));
}

export async function decryptDossierFromStorage(
  dossier: Dossier,
  keys: RecordKeys
): Promise<{ value: Dossier; stats: DecryptStats }> {
  const stats = newStats();
  const value = await mapDossierSensitiveFields(dossier, decryptingMapper(keys, stats));
  return { value, stats };
}

export async function encryptReformulationForStorage(
  record: ReformulationRecord,
  keys: RecordKeys
): Promise<ReformulationRecord> {
  return mapReformulationSensitiveFields(record, encryptingMapper(keys));
}

export async function decryptReformulationFromStorage(
  record: ReformulationRecord,
  keys: RecordKeys
): Promise<{ value: ReformulationRecord; stats: DecryptStats }> {
  const stats = newStats();
  const value = await mapReformulationSensitiveFields(record, decryptingMapper(keys, stats));
  return { value, stats };
}

// ---------------------------------------------------------------------------
// Notes de terrain : tout le contenu est chiffré d'un bloc
// ---------------------------------------------------------------------------

/** Champs d'une note lisibles par la base (tri, rétention, lien vers le dossier). */
const FIELD_NOTE_PLAIN_KEYS = [
  'id',
  'reference',
  'dossierId',
  'createdAt',
  'updatedAt',
  'expiresAt',
] as const;

/** Forme stockée d'une note : métadonnées en clair, contenu dans `payload`. */
export interface StoredFieldNote {
  id: string;
  reference: string;
  dossierId?: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: number;
  payload: string;
}

export async function encryptFieldNoteForStorage(
  note: FieldNote,
  keys: RecordKeys
): Promise<StoredFieldNote> {
  const content: Record<string, unknown> = { ...note };
  const stored: Record<string, unknown> = {};
  for (const key of FIELD_NOTE_PLAIN_KEYS) {
    if (content[key] !== undefined) stored[key] = content[key];
    delete content[key];
  }
  stored.payload = await encryptingMapper(keys)(JSON.stringify(content));
  return stored as unknown as StoredFieldNote;
}

export async function decryptFieldNoteFromStorage(
  stored: StoredFieldNote,
  keys: RecordKeys
): Promise<{ value: FieldNote | null; stats: DecryptStats }> {
  const stats = newStats();
  const text = await decryptingMapper(keys, stats)(String(stored?.payload || ''));
  if (stats.failed > 0 || !text) return { value: null, stats };
  try {
    const content = JSON.parse(text) as Partial<FieldNote>;
    const value: FieldNote = {
      eventAt: '',
      location: '',
      identities: [],
      vehicles: [],
      text: '',
      ...content,
      id: stored.id,
      reference: stored.reference,
      createdAt: stored.createdAt,
      updatedAt: stored.updatedAt,
      expiresAt: stored.expiresAt,
      ...(stored.dossierId ? { dossierId: stored.dossierId } : {}),
    };
    return { value, stats };
  } catch {
    stats.failed++;
    return { value: null, stats };
  }
}

// ---------------------------------------------------------------------------
// Analyses juridiques : tout le contenu sensible est chiffré dans encryptedPayload
// ---------------------------------------------------------------------------

export async function encryptAnalysisForStorage(
  record: AnalysisRecord,
  keys: RecordKeys
): Promise<AnalysisRecord> {
  const sensitive = {
    situation: String(record.situation || '').slice(0, 24000),
    data: record.data || {},
    selectedClarification: record.selectedClarification || undefined,
    followUpExchanges: record.followUpExchanges || undefined,
    defenseAnalysis: record.defenseAnalysis || undefined,
    compendiumCheck: record.compendiumCheck || (record.data as any)?.compendiumCheck || undefined,
    groundingSources: record.groundingSources || undefined,
  };
  const encryptedPayload = await encryptingMapper(keys)(JSON.stringify(sensitive));
  return {
    id: record.id,
    userId: keys.uid,
    timestamp: record.timestamp,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    language: record.language,
    canton: record.canton || undefined,
    situation: '',
    data: {} as any,
    encryptedPayload,
    isPro: record.isPro,
    dossierId: record.dossierId || undefined,
  };
}

export async function decryptAnalysisFromStorage(
  stored: AnalysisRecord,
  keys: RecordKeys
): Promise<{ value: AnalysisRecord | null; stats: DecryptStats }> {
  const stats = newStats();
  if (!stored || typeof stored !== 'object') {
    stats.failed++;
    return { value: null, stats };
  }
  if (stored.encryptedPayload) {
    const text = await decryptingMapper(keys, stats)(String(stored.encryptedPayload));
    if (stats.failed > 0 || !text) return { value: null, stats };
    try {
      const sensitive = JSON.parse(text);
      const { userEmail: _e, userDisplayName: _d, ...restStored } = stored;
      const { userEmail: _se, userDisplayName: _sd, ...restSensitive } = sensitive || {};
      return {
        value: {
          ...restStored,
          ...restSensitive,
          id: stored.id,
          userId: stored.userId || keys.uid,
        },
        stats,
      };
    } catch {
      stats.failed++;
      return { value: null, stats };
    }
  }
  // Enregistrement hérité en clair : compte comme 'plain' pour déclencher le rechiffrement
  stats.plain++;
  const { userEmail: _e, userDisplayName: _d, ...cleanPlain } = stored;
  return {
    value: {
      ...cleanPlain,
      userId: stored.userId || keys.uid,
    },
    stats,
  };
}

// ---------------------------------------------------------------------------
// Repères cartographiques (landmarks) : tout le contenu est chiffré dans payload
// ---------------------------------------------------------------------------

export interface StoredLandmark {
  id: string;
  userId: string;
  timestamp: number;
  payload: string;
}

export async function encryptLandmarkForStorage(
  landmark: SavedLocation,
  keys: RecordKeys
): Promise<StoredLandmark> {
  const content = {
    title: landmark.title,
    notes: landmark.notes ? landmark.notes.slice(0, 500) : undefined,
    location: landmark.location,
  };
  const payload = await encryptingMapper(keys)(JSON.stringify(content));
  return {
    id: landmark.id,
    userId: keys.uid,
    timestamp: landmark.timestamp || Date.now(),
    payload,
  };
}

export async function decryptLandmarkFromStorage(
  stored: Record<string, any>,
  keys: RecordKeys
): Promise<{ value: SavedLocation | null; stats: DecryptStats }> {
  const stats = newStats();
  if (!stored || typeof stored !== 'object') {
    stats.failed++;
    return { value: null, stats };
  }
  if (typeof stored.payload === 'string' && stored.payload.length > 0) {
    const text = await decryptingMapper(keys, stats)(stored.payload);
    if (stats.failed > 0 || !text) return { value: null, stats };
    try {
      const content = JSON.parse(text);
      return {
        value: {
          id: stored.id,
          timestamp: stored.timestamp || Date.now(),
          title: content.title || '',
          notes: content.notes,
          location: content.location,
          userId: stored.userId || keys.uid,
          syncedToCloud: true,
        },
        stats,
      };
    } catch {
      stats.failed++;
      return { value: null, stats };
    }
  }
  // Repère hérité en clair
  if (stored.location) {
    stats.plain++;
    return {
      value: {
        id: stored.id,
        timestamp: stored.timestamp || Date.now(),
        title: stored.title || '',
        notes: stored.notes,
        location: stored.location,
        userId: stored.userId || keys.uid,
        syncedToCloud: true,
      },
      stats,
    };
  }
  stats.failed++;
  return { value: null, stats };
}
