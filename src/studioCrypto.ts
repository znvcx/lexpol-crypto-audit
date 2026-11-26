/**
 * Coffre local du Studio et hygiène du stockage navigateur.
 *
 * Le chiffrement des données envoyées à la base de données est décrit dans `studioE2ee.ts`
 * (clé maîtresse par utilisateur). Ce module ne protège que les caches locaux
 * (dossiers, entités, réglages) conservés dans localStorage :
 *
 * - AES-GCM 256 avec une clé d'appareil aléatoire et NON extractible, conservée dans IndexedDB ;
 * - la clé et les caches sont effacés à la déconnexion et au changement de compte.
 *
 * Limite assumée : un script exécuté sur l'origine lexpol.ch peut utiliser cette clé. Le coffre
 * local protège contre la lecture brute de localStorage (extensions, copie du profil), pas contre
 * un code malveillant servi par le site lui-même.
 *
 * Les lectures sont synchrones (cache mémoire rempli par `hydrateLocalVault()` au démarrage),
 * les écritures sont asynchrones.
 */
import {
  decryptLegacyLocalPayload,
  isLegacyCiphertext,
  clearLegacyKeyCache,
  LEGACY_DEVICE_SECRET_STORAGE_KEY,
} from './studioCryptoLegacy';
import {
  deviceStoreAdd,
  deviceStoreDelete,
  deviceStoreDeletePrefix,
  deviceStoreGet,
} from './vaultDeviceStore';
import { base64ToBytes, bytesToBase64, randomBytes } from './studioE2ee';

export const LOCAL_VAULT_PREFIX = 'LVv2:';
export const LOCAL_VAULT_KEYS = [
  'lexpol_dossiers_v24m',
  'lexpol_field_notes_v1',
  'lexpol_studio_involved_entities',
  'lexpol_dossier_settings_v1',
  'lexpol_history_v1',
  'lexpol_saved_locations_v1',
  'lexpol_local_identities_v1',
] as const;

const ACTIVE_UID_STORAGE_KEY = '__lexpol_active_uid_v1';
const DEVICE_LOCAL_KEY_ID = 'local-vault-key-v2';
/** Préfixe des DEK mémorisées sur l'appareil (voir services/studioVault.ts). */
export const REMEMBERED_DEK_PREFIX = 'remember:';

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

interface CacheEntry {
  json: string;
  /** Dernière valeur chiffrée écrite dans localStorage (sert à détecter un effacement externe). */
  stored: string | null;
  seq: number;
  pending: number;
}

const cache = new Map<string, CacheEntry>();
let generation = 0;
let deviceKeyPromise: Promise<CryptoKey> | null = null;

function hasLocalStorage(): boolean {
  try {
    return typeof window !== 'undefined' && typeof localStorage !== 'undefined';
  } catch {
    return false;
  }
}

function getDeviceKey(): Promise<CryptoKey> {
  if (!deviceKeyPromise) {
    deviceKeyPromise = (async () => {
      const existing = await deviceStoreGet<CryptoKey>(DEVICE_LOCAL_KEY_ID);
      if (existing) return existing;
      const key = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
      ])) as CryptoKey;
      // Écriture « seulement si absente » : si un autre onglet a créé la clé entre-temps, c'est la sienne
      // qui fait foi (sinon la dernière écrite gagnerait et le cache chiffré par l'autre deviendrait illisible).
      if (await deviceStoreAdd(DEVICE_LOCAL_KEY_ID, key)) return key;
      return (await deviceStoreGet<CryptoKey>(DEVICE_LOCAL_KEY_ID)) ?? key;
    })();
    deviceKeyPromise.catch(() => {
      deviceKeyPromise = null;
    });
  }
  return deviceKeyPromise;
}

/** Compte actif sur ce navigateur (posé par enforceUserSessionIsolation) ; vide tant qu'il est inconnu. */
function activeUid(): string {
  try {
    return localStorage.getItem(ACTIVE_UID_STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

/** AAD du cache local : lie la clé de stockage et le compte. `uid` vide = ancien AAD (lecture de compatibilité). */
function localAad(storageKey: string, uid = activeUid()): BufferSource {
  return utf8Encoder.encode(
    uid ? `lexpol.ch/local-vault|v2|${uid}|${storageKey}` : `lexpol.ch/local-vault|v2|${storageKey}`
  ) as BufferSource;
}

async function encryptLocal(storageKey: string, json: string): Promise<string> {
  const key = await getDeviceKey();
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource, additionalData: localAad(storageKey) },
      key,
      utf8Encoder.encode(json) as BufferSource
    )
  );
  const payload = new Uint8Array(iv.length + ct.length);
  payload.set(iv, 0);
  payload.set(ct, iv.length);
  return `${LOCAL_VAULT_PREFIX}${bytesToBase64(payload)}`;
}

async function decryptLocal(storageKey: string, raw: string): Promise<string | null> {
  try {
    const key = await getDeviceKey();
    const payload = base64ToBytes(raw.slice(LOCAL_VAULT_PREFIX.length));
    // AAD avec le compte d'abord ; à défaut, ancien AAD sans compte (écrit avant cette liaison), réécrit ensuite.
    const candidates = activeUid()
      ? [localAad(storageKey), localAad(storageKey, '')]
      : [localAad(storageKey, '')];
    for (const additionalData of candidates) {
      try {
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: payload.subarray(0, 12) as BufferSource, additionalData },
          key,
          payload.subarray(12) as BufferSource
        );
        return utf8Decoder.decode(plain);
      } catch {
        // essai suivant
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Lecture synchrone d'une valeur du coffre local.
 * Retourne `null` si la clé est absente, ou chiffrée mais pas encore hydratée.
 */
export function readLocalVault<T>(storageKey: string): T | null {
  if (!hasLocalStorage()) return null;
  try {
    const raw = localStorage.getItem(storageKey);
    const entry = cache.get(storageKey);
    if (entry) {
      if (entry.pending > 0 || entry.stored === raw) return JSON.parse(entry.json) as T;
      cache.delete(storageKey); // valeur effacée ou remplacée hors de ce module
    }
    if (!raw || raw.startsWith(LOCAL_VAULT_PREFIX) || isLegacyCiphertext(raw)) return null;
    // Cache local antérieur au chiffrement (JSON en clair) : lu tel quel, rechiffré à la prochaine écriture.
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/** Écrit une valeur : disponible immédiatement en lecture, chiffrée puis persistée en arrière-plan. */
export function writeLocalVault(storageKey: string, value: unknown): Promise<void> {
  if (!hasLocalStorage()) return Promise.resolve();
  const json = JSON.stringify(value);
  const previous = cache.get(storageKey);
  const entry: CacheEntry = {
    json,
    stored: previous?.stored ?? null,
    seq: (previous?.seq ?? 0) + 1,
    pending: (previous?.pending ?? 0) + 1,
  };
  cache.set(storageKey, entry);
  const seq = entry.seq;
  const gen = generation;
  return encryptLocal(storageKey, json)
    .then((ciphertext) => {
      const current = cache.get(storageKey);
      if (gen !== generation || !current || current.seq !== seq) return;
      localStorage.setItem(storageKey, ciphertext);
      current.stored = ciphertext;
    })
    .catch(() => {
      // Échec de chiffrement : rien n'est écrit en clair.
    })
    .finally(() => {
      const current = cache.get(storageKey);
      if (current && gen === generation) current.pending = Math.max(0, current.pending - 1);
    });
}

export function removeLocalVault(storageKey: string): void {
  cache.delete(storageKey);
  try {
    localStorage.removeItem(storageKey);
  } catch {
    // ignore
  }
}

/**
 * Déchiffre les caches locaux en mémoire au démarrage, et migre les anciens formats
 * (JSON en clair, `ENCv1:`) vers le coffre v2.
 */
export async function hydrateLocalVault(keys: readonly string[] = LOCAL_VAULT_KEYS): Promise<void> {
  if (!hasLocalStorage()) return;
  let legacyRemaining = false;
  await Promise.all(
    keys.map(async (storageKey) => {
      let raw: string | null = null;
      try {
        raw = localStorage.getItem(storageKey);
      } catch {
        return;
      }
      if (!raw) return;
      if (raw.startsWith(LOCAL_VAULT_PREFIX)) {
        const json = await decryptLocal(storageKey, raw);
        if (json === null) {
          removeLocalVault(storageKey); // clé d'appareil perdue : le cache est irrécupérable
          return;
        }
        if (!cache.has(storageKey))
          cache.set(storageKey, { json, stored: raw, seq: 0, pending: 0 });
        return;
      }
      // Lecture de compatibilité (point de retrait : voir studioCryptoLegacy.ts).
      const json = isLegacyCiphertext(raw) ? await decryptLegacyLocalPayload(raw) : raw;
      try {
        if (json === null) throw new Error('unreadable');
        await writeLocalVault(storageKey, JSON.parse(json));
      } catch {
        if (isLegacyCiphertext(raw)) legacyRemaining = true;
        else removeLocalVault(storageKey);
      }
    })
  );
  if (!legacyRemaining) {
    try {
      localStorage.removeItem(LEGACY_DEVICE_SECRET_STORAGE_KEY);
    } catch {
      // ignore
    }
  }
}

/**
 * Mémorise l'utilisateur actif et purge les caches du Studio si un autre compte se connecte
 * sur le même navigateur. La DEK en mémoire est gérée par services/studioVault.ts, qui se
 * réinitialise elle-même à chaque changement d'uid.
 */
export function enforceUserSessionIsolation(currentUid: string | null | undefined): void {
  if (!hasLocalStorage()) return;
  try {
    const previousUid = localStorage.getItem(ACTIVE_UID_STORAGE_KEY);
    if (previousUid && currentUid && previousUid !== currentUid) {
      purgeSensitiveStudioStorage();
    }
    if (currentUid) {
      localStorage.setItem(ACTIVE_UID_STORAGE_KEY, currentUid);
    }
  } catch {
    // Non-blocking
  }
}

/**
 * Efface les caches sensibles du Studio (localStorage, mémoire) ainsi que la clé du coffre local
 * et les DEK mémorisées dans IndexedDB. Appelée à la déconnexion, à la suppression du compte
 * et au changement de compte. Les suppressions localStorage sont synchrones ; IndexedDB suit.
 */
export function purgeSensitiveStudioStorage(): Promise<void> {
  generation++;
  cache.clear();
  deviceKeyPromise = null;
  clearLegacyKeyCache();
  if (hasLocalStorage()) {
    try {
      for (const key of LOCAL_VAULT_KEYS) localStorage.removeItem(key);
      localStorage.removeItem('lexpol_history_v1');
      // Dernières adresses cherchées sur la carte (clé de SwissAddressSearch) : données de terrain.
      localStorage.removeItem('lexpol_recent_geo_searches');
      localStorage.removeItem(LEGACY_DEVICE_SECRET_STORAGE_KEY);
      localStorage.removeItem(ACTIVE_UID_STORAGE_KEY);
    } catch {
      // Non-blocking
    }
  }
  return Promise.all([
    deviceStoreDelete(DEVICE_LOCAL_KEY_ID),
    deviceStoreDeletePrefix(REMEMBERED_DEK_PREFIX),
    deviceStoreDeletePrefix('biometric:'),
  ])
    .then(() => undefined)
    .catch(() => undefined);
}
