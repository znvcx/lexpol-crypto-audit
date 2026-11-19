/**
 * Déverrouillage biométrique local du coffre E2EE (WebAuthn / Passkey / TouchID / FaceID / Windows Hello).
 *
 * Architecture Zero-Knowledge :
 * 1. L'utilisateur active le déverrouillage biométrique sur son appareil alors que son coffre est ouvert.
 * 2. Le navigateur crée un identifiant WebAuthn lié à l'authenticator matériel de l'appareil
 *    (`authenticatorAttachment: 'platform'`, `userVerification: 'required'`).
 * 3. La clé maître E2EE (DEK) est enveloppée (AES-GCM 256) avec une clé d'enveloppe non-extractible
 *    stockée dans IndexedDB (ou dérivée via l'extension WebAuthn PRF si le matériel la supporte)
 *    et liée cryptographiquement (AAD) au `credentialId` WebAuthn et à l'UID du compte.
 * 4. Lors d'un verrouillage rapide (« Fin de service ») ou d'une reprise de session sur cet appareil,
 *    la clé enveloppée biométrique ne peut être déverrouillée QU'APRÈS une assertion WebAuthn réussie
 *    (`navigator.credentials.get` avec `userVerification: 'required'`).
 * 5. À la déconnexion complète (`logoutUser`), l'enveloppe biométrique est purgée avec IndexedDB.
 */
import {
  base64ToBytes,
  bytesToBase64,
  DeviceWrappedDek,
  randomBytes,
  StudioDek,
  unwrapDekFromDevice,
  wrapDekForDevice,
  WrappedKeyBlob,
} from './studioE2ee';
import { deviceStoreDelete, deviceStoreGet, deviceStoreSet } from './vaultDeviceStore';

export const BIOMETRIC_DEK_PREFIX = 'biometric:';
const PRF_HKDF_INFO = 'lexpol-studio-webauthn-prf-kek-v2';
const utf8Encoder = new TextEncoder();

export interface BiometricVaultRecord {
  credentialId: string;
  prfSupported: boolean;
  prfSalt?: string;
  /** Présent si PRF est supporté : la DEK est chiffrée par la sortie PRF matérielle. */
  prfBlob?: WrappedKeyBlob;
  /** Présent si PRF n'est pas supporté par l'OS : la DEK est enveloppée par une CryptoKey non-extractible dans IndexedDB, conditionnée par l'assertion biométrique WebAuthn. */
  deviceWrapped?: DeviceWrappedDek;
  keyId: string;
  createdAt: string;
}

function biometricStorageKey(uid: string): string {
  return `${BIOMETRIC_DEK_PREFIX}${uid}`;
}

/** Vérifie si l'appareil supporte un capteur biométrique de plateforme (TouchID, FaceID, Windows Hello, Android Biometrics). */
export async function isBiometricUnlockSupported(): Promise<boolean> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) return false;
  try {
    if (
      typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function'
    ) {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }
    return false;
  } catch {
    return false;
  }
}

/** Indique si un verrou biométrique est configuré sur cet appareil pour ce compte. */
export async function hasBiometricVaultEnrollment(uid: string | null | undefined): Promise<boolean> {
  if (!uid) return false;
  try {
    const rec = await deviceStoreGet<BiometricVaultRecord>(biometricStorageKey(uid));
    return Boolean(rec && rec.credentialId);
  } catch {
    return false;
  }
}

async function derivePrfKek(prfOutput: ArrayBuffer, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info: utf8Encoder.encode(PRF_HKDF_INFO) as BufferSource,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

function prfAad(uid: string, credentialId: string, keyId: string): BufferSource {
  return utf8Encoder.encode(
    `lexpol.ch/studio-biometric-prf|v2|${uid}|${credentialId}|${keyId}`
  ) as BufferSource;
}

/**
 * Enrôle le déverrouillage biométrique (TouchID / FaceID / Windows Hello) sur l'appareil courant.
 */
export async function enrollBiometricVaultUnlock(
  uid: string,
  email: string,
  dek: StudioDek
): Promise<boolean> {
  if (!(await isBiometricUnlockSupported())) {
    throw new Error('BIOMETRIC_UNSUPPORTED');
  }

  const challenge = randomBytes(32);
  const prfSalt = randomBytes(32);
  const userIdBytes = utf8Encoder.encode(uid.slice(0, 64));

  const createOptions: CredentialCreationOptions = {
    publicKey: {
      challenge: challenge as BufferSource,
      rp: {
        name: 'LexPol.ch (Coffre Zero-Knowledge)',
        id: window.location.hostname,
      },
      user: {
        id: userIdBytes as BufferSource,
        name: email || uid,
        displayName: email || 'Agent LexPol',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred',
      },
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: prfSalt as BufferSource,
          },
        },
      } as any,
    },
  };

  const cred = (await navigator.credentials.create(createOptions)) as PublicKeyCredential | null;
  if (!cred) throw new Error('BIOMETRIC_CANCELLED');

  const credentialId = bytesToBase64(new Uint8Array(cred.rawId));
  const extResults = (cred.getClientExtensionResults?.() || {}) as any;
  const prfFirst: ArrayBuffer | undefined = extResults?.prf?.results?.first;

  if (prfFirst && prfFirst.byteLength >= 32) {
    const kek = await derivePrfKek(prfFirst, prfSalt);
    const iv = randomBytes(12);
    const wrapped = await crypto.subtle.wrapKey('raw', dek.key, kek, {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: prfAad(uid, credentialId, dek.keyId),
    });
    const record: BiometricVaultRecord = {
      credentialId,
      prfSupported: true,
      prfSalt: bytesToBase64(prfSalt),
      prfBlob: {
        iv: bytesToBase64(iv),
        ct: bytesToBase64(new Uint8Array(wrapped)),
      },
      keyId: dek.keyId,
      createdAt: new Date().toISOString(),
    };
    await deviceStoreSet(biometricStorageKey(uid), record);
    return true;
  }

  // Fallback matériel (appareils Windows Hello / iOS sans extension PRF) :
  // Enveloppe CryptoKey non-extractible dans IndexedDB protégée par une vérification biométrique obligatoire.
  const deviceWrapped = await wrapDekForDevice(dek, uid);
  const record: BiometricVaultRecord = {
    credentialId,
    prfSupported: false,
    prfSalt: bytesToBase64(prfSalt),
    deviceWrapped,
    keyId: dek.keyId,
    createdAt: new Date().toISOString(),
  };
  await deviceStoreSet(biometricStorageKey(uid), record);
  return true;
}

/**
 * Déverrouille la clé maître E2EE (DEK) après vérification biométrique locale (TouchID / FaceID / Windows Hello).
 */
export async function unlockDekWithBiometrics(
  uid: string,
  extractable = false
): Promise<StudioDek> {
  const record = await deviceStoreGet<BiometricVaultRecord>(biometricStorageKey(uid));
  if (!record || !record.credentialId) {
    throw new Error('BIOMETRIC_NOT_ENROLLED');
  }

  const challenge = randomBytes(32);
  const credIdBytes = base64ToBytes(record.credentialId);
  const prfSalt = record.prfSalt ? base64ToBytes(record.prfSalt) : randomBytes(32);

  const getOptions: CredentialRequestOptions = {
    publicKey: {
      challenge: challenge as BufferSource,
      rpId: window.location.hostname,
      allowCredentials: [
        {
          type: 'public-key',
          id: credIdBytes as BufferSource,
          transports: ['internal'],
        },
      ],
      userVerification: 'required',
      timeout: 60000,
      ...(record.prfSupported
        ? {
            extensions: {
              prf: {
                eval: {
                  first: prfSalt as BufferSource,
                },
              },
            } as any,
          }
        : {}),
    },
  };

  const assertion = (await navigator.credentials.get(getOptions)) as PublicKeyCredential | null;
  if (!assertion) {
    throw new Error('BIOMETRIC_CANCELLED');
  }

  if (record.prfSupported && record.prfBlob) {
    const extResults = (assertion.getClientExtensionResults?.() || {}) as any;
    const prfFirst: ArrayBuffer | undefined = extResults?.prf?.results?.first;
    if (!prfFirst) throw new Error('BIOMETRIC_PRF_FAILED');
    const kek = await derivePrfKek(prfFirst, prfSalt);
    const key = await crypto.subtle.unwrapKey(
      'raw',
      base64ToBytes(record.prfBlob.ct) as BufferSource,
      kek,
      {
        name: 'AES-GCM',
        iv: base64ToBytes(record.prfBlob.iv) as BufferSource,
        additionalData: prfAad(uid, record.credentialId, record.keyId),
      },
      { name: 'AES-GCM', length: 256 },
      extractable,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
    return { key, keyId: record.keyId };
  }

  if (record.deviceWrapped) {
    return unwrapDekFromDevice(record.deviceWrapped, uid, extractable);
  }

  throw new Error('BIOMETRIC_CORRUPTED');
}

/** Supprime l'enrôlement biométrique sur cet appareil pour ce compte. */
export async function removeBiometricVaultUnlock(uid: string): Promise<void> {
  await deviceStoreDelete(biometricStorageKey(uid));
}
