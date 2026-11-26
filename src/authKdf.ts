/**
 * Secret d'authentification « zero-knowledge » (même principe que Bitwarden).
 *
 * Le mot de passe saisi ne quitte jamais le navigateur. Celui-ci en dérive un secret
 * d'authentification (PBKDF2-SHA256, 600 000 itérations, sel propre au compte), et c'est ce
 * secret, et lui seul, qui est envoyé au serveur et vérifié par PocketBase.
 *
 * La clé qui ouvre l'enveloppe « mot de passe » du coffre est dérivée séparément du même mot de
 * passe (studioE2ee.ts, autre sel). Connaître le secret d'authentification ne donne donc pas cette
 * clé : il faudrait retrouver le mot de passe par force brute, au prix de 600 000 itérations par
 * essai.
 *
 * Module pur, sans dépendance au navigateur : WebCrypto (`globalThis.crypto.subtle`) existe aussi
 * dans Node. Le serveur l'importe tel quel (comptes de développement, migration des anciens
 * comptes), ce qui garantit une dérivation identique des deux côtés.
 */

/** Version du schéma de dérivation, renvoyée par /api/auth/prelogin (0 = ancien compte). */
export const AUTH_KDF_VERSION = 1;
export const AUTH_KDF_ITERATIONS = 600_000;
/** Préfixe du secret envoyé au serveur : distingue un secret dérivé d'un mot de passe brut. */
export const AUTH_SECRET_PREFIX = 'lpa1.';
/** Taille du sel propre au compte, en octets. */
export const AUTH_SALT_BYTES = 16;

/** Séparation de domaine : ce sel ne peut pas coïncider avec celui de l'enveloppe du coffre. */
const AUTH_SALT_CONTEXT = 'lexpol.ch/auth|v1|';

const AUTH_SALT_PATTERN = /^[A-Za-z0-9_-]{22}$/;
const AUTH_SECRET_PATTERN = /^lpa1\.[A-Za-z0-9_-]{43}$/;

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Sel de compte valide : 16 octets en base64url (22 caractères). */
export function isAuthSalt(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    AUTH_SALT_PATTERN.test(value) &&
    base64UrlToBytes(value).length === AUTH_SALT_BYTES
  );
}

/** Secret d'authentification bien formé (`lpa1.` suivi de 32 octets en base64url). */
export function isAuthSecret(value: unknown): value is string {
  return typeof value === 'string' && AUTH_SECRET_PATTERN.test(value);
}

/** Tire un nouveau sel de compte (inscription, migration d'un ancien compte). */
export function newAuthSalt(): string {
  const bytes = new Uint8Array(AUTH_SALT_BYTES);
  globalThis.crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

/**
 * Dérive le secret d'authentification à partir du mot de passe et du sel du compte.
 * Le nombre d'itérations est fixé dans le code : un serveur ne peut pas l'abaisser.
 */
export async function deriveAuthSecret(password: string, salt: string): Promise<string> {
  if (!isAuthSalt(salt)) throw new Error('Sel d’authentification invalide.');
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('Mot de passe vide.');
  }
  const encoder = new TextEncoder();
  const context = encoder.encode(AUTH_SALT_CONTEXT);
  const saltBytes = base64UrlToBytes(salt);
  const fullSalt = new Uint8Array(context.length + saltBytes.length);
  fullSalt.set(context, 0);
  fullSalt.set(saltBytes, context.length);

  const subtle = globalThis.crypto.subtle;
  const base = await subtle.importKey(
    'raw',
    encoder.encode(password.normalize('NFC')) as BufferSource,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: fullSalt as BufferSource,
      iterations: AUTH_KDF_ITERATIONS,
    },
    base,
    256
  );
  return `${AUTH_SECRET_PREFIX}${bytesToBase64Url(new Uint8Array(bits))}`;
}
