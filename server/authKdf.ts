import crypto from 'crypto';
import { getPbAdmin } from './pocketbase';
import { AUTH_KDF_VERSION, AUTH_SALT_BYTES, isAuthSalt } from '../../src/utils/authKdf';

/**
 * Paramètres de dérivation du secret d'authentification (voir src/utils/authKdf.ts).
 *
 * - `version: 1` et le sel du compte : le navigateur dérive le secret et n'envoie que lui ;
 * - `version: 0` : ancien compte dont le mot de passe n'a pas encore été converti. Le navigateur
 *   se connecte une dernière fois avec le mot de passe, puis demande la conversion.
 *
 * Une adresse inconnue reçoit `version: 1` et un sel fictif, stable pour une même adresse : la
 * réponse ne révèle pas si un compte existe.
 */
export type PreloginParams = { version: 0 } | { version: typeof AUTH_KDF_VERSION; salt: string };

const FAKE_SALT_KEY = crypto
  .createHash('sha256')
  .update(`lexpol.ch/prelogin|${process.env.APP_SECRET || 'lexpol-dev-prelogin-only'}`)
  .digest();

/** Sel fictif d'une adresse sans compte : déterministe, indiscernable d'un vrai sel. */
export function fakeAuthSalt(email: string): string {
  return crypto
    .createHmac('sha256', FAKE_SALT_KEY)
    .update(email)
    .digest()
    .subarray(0, AUTH_SALT_BYTES)
    .toString('base64url');
}

/**
 * Paramètres de connexion d'une adresse. La recherche est exacte, comme celle de PocketBase à la
 * connexion (qui distingue les majuscules) : le sel renvoyé est celui du compte que PocketBase
 * ouvrira avec cette même adresse.
 */
export async function getPreloginParams(email: string): Promise<PreloginParams> {
  const pb = await getPbAdmin();
  const found = await pb.collection('users').getList(1, 1, {
    filter: pb.filter('email = {:email}', { email }),
    fields: 'id,authSalt',
    skipTotal: true,
  });
  const record = found.items[0] as { authSalt?: string } | undefined;
  if (!record) return { version: AUTH_KDF_VERSION, salt: fakeAuthSalt(email) };
  if (isAuthSalt(record.authSalt)) return { version: AUTH_KDF_VERSION, salt: record.authSalt };
  return { version: 0 };
}
