import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import {
  AUTH_KDF_ITERATIONS,
  deriveAuthSecret,
  isAuthSalt,
  isAuthSecret,
  newAuthSalt,
} from '../../src/utils/authKdf';
import { fakeAuthSalt } from '../services/authKdf';
import { passwordUpgradeSchema, preloginSchema, registrationSignupSchema } from '../schemas';

/** Calcul de référence indépendant (crypto de Node), pour vérifier la dérivation WebCrypto. */
function referenceSecret(password: string, salt: string): string {
  const fullSalt = Buffer.concat([
    Buffer.from('lexpol.ch/auth|v1|', 'utf8'),
    Buffer.from(salt, 'base64url'),
  ]);
  const key = crypto.pbkdf2Sync(password.normalize('NFC'), fullSalt, 600_000, 32, 'sha256');
  return `lpa1.${key.toString('base64url')}`;
}

describe('Secret d’authentification (zero-knowledge)', () => {
  it('dérive exactement le calcul de référence PBKDF2-SHA256 à 600 000 itérations', async () => {
    assert.equal(AUTH_KDF_ITERATIONS, 600_000);
    const salt = 'AAECAwQFBgcICQoLDA0ODw'; // octets 0x00 à 0x0f
    const secret = await deriveAuthSecret('Correct-Horse-Battery-9!', salt);
    assert.equal(secret, referenceSecret('Correct-Horse-Battery-9!', salt));
    assert.ok(isAuthSecret(secret));
  });

  it('normalise le mot de passe (NFC) : é composé ou décomposé donnent le même secret', async () => {
    const salt = newAuthSalt();
    const composed = await deriveAuthSecret('Café-Mot-De-Passe-1', salt);
    const decomposed = await deriveAuthSecret('Café-Mot-De-Passe-1', salt);
    assert.equal(composed, decomposed);
  });

  it('change de secret avec le sel ou le mot de passe, et ne contient pas le mot de passe', async () => {
    const salt = newAuthSalt();
    const a = await deriveAuthSecret('mot-de-passe-A-1!', salt);
    assert.notEqual(a, await deriveAuthSecret('mot-de-passe-B-1!', salt));
    assert.notEqual(a, await deriveAuthSecret('mot-de-passe-A-1!', newAuthSalt()));
    assert.ok(!a.includes('mot-de-passe'));
  });

  it('diffère de la clé de l’enveloppe du coffre (même mot de passe, même octets de sel)', async () => {
    // L'enveloppe du coffre dérive PBKDF2(mot de passe, sel) sans le préfixe de domaine.
    const salt = newAuthSalt();
    const vaultKey = crypto
      .pbkdf2Sync('mot-de-passe-A-1!', Buffer.from(salt, 'base64url'), 600_000, 32, 'sha256')
      .toString('base64url');
    const secret = await deriveAuthSecret('mot-de-passe-A-1!', salt);
    assert.notEqual(secret.slice(5), vaultKey);
  });

  it('refuse un sel mal formé ou un mot de passe vide', async () => {
    await assert.rejects(deriveAuthSecret('x', 'trop-court'));
    await assert.rejects(deriveAuthSecret('', newAuthSalt()));
    assert.equal(isAuthSalt('AAECAwQFBgcICQoLDA0ODw'), true);
    assert.equal(isAuthSalt('AAECAwQFBgcICQoLDA0OD'), false);
    assert.equal(isAuthSalt('AAECAwQFBgcICQoLDA0OD+'), false);
    assert.equal(isAuthSecret('mon-mot-de-passe'), false);
  });

  it('tire des sels valides et distincts', () => {
    const a = newAuthSalt();
    const b = newAuthSalt();
    assert.ok(isAuthSalt(a) && isAuthSalt(b));
    assert.notEqual(a, b);
  });
});

describe('Pré-connexion : sel fictif des adresses inconnues', () => {
  it('est stable pour une adresse, différent d’une autre, et bien formé', () => {
    const a = fakeAuthSalt('inconnu@example.ch');
    assert.equal(a, fakeAuthSalt('inconnu@example.ch'));
    assert.notEqual(a, fakeAuthSalt('autre@example.ch'));
    assert.ok(isAuthSalt(a));
  });
});

describe('Schémas : le serveur ne reçoit jamais de mot de passe brut', () => {
  const base = { email: 'agent@example.ch', name: '', preferredLanguage: 'fr' };

  it('refuse une inscription avec un mot de passe en clair (ancienne application)', () => {
    const raw = registrationSignupSchema.safeParse({
      ...base,
      password: 'Un-Mot-De-Passe-Solide-2026!',
      authSalt: newAuthSalt(),
    });
    assert.equal(raw.success, false);
    const noSalt = registrationSignupSchema.safeParse({
      ...base,
      password: `lpa1.${'A'.repeat(43)}`,
    });
    assert.equal(noSalt.success, false);
  });

  it('accepte le secret dérivé et son sel', async () => {
    const authSalt = newAuthSalt();
    const password = await deriveAuthSecret('Un-Mot-De-Passe-Solide-2026!', authSalt);
    const ok = registrationSignupSchema.safeParse({ ...base, password, authSalt });
    assert.equal(ok.success, true);
  });

  it('ne met pas l’adresse en minuscules à la pré-connexion (PocketBase distingue la casse)', () => {
    const parsed = preloginSchema.parse({ email: '  Agent.Dupont@Example.ch ' });
    assert.equal(parsed.email, 'Agent.Dupont@Example.ch');
  });

  it('exige un sel valide pour convertir un ancien compte', () => {
    assert.equal(
      passwordUpgradeSchema.safeParse({ currentPassword: 'x', authSalt: 'nope' }).success,
      false
    );
    assert.equal(
      passwordUpgradeSchema.safeParse({ currentPassword: 'x', authSalt: newAuthSalt() }).success,
      true
    );
  });
});
