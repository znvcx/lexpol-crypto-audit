import { describe, it, expect } from 'vitest';
import { BIP39_ENGLISH_WORDLIST } from './bip39English';
import {
  RECORD_PREFIX,
  RECORD_PREFIX_V3,
  PBKDF2_MIN_ITERATIONS,
  UNREADABLE_PLACEHOLDER,
  VaultCryptoError,
  checkRecoveryPhraseInput,
  createCryptoDocument,
  decryptDossierFromStorage,
  decryptFieldNoteFromStorage,
  decryptRecordString,
  decryptReformulationFromStorage,
  encryptDossierForStorage,
  encryptFieldNoteForStorage,
  encryptRecordString,
  encryptReformulationForStorage,
  entropyToMnemonic,
  finalizeKeyRotation,
  generateDek,
  generateRecoveryPhrase,
  mapDossierSensitiveFields,
  mnemonicToEntropy,
  needsReencryption,
  pickConfirmationPositions,
  prepareKeyRotation,
  rewrapPasswordEnvelope,
  unlockCryptoDocument,
  unwrapDekFromDevice,
  wrapDekForDevice,
  RecordKeys,
  StudioDek,
} from './studioE2ee';
import { decryptLegacyString } from './studioCryptoLegacy';
import { Dossier, FieldNote, ReformulationRecord } from '../types';

const UID = 'uid_officer_42';
const PASSWORD = 'Correct-Horse-Battery-9!';
const SLOW = 60_000; // PBKDF2 at 600 000 iterations

/** Fixtures produced by the former ENCv1 implementation (SHA-256-CTR + HMAC, uid "officer_legacy"). */
const LEGACY = {
  uid: 'officer_legacy',
  title: {
    cipher:
      'ENCv1:7dbc03b1ce93ef71c0c85ca5e3096112:6310f42e43627dd2cf2ee83550ce1ed4:dRlbdvbJE/ntIK7F6jtoPRwnv+S9a8VGy8i1AoqbMKOoGmm4vZxy',
    plain: 'Trafic de stupéfiants place de la gare',
  },
  long: {
    cipher:
      'ENCv1:d4e56dee1ed878a56c4ceec0ff91bdad:c2c96b82b561d3d2841f2b1993f23dc3:4AvssdFj2odNIgVSyxUjg8ORq+OSnIrGvN1hmYPb4GIaX+OdzpWPnEMjpo5BmmVdExR3GOherVGAoWORA/n3ZA39rGEo42IdhjK8XbLkjYkQm9VGsIOgvIY6gzvo8Bf6+lNHRvNIsGIlIURhM1ayEcmrfjfa5B7QuXdtUqRMuRJKI4zL5BYTLcDR+V/MrdUk+MSuk6+hlu5O5QzeZ28rUV44Udl2XWKcmT94GY32ww==',
    plain: 'Notes de filature confidentielles. '.repeat(5),
  },
  guest: {
    cipher:
      'ENCv1:5565c966b0689988d645ddc874ba773b:6049d94fee822bfa7ad66e82eb659cfa:w+nUnz2c0AD1e7y6c50pUcU=',
    plain: 'Brouillon invité',
  },
};

function keysFor(dek: StudioDek, uid = UID): RecordKeys {
  return { uid, active: dek, ring: new Map([[dek.keyId, dek.key]]) };
}

function sampleDossier(): Dossier {
  return {
    id: 'dos_secret_01',
    reference: 'DOS-2026-7777',
    userId: UID,
    title: 'Trafic de stupéfiants place de la gare',
    description: 'Observation discrète de suspect X',
    content: 'Notes de filature confidentielles',
    category: 'stupefiants',
    status: 'en_cours',
    urgency: 'haute',
    tags: ['LStup'],
    tasks: [
      {
        id: 't1',
        dossierId: 'dos_secret_01',
        title: 'Interpellation de [ENTITY_01]',
        isCompleted: false,
        priority: 'urgente',
        position: 0,
        createdAt: '2026-10-20T10:00:00.000Z',
      },
    ],
    logs: [
      {
        id: 'l1',
        dossierId: 'dos_secret_01',
        content: 'Transaction observée à 15h12',
        logDate: '2026-10-20T15:12:00.000Z',
        type: 'acte_enquete',
        authorName: 'Agent 204',
      },
    ],
    reports: [
      {
        id: 'rep_1',
        title: 'Rapport de dénonciation LStup',
        text: 'En date du 20 octobre 2026, la patrouille a interpellé le prévenu…',
        summary: 'Saisie de 50 g sous scellés',
        updatedAt: '2026-10-20T16:00:00.000Z',
        involvedEntities: [
          { id: 'ent_1', type: 'person', realName: 'Boris Petrov', alias: '[ENTITY_01]' },
        ],
      },
    ],
    customFields: [{ key: 'magistrat', label: 'Procureur', value: 'Mme Deillon', type: 'text' }],
    createdAt: '2026-10-20T10:00:00.000Z',
    updatedAt: '2026-10-20T16:00:00.000Z',
    expiresAt: Date.now() + 1_000_000,
  };
}

describe('BIP-39 recovery phrase', () => {
  it('ships the canonical English wordlist (SHA-256 of english.txt)', async () => {
    expect(BIP39_ENGLISH_WORDLIST).toHaveLength(2048);
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(BIP39_ENGLISH_WORDLIST.join('\n') + '\n')
    );
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
    expect(hex).toBe('2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda');
  });

  it('matches the official BIP-39 test vector for 256-bit entropy', async () => {
    const words = await entropyToMnemonic(new Uint8Array(32).fill(0x7f));
    expect(words.join(' ')).toBe(
      'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'
    );
    const zero = await entropyToMnemonic(new Uint8Array(32));
    expect(zero.join(' ')).toBe(`${'abandon '.repeat(23)}art`);
  });

  it('generates 24 words that round-trip to the same 256-bit entropy', async () => {
    const { words, entropy } = await generateRecoveryPhrase();
    expect(words).toHaveLength(24);
    expect(entropy).toHaveLength(32);
    expect(Array.from(await mnemonicToEntropy(words))).toEqual(Array.from(entropy));
  });

  it('accepts a valid phrase with numbering, capitals and 4-letter prefixes', async () => {
    const { words } = await generateRecoveryPhrase();
    const typed = words
      .map((w, i) => `${i + 1}. ${i % 2 ? w.toUpperCase() : w.slice(0, 4)}`)
      .join('\n');
    const check = await checkRecoveryPhraseInput(typed);
    expect(check.ok).toBe(true);
    expect(check.words).toEqual(words);
  });

  it('rejects a phrase whose checksum is wrong', async () => {
    // Phrase valide connue (entropie nulle, mot 24 « art ») dont le dernier mot est remplacé :
    // 24 × « abandon » a une somme de contrôle fausse de façon déterministe.
    const altered = Array<string>(24).fill('abandon');
    const check = await checkRecoveryPhraseInput(altered.join(' '));
    expect(check.ok).toBe(false);
    expect(check.reason).toBe('checksum');
    await expect(mnemonicToEntropy(altered)).rejects.toBeInstanceOf(VaultCryptoError);
  });

  it('reports unknown words and wrong lengths', async () => {
    const unknown = await checkRecoveryPhraseInput('abandon notaword ' + 'abandon '.repeat(22));
    expect(unknown).toMatchObject({ ok: false, reason: 'unknown-word', unknownPositions: [2] });
    const short = await checkRecoveryPhraseInput('abandon abandon abandon');
    expect(short).toMatchObject({ ok: false, reason: 'length' });
  });

  it('picks 3 distinct confirmation positions', () => {
    const positions = pickConfirmationPositions(3);
    expect(new Set(positions).size).toBe(3);
    positions.forEach((p) => expect(p).toBeGreaterThanOrEqual(0));
    positions.forEach((p) => expect(p).toBeLessThan(24));
  });
});

describe('Master key envelopes (users/{uid}/settings/crypto)', () => {
  it(
    'creates a document that holds only ciphertext and public parameters, and unlocks with password or phrase',
    async () => {
      const dek = await generateDek();
      const phrase = await generateRecoveryPhrase();
      const doc = await createCryptoDocument({
        uid: UID,
        dek,
        phraseEntropy: phrase.entropy,
        password: PASSWORD,
      });

      const serialized = JSON.stringify(doc);
      expect(serialized).not.toContain(PASSWORD);
      expect(serialized).not.toContain(phrase.words.slice(0, 3).join(' '));
      expect(doc.kdf.password).toMatchObject({ name: 'PBKDF2', hash: 'SHA-256' });
      expect(doc.kdf.password!.iterations).toBeGreaterThanOrEqual(600_000);
      expect(atob(doc.kdf.password!.salt)).toHaveLength(16);
      expect(atob(doc.wrappedDekPassword!.iv)).toHaveLength(12);
      expect(atob(doc.wrappedDekPhrase.iv)).toHaveLength(12);
      expect(doc.version).toBe(2);

      const sample = await encryptRecordString('Déposition sous secret de fonction', dek, UID);
      const byPassword = await unlockCryptoDocument(doc, UID, { password: PASSWORD });
      const byPhrase = await unlockCryptoDocument(doc, UID, {
        phraseEntropy: await mnemonicToEntropy(phrase.words),
      });
      expect((await decryptRecordString(sample, byPassword.ring, UID)).text).toBe(
        'Déposition sous secret de fonction'
      );
      expect((await decryptRecordString(sample, byPhrase.ring, UID)).text).toBe(
        'Déposition sous secret de fonction'
      );
    },
    SLOW
  );

  it(
    'fails with a wrong password, a wrong phrase, or another account uid',
    async () => {
      const dek = await generateDek();
      const phrase = await generateRecoveryPhrase();
      const doc = await createCryptoDocument({
        uid: UID,
        dek,
        phraseEntropy: phrase.entropy,
        password: PASSWORD,
      });
      const other = await generateRecoveryPhrase();

      await expect(
        unlockCryptoDocument(doc, UID, { password: 'Wrong-Password-1!' })
      ).rejects.toMatchObject({ code: 'wrong-secret' });
      await expect(
        unlockCryptoDocument(doc, UID, { phraseEntropy: other.entropy })
      ).rejects.toMatchObject({ code: 'wrong-secret' });
      // AAD binds the envelope to its account: copying the document to another uid does not open it.
      await expect(
        unlockCryptoDocument(doc, 'uid_attacker', { phraseEntropy: phrase.entropy })
      ).rejects.toMatchObject({ code: 'wrong-secret' });
    },
    SLOW
  );

  it(
    'password change re-wraps only wrappedDekPassword: the old envelope stops working, the phrase still works',
    async () => {
      const dek = await generateDek();
      const phrase = await generateRecoveryPhrase();
      const doc = await createCryptoDocument({
        uid: UID,
        dek,
        phraseEntropy: phrase.entropy,
        password: PASSWORD,
      });
      const record = await encryptRecordString('Rapport inchangé', dek, UID);

      const unlocked = await unlockCryptoDocument(doc, UID, { password: PASSWORD });
      const updated = await rewrapPasswordEnvelope(doc, UID, unlocked, 'New-Passphrase-2026!');

      expect(updated.wrappedDekPhrase).toEqual(doc.wrappedDekPhrase);
      expect(updated.keyId).toBe(doc.keyId);
      expect(updated.wrappedDekPassword).not.toEqual(doc.wrappedDekPassword);
      await expect(
        unlockCryptoDocument(updated, UID, { password: PASSWORD })
      ).rejects.toMatchObject({ code: 'wrong-secret' });

      const viaNew = await unlockCryptoDocument(updated, UID, { password: 'New-Passphrase-2026!' });
      const viaPhrase = await unlockCryptoDocument(updated, UID, { phraseEntropy: phrase.entropy });
      // Records written before the change remain readable without any re-encryption.
      expect((await decryptRecordString(record, viaNew.ring, UID)).text).toBe('Rapport inchangé');
      expect((await decryptRecordString(record, viaPhrase.ring, UID)).text).toBe(
        'Rapport inchangé'
      );
    },
    SLOW
  );

  it(
    'forgotten password: unlock with the phrase, then rebuild the password envelope',
    async () => {
      const dek = await generateDek();
      const phrase = await generateRecoveryPhrase();
      const doc = await createCryptoDocument({
        uid: UID,
        dek,
        phraseEntropy: phrase.entropy,
        password: PASSWORD,
      });
      const viaPhrase = await unlockCryptoDocument(doc, UID, { phraseEntropy: phrase.entropy });
      const rebuilt = await rewrapPasswordEnvelope(doc, UID, viaPhrase, 'Reset-By-Email-77!');
      const viaReset = await unlockCryptoDocument(rebuilt, UID, { password: 'Reset-By-Email-77!' });
      expect(viaReset.active.keyId).toBe(dek.keyId);
    },
    SLOW
  );

  it('Google accounts get only the phrase envelope', async () => {
    const dek = await generateDek();
    const phrase = await generateRecoveryPhrase();
    const doc = await createCryptoDocument({
      uid: UID,
      dek,
      phraseEntropy: phrase.entropy,
      password: null,
    });
    expect(doc.wrappedDekPassword).toBeUndefined();
    expect(doc.kdf.password).toBeUndefined();
    await expect(unlockCryptoDocument(doc, UID, { password: PASSWORD })).rejects.toMatchObject({
      code: 'wrong-secret',
    });
    expect(
      (await unlockCryptoDocument(doc, UID, { phraseEntropy: phrase.entropy })).active.keyId
    ).toBe(dek.keyId);
  });

  it('refuses password KDF parameters below 600 000 iterations', async () => {
    const dek = await generateDek();
    const phrase = await generateRecoveryPhrase();
    const doc = await createCryptoDocument({
      uid: UID,
      dek,
      phraseEntropy: phrase.entropy,
      password: null,
    });
    const downgraded = {
      ...doc,
      kdf: {
        ...doc.kdf,
        password: {
          name: 'PBKDF2' as const,
          hash: 'SHA-256' as const,
          iterations: PBKDF2_MIN_ITERATIONS - 1,
          salt: btoa('0123456789abcdef'),
        },
      },
      wrappedDekPassword: doc.wrappedDekPhrase,
    };
    await expect(
      unlockCryptoDocument(downgraded, UID, { password: PASSWORD })
    ).rejects.toMatchObject({ code: 'kdf-params' });
  });

  it('optional device memory wraps the DEK with a non-extractable key', async () => {
    const dek = await generateDek();
    const stored = await wrapDekForDevice(dek, UID);
    expect(stored.kek.extractable).toBe(false);
    const record = await encryptRecordString('Note', dek, UID);
    const restored = await unwrapDekFromDevice(stored, UID);
    expect((await decryptRecordString(record, keysFor(restored).ring, UID)).text).toBe('Note');
    await expect(unwrapDekFromDevice(stored, 'uid_other')).rejects.toMatchObject({
      code: 'wrong-secret',
    });
  });
});

describe('Record encryption (AES-GCM, ENCv2)', () => {
  it('uses a fresh IV per value and the versioned ENCv2:<keyId>: format', async () => {
    const dek = await generateDek();
    const a = await encryptRecordString('Même texte', dek, UID);
    const b = await encryptRecordString('Même texte', dek, UID);
    expect(a.startsWith(`${RECORD_PREFIX}${dek.keyId}:`)).toBe(true);
    expect(a).not.toBe(b);
    expect(a).not.toContain('Même');
  });

  it('detects tampering and refuses other accounts', async () => {
    const dek = await generateDek();
    const ring = keysFor(dek).ring;
    const value = await encryptRecordString('Notes d’instruction secrètes', dek, UID);
    const tampered = value.slice(0, -4) + (value.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    expect(await decryptRecordString(tampered, ring, UID)).toMatchObject({
      source: 'failed',
      text: UNREADABLE_PLACEHOLDER,
    });
    expect(await decryptRecordString(value, ring, 'uid_other')).toMatchObject({ source: 'failed' });
    const otherDek = await generateDek();
    expect(await decryptRecordString(value, keysFor(otherDek).ring, UID)).toMatchObject({
      source: 'failed',
    });
  });

  it('encrypts every sensitive dossier field and restores them', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek);
    const dossier = sampleDossier();
    const encrypted = await encryptDossierForStorage(dossier, keys);
    const fields = [
      encrypted.title,
      encrypted.description,
      encrypted.content,
      encrypted.tasks[0].title,
      encrypted.logs[0].content,
      encrypted.logs[0].authorName,
      encrypted.reports[0].title,
      encrypted.reports[0].text,
      encrypted.reports[0].summary,
      encrypted.reports[0].involvedEntities![0].realName,
      encrypted.customFields![0].value,
    ];
    fields.forEach((f) => expect(f!.startsWith(RECORD_PREFIX_V3)).toBe(true));
    expect(JSON.stringify(encrypted)).not.toContain('Petrov');
    expect(encrypted.reports[0].involvedEntities![0].alias).toBe('[ENTITY_01]');
    expect(encrypted.status).toBe('en_cours');

    const { value, stats } = await decryptDossierFromStorage(encrypted, keys);
    expect(value).toEqual(dossier);
    expect(stats).toMatchObject({ failed: 0, legacy: 0, plain: 0, staleKey: 0 });
    expect(needsReencryption(stats)).toBe(false);
  });

  it('encrypts the note text, its stage and every version in the payload', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek);
    const note: FieldNote = {
      id: 'note_1',
      reference: 'NOTE-2026-1234',
      eventAt: '2026-10-31T02:15',
      location: 'Rue Secrète 4',
      identities: [{ id: 'p1', alias: '[PERSON_01]', values: { lastName: 'PETROV' } }],
      vehicles: [],
      text: 'Rapport : [PERSON_01_NAME] a refusé.',
      stage: 'report',
      textMode: 'police_style',
      summary: 'Refus de signer',
      textVersions: [
        { text: 'Note brute confidentielle', kind: 'note', savedAt: '2026-10-31T02:20:00.000Z' },
      ],
      createdAt: '2026-10-31T02:20:00.000Z',
      updatedAt: '2026-10-31T02:30:00.000Z',
      expiresAt: 4102444800000,
    };
    const stored = await encryptFieldNoteForStorage(note, keys);
    const serialized = JSON.stringify(stored);
    for (const secret of [
      'PETROV',
      'Rue Secrète',
      'Note brute confidentielle',
      'Refus de signer',
      'report',
    ]) {
      expect(serialized).not.toContain(secret);
    }
    expect(stored.payload.startsWith(RECORD_PREFIX_V3)).toBe(true);
    const { value } = await decryptFieldNoteFromStorage(stored, keys);
    expect(value).toEqual(note);
  });

  it('encrypts reformulation records', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek);
    const record: ReformulationRecord = {
      id: 'ref_1',
      userId: UID,
      timestamp: 1,
      createdAt: '2026-10-20T10:00:00.000Z',
      originalText: 'Constat concernant Marc Favre',
      reformulatedText: 'Rapport concernant [ENTITY_01]',
      title: 'Affaire Marc Favre',
      summary: 'Constat initial',
      involvedEntities: [
        { id: 'e1', type: 'person', realName: 'Marc Favre', alias: '[ENTITY_01]' },
      ],
    };
    const encrypted = await encryptReformulationForStorage(record, keys);
    expect(JSON.stringify(encrypted)).not.toContain('Favre');
    expect((await decryptReformulationFromStorage(encrypted, keys)).value).toEqual(record);
  });

  it('encrypts the free-text style instruction of a reformulation', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek);
    const record: ReformulationRecord = {
      id: 'ref_2',
      userId: UID,
      timestamp: 1,
      createdAt: '2026-10-20T10:00:00.000Z',
      originalText: 'Texte',
      reformulatedText: 'Texte reformulé',
      stylePromptUsed: 'Écrire pour le procureur Duvanel, ton neutre',
    };
    const encrypted = await encryptReformulationForStorage(record, keys);
    expect(JSON.stringify(encrypted)).not.toContain('Duvanel');
    expect(encrypted.stylePromptUsed!.startsWith(RECORD_PREFIX_V3)).toBe(true);
    expect((await decryptReformulationFromStorage(encrypted, keys)).value).toEqual(record);
  });

  it('never lets an analysis snapshot through in clear when its encryption fails', async () => {
    const dossier = { ...sampleDossier(), analysisSnapshot: { situation: 'Suspect X' } as any };
    const failOnSnapshot = async (value: string) => {
      if (value.startsWith('{')) throw new Error('encryption failure');
      return `ENC:${value}`;
    };
    await expect(mapDossierSensitiveFields(dossier, failOnSnapshot)).rejects.toThrow(
      'encryption failure'
    );
  });

  it('correctly encrypts and decrypts analysis snapshot when provided as a string', async () => {
    const snapshotObj = { situation: 'Suspect Y', result: 'infraction' };
    const snapshotStr = JSON.stringify(snapshotObj);
    const dossier = { ...sampleDossier(), analysisSnapshot: snapshotStr as any };

    const encryptFn = async (val: string) => `ENCv2:${val}`;
    const encrypted = await mapDossierSensitiveFields(dossier, encryptFn);
    expect(typeof encrypted.analysisSnapshot).toBe('string');
    expect((encrypted.analysisSnapshot as unknown as string).startsWith('ENCv2:')).toBe(true);

    const decryptFn = async (val: string) => val.replace(/^ENCv2:/, '');
    const decrypted = await mapDossierSensitiveFields(encrypted, decryptFn);
    expect(decrypted.analysisSnapshot).toEqual(snapshotObj);

    // Throws if decrypted string is not valid JSON
    const badDossier = { ...sampleDossier(), analysisSnapshot: 'ENCv2:invalid-json' as any };
    await expect(mapDossierSensitiveFields(badDossier, decryptFn)).rejects.toThrow();
  });
});

describe('Legacy ENCv1 migration', () => {
  it('reads the former scheme through WebCrypto, including drafts promoted from guest_user', async () => {
    expect(await decryptLegacyString(LEGACY.title.cipher, LEGACY.uid)).toBe(LEGACY.title.plain);
    expect(await decryptLegacyString(LEGACY.long.cipher, LEGACY.uid)).toBe(LEGACY.long.plain);
    expect(await decryptLegacyString(LEGACY.guest.cipher, LEGACY.uid)).toBe(LEGACY.guest.plain);
    expect(
      await decryptLegacyString(LEGACY.title.cipher.slice(0, -2) + 'AA', LEGACY.uid)
    ).toBeNull();
  });

  it('flags legacy and plaintext fields for re-encryption, then rewrites them as ENCv3', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek, LEGACY.uid);
    const legacyDossier: Dossier = {
      ...sampleDossier(),
      userId: LEGACY.uid,
      title: LEGACY.title.cipher,
      content: LEGACY.long.cipher,
      description: 'Ancienne description jamais chiffrée',
      tasks: [],
      logs: [],
      reports: [],
      customFields: [],
    };
    const first = await decryptDossierFromStorage(legacyDossier, keys);
    expect(first.value.title).toBe(LEGACY.title.plain);
    expect(first.value.content).toBe(LEGACY.long.plain);
    expect(first.stats).toMatchObject({ legacy: 2, plain: 2, failed: 0 });
    expect(needsReencryption(first.stats)).toBe(true);

    const migrated = await encryptDossierForStorage(first.value, keys);
    expect(migrated.title.startsWith(RECORD_PREFIX_V3)).toBe(true);
    const second = await decryptDossierFromStorage(migrated, keys);
    expect(second.value.title).toBe(LEGACY.title.plain);
    expect(needsReencryption(second.stats)).toBe(false);
  });

  it('never marks a record with unreadable fields for rewrite', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek, 'uid_not_the_owner');
    const { stats } = await decryptDossierFromStorage(
      { ...sampleDossier(), title: LEGACY.title.cipher },
      keys
    );
    expect(stats.failed).toBe(1);
    expect(needsReencryption(stats)).toBe(false);
  });

  it('rejects plaintext or legacy ciphertext when strictV2 mode is enabled after migration', async () => {
    const dek = await generateDek();
    const ring = new Map([[dek.keyId, dek.key]]);
    const uid = 'officer-strict-v2';

    // Sans strictV2 : les chaînes en clair ou legacy sont tolérées pour permettre la migration
    const loose = await decryptRecordString('texte en clair', ring, uid, false);
    expect(loose.source).toBe('plain');
    expect(loose.text).toBe('texte en clair');

    // Avec strictV2 : rejet immédiat du clair et marquage en failed (protection anti-injection)
    const strict = await decryptRecordString('texte en clair', ring, uid, true);
    expect(strict.source).toBe('failed');
    expect(strict.text).toBe(UNREADABLE_PLACEHOLDER);

    // Les données ENCv2 légitimes continuent d'être lues avec succès
    const encrypted = await encryptRecordString('donnée secrète', dek, uid);
    const valid = await decryptRecordString(encrypted, ring, uid, true);
    expect(valid.source).toBe('v2');
    expect(valid.text).toBe('donnée secrète');
  });
});

describe('Recovery phrase reset (key rotation)', () => {
  it(
    'keeps data readable with either secret during the rotation, and only with the new one afterwards',
    async () => {
      const current = await generateDek();
      const oldPhrase = await generateRecoveryPhrase();
      const doc = await createCryptoDocument({
        uid: UID,
        dek: current,
        phraseEntropy: oldPhrase.entropy,
        password: PASSWORD,
      });
      const oldRecord = await encryptRecordString('Écrit avec l’ancienne clé', current, UID);

      const next = await generateDek();
      const newPhrase = await generateRecoveryPhrase();
      const rotating = await prepareKeyRotation({
        doc,
        uid: UID,
        current,
        next,
        nextPhraseEntropy: newPhrase.entropy,
        password: PASSWORD,
      });

      for (const secret of [
        { phraseEntropy: oldPhrase.entropy },
        { phraseEntropy: newPhrase.entropy },
        { password: PASSWORD },
      ]) {
        const unlocked = await unlockCryptoDocument(rotating, UID, secret);
        expect(unlocked.active.keyId).toBe(next.keyId);
        expect(unlocked.ring.size).toBe(2);
        const res = await decryptRecordString(oldRecord, unlocked.ring, UID);
        expect(res.text).toBe('Écrit avec l’ancienne clé');
        expect(res.keyId).toBe(current.keyId);
      }

      // Stale-key fields are flagged so the rotation rewrites them with the new key.
      const during = await unlockCryptoDocument(rotating, UID, {
        phraseEntropy: newPhrase.entropy,
      });
      const { stats } = await decryptDossierFromStorage(
        {
          ...sampleDossier(),
          title: oldRecord,
          tasks: [],
          logs: [],
          reports: [],
          customFields: [],
          description: '',
          content: undefined,
        },
        { uid: UID, ...during }
      );
      expect(stats.staleKey).toBe(1);
      expect(needsReencryption(stats)).toBe(true);

      const finalized = finalizeKeyRotation(rotating);
      expect(finalized.rotation).toBeUndefined();
      expect(finalized.keyId).toBe(next.keyId);
      await expect(
        unlockCryptoDocument(finalized, UID, { phraseEntropy: oldPhrase.entropy })
      ).rejects.toMatchObject({ code: 'wrong-secret' });
      const after = await unlockCryptoDocument(finalized, UID, {
        phraseEntropy: newPhrase.entropy,
      });
      expect(after.ring.has(current.keyId)).toBe(false);
      expect(
        (await unlockCryptoDocument(finalized, UID, { password: PASSWORD })).active.keyId
      ).toBe(next.keyId);
    },
    SLOW
  );
});

describe('Record binding (ENCv3)', () => {
  const note = (id: string, text: string, expiresAt = 2_000_000_000_000): FieldNote =>
    ({
      id,
      reference: `R-${id}`,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      expiresAt,
      eventAt: '',
      location: '',
      identities: [],
      vehicles: [],
      text,
    }) as unknown as FieldNote;

  it('refuses a payload copied into another record of the same account', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek, UID);
    const a = await encryptFieldNoteForStorage(note('a', 'secret A'), keys);
    const b = await encryptFieldNoteForStorage(note('b', 'secret B'), keys);
    const swapped = { ...b, payload: a.payload };
    const { value, stats } = await decryptFieldNoteFromStorage(swapped, keys);
    expect(value).toBeNull();
    expect(stats.failed).toBeGreaterThan(0);
    expect((await decryptFieldNoteFromStorage(a, keys)).value?.text).toBe('secret A');
  });

  it('refuses a modified expiry date', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek, UID);
    const stored = await encryptFieldNoteForStorage(note('a', 'secret A'), keys);
    const tampered = { ...stored, expiresAt: stored.expiresAt + 86_400_000 };
    expect((await decryptFieldNoteFromStorage(tampered, keys)).value).toBeNull();
  });

  it('still reads the older ENCv2 format and flags it for rewriting', async () => {
    const dek = await generateDek();
    const keys = keysFor(dek, UID);
    const v2 = await encryptRecordString('{"text":"ancien"}', dek, UID);
    expect(v2.startsWith(RECORD_PREFIX)).toBe(true);
    const stored = { ...(await encryptFieldNoteForStorage(note('a', 'x'), keys)), payload: v2 };
    const { value, stats } = await decryptFieldNoteFromStorage(stored, keys);
    expect(value?.text).toBe('ancien');
    expect(needsReencryption(stats)).toBe(true);
  });

  it('never opens an ENCv3 text without its record context', async () => {
    const dek = await generateDek();
    const ring = new Map([[dek.keyId, dek.key]]);
    const v3 = await encryptRecordString('texte', dek, UID, 'dossiers|d1');
    expect((await decryptRecordString(v3, ring, UID)).source).toBe('failed');
    expect((await decryptRecordString(v3, ring, UID, false, 'dossiers|d2')).source).toBe('failed');
    expect((await decryptRecordString(v3, ring, UID, false, 'dossiers|d1')).text).toBe('texte');
  });
});

describe('Key derivation parameters', () => {
  it('refuses a phrase KDF with an unexpected info string or salt length', async () => {
    const { newPhraseKdfParams, derivePhraseKek } = await import('./studioE2ee');
    const params = newPhraseKdfParams();
    const entropy = new Uint8Array(32);
    await expect(derivePhraseKek(entropy, { ...params, info: 'autre' })).rejects.toThrow();
    await expect(derivePhraseKek(entropy, { ...params, salt: 'AAAA' })).rejects.toThrow();
    await expect(derivePhraseKek(entropy, params)).resolves.toBeDefined();
  });
});
