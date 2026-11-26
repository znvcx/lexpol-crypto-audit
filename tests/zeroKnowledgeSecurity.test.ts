import { describe, expect, it, beforeEach } from 'vitest';
import {
  decryptAnalysisFromStorage,
  decryptDossierFromStorage,
  decryptLandmarkFromStorage,
  encryptAnalysisForStorage,
  encryptDossierForStorage,
  encryptLandmarkForStorage,
  generateDek,
  needsReencryption,
  RECORD_PREFIX_V3,
  RecordKeys,
} from '../utils/studioE2ee';
import {
  hydrateFieldNoteWithLocalIdentities,
  hydrateReformulationWithLocalIdentities,
  isLocalIdentitiesOnlyEnabled,
  prepareFieldNoteForCloudSync,
  prepareReformulationForCloudSync,
  setLocalIdentitiesOnlyEnabled,
} from './localIdentities';
import { anonymizeSituation, detectSensitiveData } from '../utils/deontologySanitizer';
import { AnalysisRecord, Dossier, FieldNote, ReformulationRecord, SavedLocation } from '../types';

async function makeKeys(uid = 'uid_gendarme_1'): Promise<RecordKeys> {
  const dek = await generateDek();
  return {
    uid,
    active: dek,
    ring: new Map([[dek.keyId, dek.key]]),
  };
}

describe('Zero-Knowledge Security & Official Secrecy (Art. 320 CP)', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe('1. Analyses E2EE encryption & migration', () => {
    it('encrypts all sensitive fields of a legal analysis and strips userEmail/userDisplayName', async () => {
      const keys = await makeKeys();
      const plain: AnalysisRecord = {
        id: 'ana_1',
        userId: keys.uid,
        userEmail: 'agent@police.ch',
        userDisplayName: 'Gendarme Test',
        timestamp: Date.now(),
        createdAt: new Date().toISOString(),
        expiresAt: Date.now() + 86400000,
        language: 'fr',
        canton: 'VD',
        situation: 'Contrôle du véhicule conduit par [PERSON_01_NAME] à Lausanne.',
        data: { summary: 'Qualification LCR art. 91' } as any,
        followUpExchanges: [
          { question: 'Question 1', response: 'Réponse 1', timestamp: 123 } as any,
        ],
      };

      const encrypted = await encryptAnalysisForStorage(plain, keys);
      expect(encrypted.situation).toBe('');
      expect(encrypted.data).toEqual({});
      expect(encrypted.userEmail).toBeUndefined();
      expect(encrypted.userDisplayName).toBeUndefined();
      expect(encrypted.encryptedPayload?.startsWith(RECORD_PREFIX_V3)).toBe(true);
      expect(JSON.stringify(encrypted)).not.toContain('Qualification LCR');
      expect(JSON.stringify(encrypted)).not.toContain('agent@police.ch');

      const { value: decrypted, stats } = await decryptAnalysisFromStorage(encrypted, keys);
      expect(stats.failed).toBe(0);
      expect(needsReencryption(stats)).toBe(false);
      expect(decrypted?.situation).toBe(plain.situation);
      expect(decrypted?.data).toEqual(plain.data);
      expect(decrypted?.followUpExchanges).toEqual(plain.followUpExchanges);
    });

    it('flags legacy plaintext analysis records for automatic re-encryption', async () => {
      const keys = await makeKeys();
      const legacyPlain: AnalysisRecord = {
        id: 'ana_legacy',
        userId: keys.uid,
        timestamp: Date.now(),
        createdAt: new Date().toISOString(),
        expiresAt: Date.now() + 86400000,
        language: 'fr',
        situation: 'Ancienne analyse en clair',
        data: { summary: 'Test' } as any,
      };
      const { value, stats } = await decryptAnalysisFromStorage(legacyPlain, keys);
      expect(value?.situation).toBe('Ancienne analyse en clair');
      expect(stats.plain).toBe(1);
      expect(needsReencryption(stats)).toBe(true);
    });
  });

  describe('2. Landmarks & Dossier Tags E2EE encryption', () => {
    it('encrypts landmark coordinates, address and notes into an opaque payload', async () => {
      const keys = await makeKeys();
      const landmark: SavedLocation = {
        id: 'rep_1',
        timestamp: Date.now(),
        title: 'VD › Lausanne › Rue Centrale 10',
        notes: 'Point de contrôle radar et observation discrète',
        location: {
          coords: {
            lat: 46.52,
            lng: 6.63,
            mn95E: 2538000,
            mn95N: 1152000,
            formattedMN95: '2538000 / 1152000',
            formattedWGS84: '46.52000°N, 6.63000°E',
          },
          commune: 'Lausanne',
        } as any,
      };

      const stored = await encryptLandmarkForStorage(landmark, keys);
      expect(stored.payload.startsWith(RECORD_PREFIX_V3)).toBe(true);
      expect(JSON.stringify(stored)).not.toContain('Lausanne');
      expect(JSON.stringify(stored)).not.toContain('observation discrète');

      const { value, stats } = await decryptLandmarkFromStorage(stored, keys);
      expect(stats.failed).toBe(0);
      expect(value?.title).toBe(landmark.title);
      expect(value?.notes).toBe(landmark.notes);
      expect(value?.location.commune).toBe('Lausanne');
    });

    it('encrypts dossier tags and customField labels in addition to content', async () => {
      const keys = await makeKeys();
      const dossier: Dossier = {
        id: 'dos_1',
        reference: 'DOS-2026-1000',
        userId: keys.uid,
        title: 'Affaire stupéfiants',
        description: '',
        category: 'stupefiants',
        status: 'en_cours',
        urgency: 'haute',
        tags: ['Opération Cristal', 'Secteur Gare'],
        customFields: [{ key: 'cf1', label: 'Informateur', value: 'Code 42' }],
        tasks: [],
        logs: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        expiresAt: Date.now() + 86400000,
      };

      const encrypted = await encryptDossierForStorage(dossier, keys);
      expect(JSON.stringify(encrypted)).not.toContain('Opération Cristal');
      expect(JSON.stringify(encrypted)).not.toContain('Informateur');
      expect(encrypted.tags[0].startsWith(RECORD_PREFIX_V3)).toBe(true);
      expect(encrypted.customFields?.[0].label.startsWith(RECORD_PREFIX_V3)).toBe(true);

      const { value: decrypted } = await decryptDossierFromStorage(encrypted, keys);
      expect(decrypted.tags).toEqual(['Opération Cristal', 'Secteur Gare']);
      expect(decrypted.customFields?.[0].label).toBe('Informateur');
      expect(decrypted.customFields?.[0].value).toBe('Code 42');
    });
  });

  describe('3. Local Identities Only mode (Zero nominative data sent to server)', () => {
    it('strips all nominative values before cloud sync when enabled, and rehydrates them locally', async () => {
      await setLocalIdentitiesOnlyEnabled(true);
      expect(isLocalIdentitiesOnlyEnabled()).toBe(true);

      const note: FieldNote = {
        id: 'note_secret_1',
        reference: 'NOTE-2026-1111',
        eventAt: '2026-11-19T14:30',
        location: 'Rue de Bourg 12, 1003 Lausanne',
        identities: [
          {
            id: 'id_1',
            alias: '[PERSON_01]',
            values: {
              lastName: 'KRASNIQI',
              firstName: 'Arben',
              birthDate: '1988-04-12',
              phone: '079 444 55 66',
              role: 'suspect',
            },
          },
        ],
        vehicles: [
          {
            id: 'veh_1',
            alias: '[VEHICLE_01]',
            values: {
              plate: 'VD 456789',
              brand: 'Audi',
              color: 'Noire',
            },
          },
        ],
        entities: [
          {
            id: 'ent_1',
            type: 'company',
            alias: '[COMPANY_01]',
            realName: 'Fiduciaire Léman SA',
          },
        ],
        text: 'Contrôle de [PERSON_01_NAME] au volant du véhicule [VEHICLE_01] devant [PLACE].',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        expiresAt: Date.now() + 86400000,
      };

      const cloudNote = await prepareFieldNoteForCloudSync(note);
      const serializedCloud = JSON.stringify(cloudNote);
      expect(serializedCloud).not.toContain('KRASNIQI');
      expect(serializedCloud).not.toContain('Arben');
      expect(serializedCloud).not.toContain('1988-04-12');
      expect(serializedCloud).not.toContain('079 444 55 66');
      expect(serializedCloud).not.toContain('VD 456789');
      expect(serializedCloud).not.toContain('Rue de Bourg');
      expect(serializedCloud).not.toContain('Fiduciaire Léman');
      // Non-identifying fields remain synced
      expect(cloudNote.identities[0].values.role).toBe('suspect');
      expect(cloudNote.vehicles[0].values.brand).toBe('Audi');

      // Reconcile on the same device
      const rehydrated = hydrateFieldNoteWithLocalIdentities(cloudNote);
      expect(rehydrated.location).toBe('Rue de Bourg 12, 1003 Lausanne');
      expect(rehydrated.identities[0].values.lastName).toBe('KRASNIQI');
      expect(rehydrated.identities[0].values.firstName).toBe('Arben');
      expect(rehydrated.vehicles[0].values.plate).toBe('VD 456789');
      expect(rehydrated.entities?.[0].realName).toBe('Fiduciaire Léman SA');

      // Studio report & dossier entities stripping and rehydration
      const report: ReformulationRecord = {
        id: 'ref_secret_1',
        userId: 'u1',
        timestamp: Date.now(),
        createdAt: new Date().toISOString(),
        originalText: '[PERSON_01] a déclaré...',
        reformulatedText: '[PERSON_01] a déclaré...',
        involvedEntities: [
          { id: 'e1', type: 'person', alias: '[PERSON_01]', realName: 'Krasniqi Arben' },
        ],
      };
      const cloudReport = await prepareReformulationForCloudSync(report);
      expect(JSON.stringify(cloudReport)).not.toContain('Krasniqi');
      const rehydratedReport = hydrateReformulationWithLocalIdentities(cloudReport);
      expect(rehydratedReport.involvedEntities?.[0].realName).toBe('Krasniqi Arben');

      await setLocalIdentitiesOnlyEnabled(false);
    });
  });

  describe('4. Hardened Deontology Sanitizer (Police jargon, IBAN, VIN, DOB, Case Refs)', () => {
    it('detects and masks police jargon names without M./Mme, IBANs, VINs, standalone birthdates and police refs', () => {
      const text =
        "Dans le Journal n° 2026-99881 (procédure PE25.004123), le nommé Krasniqi Arben, 14.05.1989, et la prévenue Muller Sophie ont utilisé l'IBAN CH93 0076 2011 6238 5295 7 et le châssis WVWZZZ1JZ3W386752.";
      const detection = detectSensitiveData(text);
      expect(detection.hasSensitiveData).toBe(true);
      expect(detection.detectedTypes).toContain('policeJargonName');
      expect(detection.detectedTypes).toContain('iban');
      expect(detection.detectedTypes).toContain('vin');
      expect(detection.detectedTypes).toContain('dob');
      expect(detection.detectedTypes).toContain('policeRef');

      const sanitized = anonymizeSituation(text);
      expect(sanitized).not.toContain('Krasniqi');
      expect(sanitized).not.toContain('Muller');
      expect(sanitized).not.toContain('14.05.1989');
      expect(sanitized).not.toContain('CH93 0076');
      expect(sanitized).not.toContain('WVWZZZ1JZ3W386752');
      expect(sanitized).not.toContain('PE25.004123');
    });

    it('detects and masks standalone FirstName LastName / LASTNAME FirstName pairs offline without false positives on legal or geographic terms', () => {
      const text =
        'Lors de la rixe devant la gare de Lausanne, Marc Keller a frappé Luca Bernasconi et KRASNIQI Arben.';
      const detection = detectSensitiveData(text);
      expect(detection.hasSensitiveData).toBe(true);
      expect(detection.detectedTypes).toContain('personName');

      const sanitized = anonymizeSituation(text);
      expect(sanitized).not.toContain('Marc Keller');
      expect(sanitized).not.toContain('Luca Bernasconi');
      expect(sanitized).not.toContain('KRASNIQI Arben');
      expect(sanitized).toContain('Lausanne');

      // Legal and institutional terms must not trigger false positives
      const cleanLegalText =
        'Selon le Code Pénal et le Tribunal Fédéral à Lausanne, le Conducteur A circulait sur la Route Cantonale.';
      const cleanDetection = detectSensitiveData(cleanLegalText);
      expect(cleanDetection.hasSensitiveData).toBe(false);
    });
  });
});
