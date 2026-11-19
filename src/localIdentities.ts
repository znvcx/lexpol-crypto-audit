/**
 * Mode « Identités locales uniquement » (Art. 320 CP / Secret de fonction).
 *
 * Lorsque ce mode est activé par l'utilisateur :
 * - Les vraies valeurs nominatives (noms, prénoms, dates de naissance, téléphones, plaques, adresses,
 *   et les `realName` des entités impliquées dans les notes, dossiers et rapports Studio) ne quittent
 *   JAMAIS l'appareil, même sous forme chiffrée E2EE, vers le serveur PocketBase.
 * - Elles sont conservées exclusivement dans le coffre local de l'appareil (`LVv2:` dans localStorage,
 *   chiffré avec la clé CryptoKey non-extractible stockée dans IndexedDB).
 * - Avant l'envoi au serveur PocketBase, les champs nominatifs sont vidés ou remplacés par leurs alias
 *   (`[PERSON_01_NAME]`, `[VEHICLE_01]`, etc.).
 * - À la lecture sur cet appareil, le registre local réconcilie automatiquement les enregistrements
 *   avec leurs vraies identités. Sur un autre appareil, la note ou le rapport reste 100 % fonctionnel
 *   avec ses alias.
 */
import { Dossier, FieldNote, InvolvedEntity, NoteRecordEntry, ReformulationRecord } from '../types';
import { DEFAULT_NOTE_TEMPLATE } from '../utils/fieldNotes';
import { readLocalVault, writeLocalVault } from '../utils/studioCrypto';
import { auth } from './pocketbase';
import { getUserSetting, setUserSetting } from './pbStore';

export const LOCAL_IDENTITIES_STORAGE_KEY = 'lexpol_local_identities_v1';
const LOCAL_IDENTITIES_PREF_LOCAL_KEY = 'lexpol_local_identities_only_pref_v1';
const LOCAL_IDENTITIES_SETTING_KEY = 'local_identities_only';
export const LOCAL_IDENTITIES_CHANGED_EVENT = 'lexpol_local_identities_only_changed';

export interface LocalNoteIdentitySnapshot {
  location?: string;
  previousLocations?: string[];
  identities?: Array<{
    id: string;
    alias: string;
    values: Record<string, string>;
    previous?: Record<string, string[]>;
  }>;
  vehicles?: Array<{
    id: string;
    alias: string;
    values: Record<string, string>;
    previous?: Record<string, string[]>;
  }>;
  entities?: InvolvedEntity[];
}

export interface LocalIdentityRegistry {
  notes: Record<string, LocalNoteIdentitySnapshot>;
  reports: Record<string, InvolvedEntity[]>;
  dossiers: Record<string, Record<string, InvolvedEntity[]>>;
}

function emptyRegistry(): LocalIdentityRegistry {
  return { notes: {}, reports: {}, dossiers: {} };
}

function loadRegistry(): LocalIdentityRegistry {
  const data = readLocalVault<LocalIdentityRegistry>(LOCAL_IDENTITIES_STORAGE_KEY);
  if (!data || typeof data !== 'object') return emptyRegistry();
  return {
    notes: data.notes && typeof data.notes === 'object' ? data.notes : {},
    reports: data.reports && typeof data.reports === 'object' ? data.reports : {},
    dossiers: data.dossiers && typeof data.dossiers === 'object' ? data.dossiers : {},
  };
}

function saveRegistry(reg: LocalIdentityRegistry): Promise<void> {
  return writeLocalVault(LOCAL_IDENTITIES_STORAGE_KEY, reg);
}

// ---------------------------------------------------------------------------
// Réglage « Identités locales uniquement » (actif / inactif)
// ---------------------------------------------------------------------------

let enabledCache: boolean | null = null;
let enabledCacheUid: string | null = null;

function ensureCacheUid(): void {
  const currentUid = auth?.currentUser?.uid || null;
  if (currentUid !== enabledCacheUid) {
    enabledCacheUid = currentUid;
    enabledCache = null;
  }
}

export function isLocalIdentitiesOnlyEnabled(): boolean {
  ensureCacheUid();
  if (enabledCache !== null) return enabledCache;
  try {
    if (typeof localStorage !== 'undefined') {
      const raw = localStorage.getItem(LOCAL_IDENTITIES_PREF_LOCAL_KEY);
      if (raw !== null) {
        enabledCache = raw === 'true';
        return enabledCache;
      }
    }
  } catch {
    // ignore
  }
  return false;
}

export async function fetchLocalIdentitiesOnlySetting(): Promise<boolean> {
  const localVal = isLocalIdentitiesOnlyEnabled();
  const user = auth?.currentUser;
  if (!user) return localVal;
  try {
    const remote = await getUserSetting<{ enabled?: unknown }>(
      user.uid,
      LOCAL_IDENTITIES_SETTING_KEY
    );
    if (typeof remote?.enabled === 'boolean') {
      enabledCacheUid = user.uid;
      enabledCache = remote.enabled;
      try {
        localStorage.setItem(LOCAL_IDENTITIES_PREF_LOCAL_KEY, String(remote.enabled));
      } catch {}
      return remote.enabled;
    }
  } catch {
    // ignore
  }
  return localVal;
}

export async function setLocalIdentitiesOnlyEnabled(enabled: boolean): Promise<boolean> {
  ensureCacheUid();
  enabledCache = Boolean(enabled);
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(LOCAL_IDENTITIES_PREF_LOCAL_KEY, String(Boolean(enabled)));
    }
  } catch {}
  if (typeof window !== 'undefined') {
    window.dispatchEvent(
      new CustomEvent(LOCAL_IDENTITIES_CHANGED_EVENT, { detail: { enabled: Boolean(enabled) } })
    );
  }
  const user = auth?.currentUser;
  if (user) {
    await setUserSetting(user.uid, LOCAL_IDENTITIES_SETTING_KEY, { enabled: Boolean(enabled) });
  }
  return Boolean(enabled);
}

// ---------------------------------------------------------------------------
// Notes de terrain : séparation et réconciliation des identités
// ---------------------------------------------------------------------------

const MASKED_IDENTITY_KEYS = new Set(
  DEFAULT_NOTE_TEMPLATE.identity.filter((d) => d.masked).map((d) => d.key)
);
const MASKED_VEHICLE_KEYS = new Set(
  DEFAULT_NOTE_TEMPLATE.vehicle.filter((d) => d.masked).map((d) => d.key)
);

function stripMaskedRecordValues(
  records: NoteRecordEntry[],
  maskedKeys: Set<string>
): NoteRecordEntry[] {
  return (records || []).map((r) => {
    const cleanValues: Record<string, string> = {};
    for (const [k, v] of Object.entries(r.values || {})) {
      // On ne conserve pour le serveur que les champs non nominatifs (ex. rôle, sexe, marque, couleur, dégâts)
      if (!maskedKeys.has(k) && k !== 'lastName' && k !== 'firstName' && k !== 'plate') {
        cleanValues[k] = v;
      }
    }
    return {
      id: r.id,
      alias: r.alias,
      values: cleanValues,
    };
  });
}

/**
 * Enregistre localement les vraies identités de la note dans le coffre de l'appareil,
 * et renvoie une copie de la note purgée de toute identité réelle si le mode est actif.
 */
export async function prepareFieldNoteForCloudSync(note: FieldNote): Promise<FieldNote> {
  const reg = loadRegistry();
  reg.notes[note.id] = {
    location: note.location,
    previousLocations: note.previousLocations,
    identities: (note.identities || []).map((r) => ({
      id: r.id,
      alias: r.alias,
      values: { ...(r.values || {}) },
      ...(r.previous ? { previous: { ...r.previous } } : {}),
    })),
    vehicles: (note.vehicles || []).map((r) => ({
      id: r.id,
      alias: r.alias,
      values: { ...(r.values || {}) },
      ...(r.previous ? { previous: { ...r.previous } } : {}),
    })),
    entities: (note.entities || []).map((e) => ({ ...e })),
  };
  await saveRegistry(reg);

  if (!isLocalIdentitiesOnlyEnabled()) {
    return note;
  }

  return {
    ...note,
    location: '',
    previousLocations: undefined,
    identities: stripMaskedRecordValues(note.identities || [], MASKED_IDENTITY_KEYS),
    vehicles: stripMaskedRecordValues(note.vehicles || [], MASKED_VEHICLE_KEYS),
    entities: (note.entities || []).map((e) => ({
      id: e.id,
      type: e.type,
      alias: e.alias,
      realName: e.alias,
    })),
  };
}

/**
 * Réconcilie une note chargée depuis le serveur avec les vraies identités stockées sur cet appareil.
 */
export function hydrateFieldNoteWithLocalIdentities(note: FieldNote): FieldNote {
  const reg = loadRegistry();
  const snap = reg.notes[note.id];
  if (!snap) return note;

  const mergeRecords = (
    remoteList: NoteRecordEntry[],
    localList: LocalNoteIdentitySnapshot['identities']
  ): NoteRecordEntry[] => {
    if (!Array.isArray(localList) || localList.length === 0) return remoteList;
    const byId = new Map(localList.map((item) => [item.id, item]));
    const byAlias = new Map(localList.map((item) => [item.alias, item]));
    return (remoteList || []).map((rem) => {
      const loc = byId.get(rem.id) || byAlias.get(rem.alias);
      if (!loc) return rem;
      const mergedValues: Record<string, string> = { ...loc.values };
      for (const [k, v] of Object.entries(rem.values || {})) {
        if (v && v.trim()) mergedValues[k] = v;
      }
      return {
        ...rem,
        values: mergedValues,
        ...(rem.previous || loc.previous
          ? { previous: { ...(loc.previous || {}), ...(rem.previous || {}) } }
          : {}),
      };
    });
  };

  const mergeEntities = (
    remoteEntities: InvolvedEntity[] | undefined,
    localEntities: InvolvedEntity[] | undefined
  ): InvolvedEntity[] | undefined => {
    if (!Array.isArray(localEntities) || localEntities.length === 0) return remoteEntities;
    if (!Array.isArray(remoteEntities) || remoteEntities.length === 0) return localEntities;
    const byAlias = new Map(localEntities.map((e) => [e.alias, e]));
    return remoteEntities.map((rem) => {
      const loc = byAlias.get(rem.alias);
      if (loc && (!rem.realName || rem.realName === rem.alias)) {
        return { ...rem, realName: loc.realName, previousNames: loc.previousNames };
      }
      return rem;
    });
  };

  return {
    ...note,
    location: note.location && note.location.trim() ? note.location : snap.location || '',
    ...(note.previousLocations?.length
      ? { previousLocations: note.previousLocations }
      : snap.previousLocations?.length
        ? { previousLocations: snap.previousLocations }
        : {}),
    identities: mergeRecords(note.identities || [], snap.identities),
    vehicles: mergeRecords(note.vehicles || [], snap.vehicles),
    ...(mergeEntities(note.entities, snap.entities)
      ? { entities: mergeEntities(note.entities, snap.entities) }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// Rapports Studio (reformulations) & Dossiers
// ---------------------------------------------------------------------------

export async function prepareReformulationForCloudSync(
  record: ReformulationRecord
): Promise<ReformulationRecord> {
  if (Array.isArray(record.involvedEntities) && record.involvedEntities.length > 0) {
    const reg = loadRegistry();
    reg.reports[record.id] = record.involvedEntities.map((e) => ({ ...e }));
    await saveRegistry(reg);
  }
  if (!isLocalIdentitiesOnlyEnabled()) return record;
  return {
    ...record,
    ...(Array.isArray(record.involvedEntities)
      ? {
          involvedEntities: record.involvedEntities.map((e) => ({
            ...e,
            realName: e.alias,
            previousNames: undefined,
          })),
        }
      : {}),
  };
}

export function hydrateReformulationWithLocalIdentities(
  record: ReformulationRecord
): ReformulationRecord {
  if (!Array.isArray(record.involvedEntities)) return record;
  const reg = loadRegistry();
  const localEntities = reg.reports[record.id];
  if (!Array.isArray(localEntities) || localEntities.length === 0) return record;
  const byAlias = new Map(localEntities.map((e) => [e.alias, e]));
  return {
    ...record,
    involvedEntities: record.involvedEntities.map((rem) => {
      const loc = byAlias.get(rem.alias);
      if (loc && (!rem.realName || rem.realName === rem.alias)) {
        return { ...rem, realName: loc.realName };
      }
      return rem;
    }),
  };
}

export async function prepareDossierForCloudSync(dossier: Dossier): Promise<Dossier> {
  if (Array.isArray(dossier.reports) && dossier.reports.length > 0) {
    const reg = loadRegistry();
    const map: Record<string, InvolvedEntity[]> = reg.dossiers[dossier.id] || {};
    for (const r of dossier.reports) {
      if (Array.isArray(r.involvedEntities) && r.involvedEntities.length > 0) {
        map[r.id] = r.involvedEntities.map((e) => ({ ...e }));
      }
    }
    reg.dossiers[dossier.id] = map;
    await saveRegistry(reg);
  }
  if (!isLocalIdentitiesOnlyEnabled()) return dossier;
  return {
    ...dossier,
    ...(Array.isArray(dossier.reports)
      ? {
          reports: dossier.reports.map((r) => ({
            ...r,
            ...(Array.isArray(r.involvedEntities)
              ? {
                  involvedEntities: r.involvedEntities.map((e) => ({
                    ...e,
                    realName: e.alias,
                    previousNames: undefined,
                  })),
                }
              : {}),
          })),
        }
      : {}),
  };
}

export function hydrateDossierWithLocalIdentities(dossier: Dossier): Dossier {
  if (!Array.isArray(dossier.reports) || dossier.reports.length === 0) return dossier;
  const reg = loadRegistry();
  const map = reg.dossiers[dossier.id];
  if (!map) return dossier;
  return {
    ...dossier,
    reports: dossier.reports.map((r) => {
      const localEntities = map[r.id];
      if (!Array.isArray(localEntities) || !Array.isArray(r.involvedEntities)) return r;
      const byAlias = new Map(localEntities.map((e) => [e.alias, e]));
      return {
        ...r,
        involvedEntities: r.involvedEntities.map((rem) => {
          const loc = byAlias.get(rem.alias);
          if (loc && (!rem.realName || rem.realName === rem.alias)) {
            return { ...rem, realName: loc.realName };
          }
          return rem;
        }),
      };
    }),
  };
}
