/**
 * Alias des données sensibles (Studio et onglet « Données sensibles » du dossier) : même préfixe anglais
 * par catégorie et même numérotation partout, pour que l'IA lise l'alias comme un indice de sa nature.
 */
import { InvolvedEntity, InvolvedEntityType } from '../types';

/** Préfixe anglais de l'alias selon la catégorie. */
export const ALIAS_PREFIX: Record<InvolvedEntityType, string> = {
  person: 'PERSON',
  company: 'COMPANY',
  vehicle: 'VEHICLE',
  place: 'PLACE',
  date: 'DATE',
  other: 'ENTITY',
};

/** Tous les préfixes générés un jour, y compris les anciens en français. */
const GENERATED_PREFIXES =
  'ENTITY|PERSON|COMPANY|VEHICLE|PLACE|DATE|OTHER|PERSONNE|VEHICULE|INDIVIDU|SOCIETE|LIEU';
const GENERATED_ALIAS_REGEX = new RegExp(`^\\[\\s*(${GENERATED_PREFIXES})_(\\d+)\\s*\\]$`, 'i');

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Alias suivant pour la catégorie : [PERSON_01], [PLACE_02]… numérotés par préfixe. */
export function nextEntityAlias(
  type: InvolvedEntityType,
  entities: Pick<InvolvedEntity, 'id' | 'alias'>[],
  ignoreId?: string
): string {
  const prefix = ALIAS_PREFIX[type] ?? 'ENTITY';
  let max = 0;
  for (const ent of entities) {
    if (ent.id === ignoreId) continue;
    const match = (ent.alias || '').match(GENERATED_ALIAS_REGEX);
    if (match && match[1].toUpperCase() === prefix) max = Math.max(max, Number(match[2]) || 0);
  }
  return `[${prefix}_${String(max + 1).padStart(2, '0')}]`;
}

/** Vrai pour un alias produit automatiquement (et non saisi à la main). */
export function isGeneratedAlias(alias: string): boolean {
  return GENERATED_ALIAS_REGEX.test((alias || '').trim());
}

/** Vrai si l'alias porte déjà le préfixe de la catégorie. */
export function aliasMatchesType(alias: string, type: InvolvedEntityType): boolean {
  const match = (alias || '').trim().match(GENERATED_ALIAS_REGEX);
  return Boolean(match && match[1].toUpperCase() === ALIAS_PREFIX[type]);
}

/**
 * Alias après un changement de catégorie : un alias automatique prend le préfixe de la nouvelle
 * catégorie ([PERSON_01] devient [PLACE_01]) ; un alias saisi à la main est conservé.
 */
export function retypedEntityAlias(
  alias: string,
  type: InvolvedEntityType,
  entities: Pick<InvolvedEntity, 'id' | 'alias'>[],
  entityId?: string
): string {
  const current = (alias || '').trim();
  if (current && (!isGeneratedAlias(current) || aliasMatchesType(current, type))) return current;
  return nextEntityAlias(type, entities, entityId);
}

/** Remplace dans un texte l'ancien alias, avec ses sous-parties ([PERSON_01_NAME]…), par le nouveau. */
export function renameAliasInText(text: string, oldAlias: string, newAlias: string): string {
  const oldBase = (oldAlias || '').replace(/^\[|\]$/g, '').trim();
  const newBase = (newAlias || '').replace(/^\[|\]$/g, '').trim();
  if (!text || !oldBase || !newBase || oldBase === newBase) return text;
  const re = new RegExp(`\\[\\s*${escapeRegex(oldBase)}(_[A-Za-z0-9_]+)?\\s*\\]`, 'gi');
  return text.replace(re, (_m, suffix?: string) => `[${newBase}${suffix ?? ''}]`);
}
