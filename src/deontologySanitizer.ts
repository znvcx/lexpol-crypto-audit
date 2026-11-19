/**
 * Deontological Sanitizer & Sensitive Data Helper for Swiss Police & Legal context.
 * Complies with Art. 320 Swiss Criminal Code (Official secrecy) and Swiss FADP (nLPD).
 */

export type SensitiveDataType =
  | 'plate'
  | 'avs'
  | 'email'
  | 'phone'
  | 'civilStatus'
  | 'policeJargonName'
  | 'personName'
  | 'iban'
  | 'vin'
  | 'dob'
  | 'policeRef';

export interface SensitiveDetectionResult {
  hasSensitiveData: boolean;
  detectedTypes: SensitiveDataType[];
  matchesCount: number;
}

// Swiss Cantonal vehicle license plates: e.g. VD 123456, GE-987654, ZH 1234, BE 45678
const SWISS_PLATE_REGEX =
  /\b(AG|AI|AR|BE|BL|BS|FR|GE|GL|GR|JU|LU|NE|NW|OW|SG|SH|SO|SZ|TG|TI|UR|VD|VS|ZG|ZH)\s*[-.]?\s*(\d{1,6})\b/gi;

// Swiss AVS (AHV) number format: 756.xxxx.xxxx.xx or 756xxxxxxxxxx
const SWISS_AVS_REGEX = /\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b/g;

// Swiss & European IBAN format: CHxx xxxx xxxx xxxx xxxx x
const SWISS_IBAN_REGEX = /\b(?:CH|LI|FR|DE|IT|AT)\d{2}\s?(?:[0-9A-Z]{4}\s?){3,4}[0-9A-Z]{1,4}\b/gi;

// Vehicle Identification Number (VIN - 17 alphanumeric chars excluding I, O, Q, containing at least 4 digits)
const VIN_REGEX =
  /\b(?=[A-HJ-NPR-Z0-9]{17}\b)[A-HJ-NPR-Z0-9]*\d[A-HJ-NPR-Z0-9]*\d[A-HJ-NPR-Z0-9]*\d[A-HJ-NPR-Z0-9]*\d[A-HJ-NPR-Z0-9]*\b/g;

// Email addresses
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// Swiss Phone Numbers (+41 or 07x / 02x / 03x / 04x / 09x)
const SWISS_PHONE_REGEX =
  /(?:\+41|0041|0)\s*(?:[1-9]\d{1}|7[5-9])\s*[-.\s]?\d{3}\s*[-.\s]?\d{2}\s*[-.\s]?\d{2}\b/g;

// Formal Swiss Civil Status with potential real names (e.g. Monsieur / Madame / Herr / Frau followed by capitalized names)
const CIVIL_STATUS_REGEX =
  /\b(M\.|Mme|Monsieur|Madame|Herr|Frau|Sig\.|Sig\.ra|Signor|Signora)\s+([A-ZÀ-ÖØ-ß][A-Za-zÀ-ÖØ-öø-ÿ'-]+(?:\s+[A-ZÀ-ÖØ-ß][A-Za-zÀ-ÖØ-öø-ÿ'-]+)?)\b/g;

// Police jargon introducing a real name without M./Mme (e.g. "le nommé Krasniqi Arben", "la prévenue DUPONT Marie", "le plaignant Rossi")
const POLICE_JARGON_NAME_REGEX =
  /\b((?:le|la)\s+(?:nommé|nommée|prévenu|prévenue|plaignant|plaignante|mis\s+en\s+cause|mise\s+en\s+cause|suspect|suspecte|conducteur|conductrice|détenteur|détentrice|propriétaire|victime)|l['’](?:intéressé|intéressée|auteur|auteure|individu))\s+([A-ZÀ-ÖØ-ß][A-Za-zÀ-ÖØ-öø-ÿ'-]{1,30}(?:\s+[A-ZÀ-ÖØ-ß][A-Za-zÀ-ÖØ-öø-ÿ'-]{1,30})?)\b/g;

// Police / Prosecutor journal or procedure references (e.g. Journal n° 2026-12345, Réf. MP-2025/987, Procédure PE24.012345)
const POLICE_REF_REGEX =
  /\b(?:(?:journal|rapport|procédure|dossier)\s*(?:de\s+police\s*)?(?:n[°o]|réf\.?|numéro)\s*[:.]?\s*[A-Z0-9./-]{4,25}|(?:PE|MP|STR|J|POL)[-.]?\d{2,4}[./-]\d{3,8})\b/gi;

// Precise Swiss street address patterns (e.g. Rue de la Gare 12, Bahnhofstrasse 45, Via Roma 3)
const STREET_ADDRESS_REGEX =
  /\b(?:rue|route|avenue|chemin|boulevard|allée|impasse|place|quai|strasse|str\.|weg|gasse|via)\s+[A-ZÀ-ÖØ-ßa-zà-öø-ÿ'’\s-]{2,35}\s+\d{1,4}[a-zA-Z]?\b/gi;

// Complete dates of birth (explicit "né le..." OR standalone Swiss birth date DD.MM.19xx / DD.MM.200x)
const DOB_REGEX =
  /\b(?:(?:né[e]?\s+le|geboren\s+am|nato\/a\s+il|born\s+on)\s+\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|(?:0?[1-9]|[12]\d|3[01])[./](?:0?[1-9]|1[0-2])[./](?:19[2-9]\d|20[01]\d))\b/gi;

/**
 * Offline dictionary of common first names encountered in Switzerland (FR, DE, IT, RM, Balkan, PT, ES, EN)
 * for local zero-network Named Entity Recognition (NER) of standalone "FirstName LastName" / "LASTNAME FirstName" pairs.
 */
const SWISS_COMMON_FIRST_NAMES = new Set<string>([
  // French / Romandie
  'alain',
  'alexandre',
  'alexia',
  'alice',
  'amélie',
  'andré',
  'anna',
  'anne',
  'antoine',
  'arnaud',
  'arthur',
  'aurélie',
  'baptiste',
  'bastiaan',
  'bastien',
  'benjamin',
  'benoît',
  'benoit',
  'bernard',
  'camille',
  'caroline',
  'catherine',
  'cédric',
  'cedric',
  'céline',
  'celine',
  'charles',
  'charlotte',
  'chloé',
  'chloe',
  'christian',
  'christophe',
  'claire',
  'claude',
  'clément',
  'clement',
  'corinne',
  'cyril',
  'damien',
  'daniel',
  'david',
  'denis',
  'didier',
  'dominique',
  'élite',
  'élodie',
  'elodie',
  'émilie',
  'emilie',
  'emma',
  'éric',
  'eric',
  'étienne',
  'etienne',
  'eva',
  'fabien',
  'fabrice',
  'fanny',
  'florian',
  'françois',
  'francois',
  'frédéric',
  'frederic',
  'gabriel',
  'gaël',
  'gael',
  'georges',
  'gérard',
  'gerard',
  'gilles',
  'grégoire',
  'gregoire',
  'guillaume',
  'guy',
  'hélène',
  'helene',
  'henri',
  'hugo',
  'isabelle',
  'jacques',
  'jean',
  'jean-claude',
  'jean-luc',
  'jean-marc',
  'jean-michel',
  'jean-pierre',
  'jérémie',
  'jeremie',
  'jérôme',
  'jerome',
  'joël',
  'joel',
  'jonathan',
  'julie',
  'julien',
  'justine',
  'karine',
  'kevin',
  'kévin',
  'laura',
  'laurence',
  'laurent',
  'léa',
  'lea',
  'léo',
  'leo',
  'lionel',
  'loïc',
  'loic',
  'louis',
  'louise',
  'luc',
  'lucas',
  'lucie',
  'ludovic',
  'manon',
  'marc',
  'marcel',
  'margaux',
  'marie',
  'marine',
  'marion',
  'mathieu',
  'mathilde',
  'matthieu',
  'maxime',
  'mélanie',
  'melanie',
  'michel',
  'michèle',
  'michele',
  'monique',
  'morgane',
  'nadia',
  'nadine',
  'nathalie',
  'nathan',
  'nicolas',
  'nicole',
  'noah',
  'noémie',
  'noemie',
  'olivier',
  'pascal',
  'pascale',
  'patricia',
  'patrick',
  'paul',
  'pauline',
  'philippe',
  'pierre',
  'quentin',
  'raphaël',
  'raphael',
  'raymond',
  'rémi',
  'remi',
  'rené',
  'rene',
  'richard',
  'robert',
  'robin',
  'roger',
  'roland',
  'romain',
  'roxane',
  'sabrina',
  'samuel',
  'sandra',
  'sandrine',
  'sarah',
  'sébastien',
  'sebastien',
  'serge',
  'simon',
  'sophie',
  'stéphane',
  'stephane',
  'stéphanie',
  'stephanie',
  'sylvain',
  'sylvie',
  'théo',
  'theo',
  'thierry',
  'thomas',
  'valérie',
  'valerie',
  'vanessa',
  'véronique',
  'veronique',
  'victor',
  'vincent',
  'virginie',
  'xavier',
  'yann',
  'yannick',
  'yves',
  'zoé',
  'zoe',
  // German / Deutschschweiz
  'adrian',
  'andi',
  'andreas',
  'anita',
  'beat',
  'bernhard',
  'brigitte',
  'bruno',
  'christoph',
  'claudia',
  'cornelia',
  'dani',
  'dieter',
  'doris',
  'erich',
  'ernst',
  'fabian',
  'felix',
  'franz',
  'fritz',
  'gerhard',
  'hans',
  'hanspeter',
  'hansruedi',
  'heinz',
  'helmut',
  'jakob',
  'jan',
  'jürg',
  'juerg',
  'karin',
  'karl',
  'kaspar',
  'katharina',
  'klaus',
  'konrad',
  'kurt',
  'lars',
  'lena',
  'lukas',
  'manuela',
  'marcel',
  'marco',
  'margrit',
  'markus',
  'martin',
  'matthias',
  'max',
  'michael',
  'monika',
  'moritz',
  'niklaus',
  'nina',
  'norbert',
  'oliver',
  'otto',
  'peter',
  'petra',
  'philipp',
  'pius',
  'pirmin',
  'rainer',
  'remo',
  'renato',
  'reto',
  'rolf',
  'roman',
  'ruedi',
  'ruth',
  'sabine',
  'sascha',
  'severin',
  'silvan',
  'silvia',
  'stefan',
  'susanne',
  'sven',
  'tanja',
  'tobias',
  'ueli',
  'ulrich',
  'urs',
  'ursula',
  'verena',
  'walter',
  'werner',
  'wolfgang',
  'yvonne',
  // Italian / Ticino
  'alessandro',
  'alessia',
  'andrea',
  'angelo',
  'antonio',
  'chiara',
  'claudio',
  'davide',
  'diego',
  'elena',
  'emanuele',
  'enrico',
  'fabio',
  'federico',
  'filippo',
  'francesca',
  'francesco',
  'gabriele',
  'giacomo',
  'gianluca',
  'giorgio',
  'giovanni',
  'giulia',
  'giuseppe',
  'leonardo',
  'lorenzo',
  'luca',
  'luigi',
  'massimo',
  'matteo',
  'mattia',
  'maurizio',
  'michele',
  'nicola',
  'paola',
  'paolo',
  'pietro',
  'riccardo',
  'roberto',
  'salvatore',
  'sara',
  'simone',
  'stefano',
  'tommaso',
  'valentina',
  'valerio',
  'vincenzo',
  // Balkan / Portuguese / Spanish / International frequent in CH
  'adem',
  'agim',
  'ahmet',
  'ali',
  'amir',
  'ana',
  'antónio',
  'antonio',
  'arben',
  'ardian',
  'armend',
  'artur',
  'astrit',
  'bekim',
  'besnik',
  'bledar',
  'blerim',
  'burim',
  'carlos',
  'catarina',
  'diogo',
  'dragan',
  'driton',
  'duarte',
  'edon',
  'emir',
  'enis',
  'erion',
  'fatmir',
  'fatima',
  'fernando',
  'filipe',
  'flamur',
  'florim',
  'gazmend',
  'gezim',
  'gëzim',
  'gonçalo',
  'goncalo',
  'goran',
  'hasan',
  'ibrahim',
  'igor',
  'ilir',
  'inês',
  'ines',
  'ismet',
  'ivan',
  'jorge',
  'josé',
  'jose',
  'joão',
  'joao',
  'juan',
  'kushtrim',
  'leart',
  'lirim',
  'luis',
  'luís',
  'manuel',
  'maria',
  'milan',
  'milos',
  'mehmet',
  'merгим',
  'mergim',
  'miguel',
  'miroslav',
  'mohamed',
  'muhamed',
  'mustafa',
  'naim',
  'nenad',
  'nikola',
  'nuno',
  'omar',
  'pedro',
  'petrit',
  'ramiz',
  'ricardo',
  'rui',
  'samir',
  'shkelzen',
  'shpend',
  'slobodan',
  'tiago',
  'valon',
  'visar',
  'vladimir',
  'xhevat',
  'yll',
  'zoran',
]);

/**
 * Words that can appear capitalized in Swiss legal/police text and must never be treated as a person's surname or given name.
 */
const NON_PERSON_CAPITALIZED_WORDS = new Set<string>([
  // Legal & institutional
  'code',
  'loi',
  'art',
  'article',
  'alinéa',
  'alinea',
  'ordonnance',
  'tribunal',
  'conseil',
  'ministère',
  'ministere',
  'police',
  'gendarmerie',
  'parquet',
  'procureur',
  'juge',
  'droit',
  'pénal',
  'penal',
  'civil',
  'fédéral',
  'federal',
  'cantonal',
  'communal',
  'confédération',
  'confederation',
  'suisse',
  'helvétique',
  'circulation',
  'routière',
  'routiere',
  'stupéfiants',
  'stupefiants',
  'armes',
  'étrangers',
  'etrangers',
  'instruction',
  'procédure',
  'procedure',
  // Roles & placeholders
  'conducteur',
  'conductrice',
  'véhicule',
  'vehicule',
  'impliqué',
  'implique',
  'impliquée',
  'piéton',
  'pieton',
  'passager',
  'cycliste',
  'auteur',
  'victime',
  'plaignant',
  'plaignante',
  'prévenu',
  'prevenu',
  'prévenue',
  'suspect',
  'suspecte',
  'témoin',
  'temoin',
  'individu',
  'personne',
  'homme',
  'femme',
  'enfant',
  'client',
  'agent',
  'patrouille',
  'centrale',
  'monsieur',
  'madame',
  'herr',
  'frau',
  'signor',
  'signora',
  'nommé',
  'nommée',
  // Geography, streets & Swiss cities/cantons
  'rue',
  'route',
  'avenue',
  'chemin',
  'place',
  'quai',
  'boulevard',
  'allée',
  'impasse',
  'pont',
  'gare',
  'aéroport',
  'aeroport',
  'poste',
  'hôpital',
  'hopital',
  'école',
  'ecole',
  'parking',
  'autoroute',
  'tunnel',
  'canton',
  'ville',
  'commune',
  'district',
  'lac',
  'mont',
  'saint',
  'sainte',
  'lausanne',
  'genève',
  'geneve',
  'zurich',
  'zürich',
  'berne',
  'bern',
  'bâle',
  'basel',
  'lucerne',
  'luzern',
  'lugano',
  'fribourg',
  'neuchâtel',
  'neuchatel',
  'sion',
  'sierre',
  'martigny',
  'montreux',
  'vevey',
  'nyon',
  'morges',
  'yverdon',
  'renens',
  'bienne',
  'biel',
  'thoune',
  'thun',
  'winterthour',
  'winterthur',
  'aarau',
  'soleure',
  'schaffhouse',
  'coire',
  'chur',
  'bellinzone',
  'bellinzona',
  'locarno',
  'mendrisio',
  'delémont',
  'delemont',
  'porrentruy',
  'bulle',
  'vaud',
  'valais',
  'tessin',
  'ticino',
  'grisons',
  'jura',
  'argovie',
  'thurgovie',
  'zoug',
  'zug',
  'uri',
  'schwyz',
  'glaris',
  // Common French/German/Italian grammar words & months/days
  'le',
  'la',
  'les',
  'un',
  'une',
  'des',
  'du',
  'de',
  'ce',
  'cet',
  'cette',
  'ces',
  'mon',
  'ton',
  'son',
  'notre',
  'votre',
  'leur',
  'il',
  'elle',
  'ils',
  'elles',
  'on',
  'nous',
  'vous',
  'je',
  'tu',
  'dans',
  'sur',
  'sous',
  'avec',
  'sans',
  'pour',
  'par',
  'vers',
  'chez',
  'entre',
  'après',
  'apres',
  'avant',
  'pendant',
  'lors',
  'depuis',
  'selon',
  'malgré',
  'suite',
  'alors',
  'mais',
  'donc',
  'car',
  'lundi',
  'mardi',
  'mercredi',
  'jeudi',
  'vendredi',
  'samedi',
  'dimanche',
  'janvier',
  'février',
  'mars',
  'avril',
  'mai',
  'juin',
  'juillet',
  'août',
  'septembre',
  'octobre',
  'novembre',
  'décembre',
]);

// Matches two consecutive capitalized words (FirstName LastName or LASTNAME FirstName)
const CAPITALIZED_PAIR_REGEX =
  /\b([A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'-]{1,28})\s+([A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'-]{1,28})\b/g;

function isStandalonePersonNamePair(word1: string, word2: string): boolean {
  const w1 = word1.toLowerCase();
  const w2 = word2.toLowerCase();
  if (NON_PERSON_CAPITALIZED_WORDS.has(w1) || NON_PERSON_CAPITALIZED_WORDS.has(w2)) {
    return false;
  }
  return SWISS_COMMON_FIRST_NAMES.has(w1) || SWISS_COMMON_FIRST_NAMES.has(w2);
}

function findStandalonePersonNames(text: string): string[] {
  // Strip already matched civil status, police jargon prefixes & street addresses so we don't double-count
  const stripped = text
    .replace(STREET_ADDRESS_REGEX, ' ')
    .replace(CIVIL_STATUS_REGEX, ' ')
    .replace(POLICE_JARGON_NAME_REGEX, ' ');
  const found: string[] = [];
  let match: RegExpExecArray | null;
  const regex = new RegExp(CAPITALIZED_PAIR_REGEX.source, 'g');
  while ((match = regex.exec(stripped)) !== null) {
    if (isStandalonePersonNamePair(match[1], match[2])) {
      found.push(match[0]);
    }
  }
  return found;
}

/**
 * Checks whether text contains potential Swiss identifying or sensitive details.
 */
export function detectSensitiveData(text: string): SensitiveDetectionResult {
  if (!text || text.trim().length < 4) {
    return { hasSensitiveData: false, detectedTypes: [], matchesCount: 0 };
  }

  const detectedTypes: SensitiveDataType[] = [];
  let count = 0;

  const check = (regex: RegExp, type: SensitiveDataType) => {
    const matches = text.match(regex);
    if (matches && matches.length > 0) {
      detectedTypes.push(type);
      count += matches.length;
    }
  };

  check(SWISS_PLATE_REGEX, 'plate');
  check(SWISS_AVS_REGEX, 'avs');
  check(SWISS_IBAN_REGEX, 'iban');
  check(VIN_REGEX, 'vin');
  check(EMAIL_REGEX, 'email');
  check(SWISS_PHONE_REGEX, 'phone');
  check(CIVIL_STATUS_REGEX, 'civilStatus');
  check(POLICE_JARGON_NAME_REGEX, 'policeJargonName');
  const standaloneNames = findStandalonePersonNames(text);
  if (standaloneNames.length > 0) {
    detectedTypes.push('personName');
    count += standaloneNames.length;
  }
  check(DOB_REGEX, 'dob');
  check(POLICE_REF_REGEX, 'policeRef');

  return {
    hasSensitiveData: detectedTypes.length > 0,
    detectedTypes,
    matchesCount: count,
  };
}

/**
 * Anonymizes the situation text by replacing identifying Swiss markers
 * with neutral and legally sound placeholders (e.g. [Véhicule X], [Conducteur A]).
 */
export function anonymizeSituation(text: string): string {
  if (!text) return '';

  let sanitized = text;

  // 1. Replace license plates
  let plateIndex = 1;
  sanitized = sanitized.replace(SWISS_PLATE_REGEX, () => {
    const replacement =
      plateIndex === 1
        ? '[Véhicule A]'
        : `[Véhicule ${String.fromCharCode(64 + Math.min(26, plateIndex))}]`;
    plateIndex++;
    return replacement;
  });

  // 2. Replace AVS numbers
  sanitized = sanitized.replace(SWISS_AVS_REGEX, '[N° AVS anonymisé]');

  // 2b. Replace IBAN numbers
  sanitized = sanitized.replace(SWISS_IBAN_REGEX, '[IBAN anonymisé]');

  // 2c. Replace VIN numbers
  sanitized = sanitized.replace(VIN_REGEX, '[N° de châssis VIN masqué]');

  // 2d. Replace Police/Prosecutor procedure references
  sanitized = sanitized.replace(POLICE_REF_REGEX, '[Réf. dossier masquée]');

  // 3. Replace emails
  sanitized = sanitized.replace(EMAIL_REGEX, '[courriel anonymisé]');

  // 4. Replace phone numbers
  sanitized = sanitized.replace(SWISS_PHONE_REGEX, '[téléphone masqué]');

  // 5. Replace civil status and names
  let personIndex = 1;
  sanitized = sanitized.replace(CIVIL_STATUS_REGEX, (_match, prefix) => {
    const label =
      personIndex === 1
        ? 'Conducteur A / Impliqué A'
        : `Impliqué ${String.fromCharCode(64 + Math.min(26, personIndex))}`;
    personIndex++;
    return `${prefix} [${label}]`;
  });

  // 5b. Replace police jargon followed by real names ("le nommé X", "le prévenu Y")
  sanitized = sanitized.replace(POLICE_JARGON_NAME_REGEX, (_match, rolePrefix) => {
    const label = `Impliqué ${String.fromCharCode(64 + Math.min(26, personIndex))}`;
    personIndex++;
    return `${rolePrefix} [${label}]`;
  });

  // 6. Replace precise dates of birth
  sanitized = sanitized.replace(DOB_REGEX, '[Date de naissance masquée]');

  // 7. Replace precise street addresses with numbers
  sanitized = sanitized.replace(STREET_ADDRESS_REGEX, '[Adresse masquée]');

  // 8. Replace standalone FirstName LastName / LASTNAME FirstName pairs via offline NER dictionary
  sanitized = sanitized.replace(CAPITALIZED_PAIR_REGEX, (fullMatch, word1, word2) => {
    if (!isStandalonePersonNamePair(word1, word2)) {
      return fullMatch;
    }
    const label = `Impliqué ${String.fromCharCode(64 + Math.min(26, personIndex))}`;
    personIndex++;
    return `[${label}]`;
  });

  return sanitized;
}
