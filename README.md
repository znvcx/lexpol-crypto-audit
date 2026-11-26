# LexPol.ch — Brique Cryptographique Zero-Knowledge & Moteur d'Anonymisation Local (`lexpol-crypto-audit`)

Ce dépôt public contient le code source auditable de la **couche cryptographique côté client** (authentification zero-knowledge, chiffrement de bout en bout `ENCv3`) et du **moteur de désidentification local** utilisés en production par **[LexPol.ch](https://lexpol.ch)**.

Il est publié en open source afin de permettre aux corps de police, aux préposés à la protection des données (PFPDT / préposés cantonaux), aux auditeurs en sécurité informatique et aux praticiens du droit suisse de **vérifier techniquement** comment LexPol protège le **secret de fonction (art. 320 CP)** et respecte la **loi fédérale sur la protection des données (nLPD)**.

---

## 1. Modèle de menace : zero-knowledge

LexPol applique un modèle **zero-knowledge** : le serveur (hébergé exclusivement en Suisse chez Infomaniak Network SA, certifié ISO 27001, contrat de sous-traitance DPA conforme nLPD) ne reçoit **ni le mot de passe, ni les clés, ni les contenus en clair**. Il stocke des blocs chiffrés qu'il ne peut pas ouvrir.

| Ce qui reste sur l'appareil | Ce que reçoit le serveur |
| :--- | :--- |
| Le mot de passe | Un secret d'authentification dérivé (`lpa1.…`), qui n'ouvre pas le coffre |
| La clé maîtresse (DEK, AES-256) | La DEK enveloppée par le mot de passe et par la phrase de récupération |
| Les notes, analyses, rapports et repères en clair | Des blocs `ENCv3:` chiffrés en AES-256-GCM |

**Authentification sans transmission du mot de passe** (même principe que Bitwarden). Le navigateur demande le sel du compte (`POST /api/auth/prelogin`), puis dérive du mot de passe un secret `lpa1.<32 octets>` par **PBKDF2-SHA256, 600 000 itérations** (nombre fixé dans le code, jamais fourni par le serveur), sel de 16 octets propre au compte, précédé d'un préfixe de domaine. PocketBase ne reçoit et ne vérifie que ce secret, à l'inscription, à la connexion, au changement et à la réinitialisation du mot de passe. L'enveloppe de la clé maîtresse est dérivée du même mot de passe **avec un autre sel** : connaître le secret d'authentification ne permet pas de l'ouvrir ; il faudrait retrouver le mot de passe par force brute, à 600 000 itérations par essai. Une adresse inconnue reçoit un sel fictif stable, qui ne révèle pas l'existence d'un compte.

**Limites assumées.**
- Pour l'analyse juridique et la rédaction, l'IA doit lire un texte : le navigateur remplace d'abord les noms, plaques, lieux et dates par des alias (`deontologySanitizer.ts`, `entityAliases.ts`), puis le texte masqué est traité en Suisse, gardé au plus 15 minutes en mémoire vive et jamais écrit sur disque. Le résultat revient dans la note, chiffré sur l'appareil.
- Quelques métadonnées restent lisibles par la base pour le tri, la rétention et les liens entre éléments (identifiants, références, dates, langue, lien entre une note et son analyse). L'identifiant de l'enregistrement et sa date d'échéance sont **liés cryptographiquement** au contenu (données associées AES-GCM) : les modifier rend le contenu indéchiffrable.
- Perte conjointe du mot de passe et de la phrase de récupération de 24 mots : personne, pas même LexPol, ne peut récupérer les données.

### Périmètre auditable dans ce dépôt

| Fichier source | Rôle et garanties techniques |
| :--- | :--- |
| [`src/authKdf.ts`](./src/authKdf.ts) | **Secret d'authentification zero-knowledge** : dérivation PBKDF2-SHA256 (600 000 itérations) du secret `lpa1.` envoyé à la place du mot de passe, séparation de domaine avec la clé du coffre, validation du sel. Module partagé par le navigateur et le serveur (WebCrypto). |
| [`server/authKdf.ts`](./server/authKdf.ts) | **Pré-connexion côté serveur** : sel du compte, et sel fictif déterministe (HMAC-SHA256) pour une adresse inconnue, afin de ne pas révéler l'existence des comptes. |
| [`src/studioE2ee.ts`](./src/studioE2ee.ts) | **Chiffrement de bout en bout `ENCv3`** de tous les enregistrements synchronisés (`analyses`, `field_notes`, `dossiers`, `reformulations`, `landmarks`) en **AES-256-GCM** (WebCrypto, IV aléatoire de 96 bits par valeur, tag de 128 bits, format `ENCv3:<keyId>:<base64(IV, texte chiffré, tag)>`). Les données associées lient chaque texte chiffré au compte, à la clé, à la collection, à l'identifiant de l'enregistrement et à son échéance : un bloc copié dans un autre enregistrement ne se déchiffre plus. Clé maîtresse (DEK) aléatoire, enveloppée par le mot de passe (**PBKDF2-SHA256, 600 000 itérations**) et par la phrase de récupération **BIP-39 de 24 mots** (**HKDF-SHA256**). L'ancien format `ENCv2` reste lisible puis est réécrit en `ENCv3`. |
| [`src/studioVault.ts`](./src/studioVault.ts) | **Orchestration du coffre** : création, déverrouillage, rotation de la phrase de récupération, rechiffrement par lots. Le mode strict (refus du texte en clair) et la date du dernier document de clés vu sont mémorisés sur l'appareil : un serveur ne peut ni désactiver ce mode ni rejouer un ancien document. |
| [`src/studioCrypto.ts`](./src/studioCrypto.ts) | **Coffre local (`LVv2:`)** : chiffrement automatique du `localStorage` par une clé AES-GCM non extractible conservée dans `IndexedDB`, créée de façon atomique (un second onglet ne peut pas l'écraser) ; données associées liées au compte et à la clé de stockage. |
| [`src/webauthnVault.ts`](./src/webauthnVault.ts) | **Déverrouillage biométrique (WebAuthn / TouchID / FaceID / Windows Hello)** : protection de la DEK par l'authentificateur matériel de l'appareil, vérification de l'utilisateur obligatoire (`userVerification: 'required'`), extension `prf` (HKDF-SHA256). |
| [`src/localIdentities.ts`](./src/localIdentities.ts) | **Mode « Identités locales uniquement »** : séparation entre le récit (chiffré, avec alias `[PERSON_01]`, `[VEHICLE_01]`, `[PLACE]`) et la table de correspondance nominative, **purgée avant tout envoi réseau** et conservée uniquement dans le stockage local chiffré `LVv2:`. |
| [`src/deontologySanitizer.ts`](./src/deontologySanitizer.ts) | **Pare-feu déontologique hors ligne** : détection et masquage dans le navigateur, sans appel réseau, des plaques suisses, numéros AVS (`756.xxxx.xxxx.xx`), IBAN, numéros de châssis, dates de naissance, références de procédure, tournures policières et couples prénom/nom courants en Suisse. |
| [`src/entityAliases.ts`](./src/entityAliases.ts) | **Pseudonymisation par alias déterministes** (`[PERSON_01_NAME]`, `[VEHICLE_01_PLATE]`…) : l'IA raisonne sur les rôles procéduraux sans recevoir d'identité réelle (`realName` est exclu des requêtes). |
| [`src/vaultDeviceStore.ts`](./src/vaultDeviceStore.ts) | Stockage dans `IndexedDB` des clés WebCrypto non extractibles (`extractable: false`), écriture atomique, purge à la déconnexion et au bouton **« Fin de service »**. |
| [`tests/authKdf.test.ts`](./tests/authKdf.test.ts) | Vecteur de référence indépendant (crypto de Node) pour la dérivation, séparation d'avec la clé du coffre, sel fictif stable, refus d'un mot de passe brut à l'inscription. |
| [`tests/studioE2ee.test.ts`](./tests/studioE2ee.test.ts) | Chiffrement des enregistrements, liaison `ENCv3` (permutation entre enregistrements et échéance modifiée refusées), enveloppes, rotation, paramètres de dérivation. |
| [`tests/zeroKnowledgeSecurity.test.ts`](./tests/zeroKnowledgeSecurity.test.ts) | Absence de texte en clair dans les charges utiles chiffrées, purge des identités en mode local, efficacité du pare-feu déontologique. |

---

## 2. Vérifier vous-même que LexPol applique ce code en production

Tout le chiffrement et l'anonymisation s'exécutent dans votre navigateur *avant* l'envoi. N'importe quel utilisateur ou auditeur peut donc contrôler le comportement réel de [LexPol.ch](https://lexpol.ch) avec les outils de développement du navigateur (**touche `F12`** sur Chrome, Edge, Firefox ou Safari).

### Vérification n° 1 — Le mot de passe ne quitte pas l'appareil
1. Ouvrez **`F12` > onglet `Network` / `Réseau`**, puis connectez-vous.
2. Observez la requête `POST /api/auth/prelogin` : elle ne contient que l'adresse e-mail et renvoie le sel du compte.
3. Observez la requête `POST /pb/api/collections/users/auth-with-password` : le champ `password` contient une valeur `lpa1.…` dérivée, **jamais le mot de passe saisi**. Cherchez votre mot de passe dans toutes les requêtes (filtre ou recherche `Ctrl+F` de l'onglet Réseau) : il n'apparaît nulle part.

### Vérification n° 2 — Chiffrement de bout en bout (`ENCv3:`) sur le réseau
1. Dans **`F12` > `Network`**, filtrez sur `/pb/api/collections/`.
2. Enregistrez une note, une analyse ou un repère cartographique.
3. Inspectez la charge utile de l'appel `POST` ou `PATCH` : les contenus sont des chaînes **`ENCv3:`** suivies de blocs base64 aléatoires ; aucun mot de votre texte ni coordonnée GPS n'y figure en clair.

### Vérification n° 3 — Aucune identité envoyée à l'IA (`/api/legal/`)
1. Dans **`F12` > `Network`**, filtrez sur `/api/legal/`.
2. Ajoutez une personne fictive (ex. `DUPONT Jean`) à une note, puis lancez la mise en forme ou l'analyse.
3. Inspectez le corps JSON envoyé : le texte ne contient que des alias comme `[PERSON_01_NAME]`, et les entités ne portent que `{ id, type, alias }` : **la propriété `realName` est absente**.

### Vérification n° 4 — Mode « Identités locales uniquement »
1. Activez l'option **« Identités locales uniquement »** dans le profil.
2. Saisissez des identités ou véhicules dans une note et observez la requête `/pb/api/collections/field_notes/records` : les valeurs nominatives sont retirées de la charge utile avant même le chiffrement et restent dans le stockage local chiffré de l'appareil.

### Vérification n° 5 — Stockage local chiffré (`LVv2:`) et bouton « Fin de service »
1. Ouvrez **`F12` > onglet `Application` (ou `Stockage`) > `Local Storage` > `https://lexpol.ch`**.
2. Inspectez les clés `lexpol_field_notes_v1`, `lexpol_dossiers_v24m`, `lexpol_history_v1` ou `lexpol_local_identities_v1` : les valeurs commencent par **`LVv2:`** suivi d'un bloc AES-256-GCM.
3. Cliquez sur le bouton **« Fin de service »** (cadenas dans l'en-tête) : la clé en mémoire est oubliée, le presse-papiers est vidé et le coffre se verrouille.

---

## 3. Correspondance avec le code de l'application

Les fichiers de ce dépôt sont des copies à l'identique des modules suivants du code source de LexPol.ch :

- `src/authKdf.ts` ➔ `src/utils/authKdf.ts`
- `server/authKdf.ts` ➔ `server/services/authKdf.ts`
- `src/studioE2ee.ts` ➔ `src/utils/studioE2ee.ts`
- `src/studioVault.ts` ➔ `src/services/studioVault.ts`
- `src/studioCrypto.ts` ➔ `src/utils/studioCrypto.ts`
- `src/webauthnVault.ts` ➔ `src/utils/webauthnVault.ts`
- `src/vaultDeviceStore.ts` ➔ `src/utils/vaultDeviceStore.ts`
- `src/deontologySanitizer.ts` ➔ `src/utils/deontologySanitizer.ts`
- `src/localIdentities.ts` ➔ `src/services/localIdentities.ts`
- `src/entityAliases.ts` ➔ `src/utils/entityAliases.ts`
- `src/bip39English.ts` ➔ `src/utils/bip39English.ts`
- `tests/authKdf.test.ts` ➔ `server/utils/authKdf.test.ts`
- `tests/studioE2ee.test.ts` ➔ `src/utils/studioE2ee.test.ts`
- `tests/zeroKnowledgeSecurity.test.ts` ➔ `src/services/zeroKnowledgeSecurity.test.ts`

Les chemins d'import sont ceux de l'application : ce dépôt sert à la lecture et à l'audit, il ne se compile pas seul.

---

## 4. Licence & contact sécurité

Ce module d'audit cryptographique est publié sous licence **MIT** (voir [`LICENSE`](./LICENSE)).
Pour toute question relative à la sécurité, à la protection des données (nLPD) ou à un audit institutionnel : **contact@lexpol.ch**.
