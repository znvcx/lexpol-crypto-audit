# LexPol.ch — Brique Cryptographique Zero-Knowledge & Moteur d'Anonymisation Local (`lexpol-crypto-audit`)

Ce dépôt public contient le code source complet et auditable de la **couche cryptographique côté client (Zero-Knowledge E2EE v2)** et du **moteur de désidentification local** utilisés en production par **[LexPol.ch](https://lexpol.ch)**.

Il est publié en open source afin de permettre aux corps de police, aux préposés à la protection des données (PFPDT / préposés cantonaux), aux auditeurs en sécurité informatique et aux praticiens du droit suisse de **vérifier mathématiquement et techniquement** comment LexPol garantit le respect du **secret de fonction (art. 320 CP)** et de la **nouvelle Loi fédérale sur la protection des données (nLPD)**.

---

## 1. Architecture de sécurité & Modèle de menace (Zero-Knowledge)

LexPol applique un modèle **Zero-Knowledge (connaissance nulle)** côté serveur : l'infrastructure d'hébergement (exclusivement située en Suisse chez Infomaniak Network SA, Genève/Winterthour, certifiée ISO 27001 / Tier III+, couverte par un contrat de sous-traitance DPA conforme nLPD) est considérée comme un simple stockage de blocs chiffrés opaques.

### Périmètre auditable dans ce dépôt :

| Fichier source | Rôle et garanties techniques |
| :--- | :--- |
| [`src/studioE2ee.ts`](./src/studioE2ee.ts) | **Chiffrement de bout en bout (E2EE v2)** de tous les enregistrements synchronisés (`analyses`, `field_notes`, `dossiers`, `reformulations`, `landmarks`) avec **AES-256-GCM** (WebCrypto natif, IV aléatoire 96 bits par champ via `crypto.getRandomValues`, tag d'authentification 128 bits, préfixe `ENCv2:<keyId>:<iv_b64>:<ct_b64>`). |
| [`src/studioCrypto.ts`](./src/studioCrypto.ts) | **Dérivation de clés & Coffre-fort local (`LVv2:`)** : dérivation **PBKDF2-HMAC-SHA256 à 600 000 itérations** (recommandation OWASP 2024+), clé de secours **BIP-39 (24 mots / 256 bits d'entropie)** dérivée via **HKDF-SHA256**, et chiffrement automatique du `localStorage` (`LVv2:`) par une clé AES-GCM non-extractible stockée dans `IndexedDB`. |
| [`src/webauthnVault.ts`](./src/webauthnVault.ts) | **Déverrouillage biométrique matériel (WebAuthn / TouchID / FaceID / Windows Hello)** : protection de la clé de données (DEK) par l'authentificateur matériel de l'appareil (Secure Enclave / TPM) avec vérification biométrique obligatoire (`userVerification: 'required'`) et extension WebAuthn `prf` (HKDF-SHA256). |
| [`src/localIdentities.ts`](./src/localIdentities.ts) | **Mode « Identités locales uniquement »** : séparation stricte entre le récit métier (chiffré E2EE avec alias `[PERSON_01]`, `[VEHICLE_01]`, `[PLACE]`) et le tableau de correspondance nominatif (noms, prénoms, dates de naissance, plaques, téléphones, adresses), qui est **intégralement purgé avant tout envoi réseau** et conservé exclusivement dans le stockage local chiffré `LVv2:` de l'appareil. |
| [`src/deontologySanitizer.ts`](./src/deontologySanitizer.ts) | **Pare-feu déontologique & Détection hors-ligne (NER local)** : détection et masquage instantanés, 100 % dans le navigateur (sans appel réseau), des plaques cantonales suisses, numéros AVS (`756.xxxx.xxxx.xx`), IBAN, numéros de châssis VIN, dates de naissance, références de journaux/procédures de police (`PE...`, `MP...`), états civils, jargon policier (*« le nommé X »*, *« le prévenu Y »*) et couples Prénom/Nom autonomes via un dictionnaire hors-ligne des prénoms courants en Suisse. |
| [`src/entityAliases.ts`](./src/entityAliases.ts) | **Moteur de pseudonymisation par alias déterministes** (`[PERSON_01_NAME]`, `[VEHICLE_01_PLATE]`, `[COMPANY_01_NAME]`) permettant à l'IA juridique suisse de raisonner sur les rôles procéduraux sans jamais recevoir la moindre identité réelle (`realName` est exclu des requêtes API). |
| [`src/vaultDeviceStore.ts`](./src/vaultDeviceStore.ts) | Stockage isolé dans `IndexedDB` des clés WebCrypto non-extractibles (`extractable: false`) et purge cryptographique immédiate lors de la déconnexion ou du bouton **« Fin de service »**. |
| [`tests/zeroKnowledgeSecurity.test.ts`](./tests/zeroKnowledgeSecurity.test.ts) | Suite de tests unitaires vérifiant l'absence totale de texte en clair dans les charges utiles E2EE, la purge des identités en mode local et l'efficacité du nettoyeur déontologique. |

---

## 2. Comment vérifier vous-même en 2 minutes que LexPol applique ce code en production

En sécurité informatique, un rapport ou une déclaration ne suffit pas : **la preuve doit être vérifiable par l'utilisateur lui-même**. Comme tout le chiffrement et l'anonymisation s'exécutent dans votre navigateur *avant* que la moindre donnée ne quitte votre appareil, n'importe quel utilisateur ou auditeur peut contrôler le comportement réel de [LexPol.ch](https://lexpol.ch) à l'aide des outils de développement standard du navigateur (**Touche `F12`** sur Chrome, Edge, Firefox ou Safari) :

### Vérification n° 1 — Preuve du chiffrement de bout en bout (E2EE `ENCv2:`) sur le réseau
1. Ouvrez [https://lexpol.ch](https://lexpol.ch), connectez-vous et ouvrez l'inspecteur réseau (**`F12` > onglet `Network` / `Réseau`**).
2. Filtrez les requêtes sur `/pb/api/collections/`.
3. Créez ou enregistrez une analyse juridique, une main courante, un dossier, un rapport ou un repère cartographique.
4. Inspectez l'onglet **Payload / Requête** de l'appel `POST` ou `PATCH` envoyé au serveur :
   - Vous constaterez que tous les champs métier contiennent **exclusivement des chaînes chiffrées commençant par `ENCv2:`** (ex. `"ENCv2:a1b2c3d4:9f8e...:7a6b..."`).
   - **Aucun mot en clair** de votre texte, de vos notes ou de vos coordonnées GPS ne figure dans la requête réseau.

### Vérification n° 2 — Preuve de l'absence d'identités envoyées à l'IA (`/api/legal/`)
1. Dans l'onglet **`F12` > `Network`**, filtrez sur `/api/legal/`.
2. Dans le Studio (Main courante / Rapports), ajoutez une personne avec un nom fictif (ex. `DUPONT Jean`) et lancez une reformulation IA.
3. Inspectez le corps JSON (`Payload`) envoyé à `/api/legal/reformulate` :
   - Le texte transmis contient uniquement le jeton `[PERSON_01_NAME]`.
   - Le tableau `involvedEntities` envoyé au serveur ne contient que `{ id, type, alias }` : **la propriété `realName` est absente de la requête réseau**.

### Vérification n° 3 — Preuve du mode « Identités locales uniquement »
1. Activez l'option **« Identités locales uniquement »** dans **Profil > Préférences** (ou directement dans le Studio).
2. Saisissez des identités ou véhicules dans une main courante et observez la requête réseau `/pb/api/collections/field_notes/records` dans **`F12` > `Network`** :
   - Avant même le chiffrement E2EE, les valeurs nominatives (`lastName`, `firstName`, `birthDate`, `plate`, `phone`, `address`) sont purgées de la charge utile destinée au cloud et restent exclusivement dans le stockage local chiffré de votre appareil.

### Vérification n° 4 — Preuve du chiffrement du stockage local (`LVv2:`) et du bouton « Fin de service »
1. Ouvrez **`F12` > onglet `Application` (ou `Stockage`) > `Local Storage` > `https://lexpol.ch`**.
2. Inspectez les clés `lexpol_history_v1`, `lexpol_studio_field_notes_v1`, `lexpol_studio_dossiers_v1` ou `lexpol_local_identities_map_v1` :
   - Toutes les valeurs commencent par le préfixe **`LVv2:`** suivi d'un bloc AES-256-GCM chiffré. Aucune donnée métier n'est lisible en clair sur le disque.
3. Cliquez sur le bouton **« Fin de service »** (icône bouclier dans l'en-tête) :
   - La clé DEK en mémoire vive est immédiatement détruite, le presse-papiers est vidé et le coffre-fort passe instantanément à l'état verrouillé.

---

## 3. Correspondance des fichiers avec l'application principale

Les fichiers de ce dépôt correspondent ligne pour ligne aux modules suivants du code source de LexPol.ch :

- `src/studioE2ee.ts` ➔ `src/utils/studioE2ee.ts`
- `src/studioCrypto.ts` ➔ `src/utils/studioCrypto.ts`
- `src/webauthnVault.ts` ➔ `src/utils/webauthnVault.ts`
- `src/vaultDeviceStore.ts` ➔ `src/utils/vaultDeviceStore.ts`
- `src/deontologySanitizer.ts` ➔ `src/utils/deontologySanitizer.ts`
- `src/localIdentities.ts` ➔ `src/services/localIdentities.ts`
- `src/entityAliases.ts` ➔ `src/utils/entityAliases.ts`
- `src/bip39English.ts` ➔ `src/utils/bip39English.ts`
- `tests/zeroKnowledgeSecurity.test.ts` ➔ `src/services/zeroKnowledgeSecurity.test.ts`

---

## 4. Licence & Contact Sécurité

Ce module d'audit cryptographique est publié sous licence **MIT** (voir [`LICENSE`](./LICENSE)).
Pour toute question relative à la sécurité, à la protection des données (nLPD) ou à un audit institutionnel : **contact@lexpol.ch**.
