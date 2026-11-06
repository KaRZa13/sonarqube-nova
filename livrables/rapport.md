# TP — Analyse statique de TIWAP avec SonarQube (NOVA SERVICES)

Module : Pilotage & amélioration continue de la sécurité
Date : 6 novembre 2026
Outils : SonarQube Community Build 26.10.0.133078, PostgreSQL 15, SonarScanner CLI 8.3.1, Python 3.14

---

## Contenu du dossier

| Fichier | Livrable |
|---|---|
| `../compose.yaml` | Fichier Compose (sans secret, mot de passe lu depuis `.env`, non versionné) |
| `sonar-project.properties` | Configuration de l'analyse (copie de `TIWAP/sonar-project.properties`) |
| `capture_projet_tiwap.png` | Capture de l'interface SonarQube montrant le projet analysé *(à ajouter)* |
| `sonarqube_resultats.csv` | Export complet des 51 anomalies relevées par SonarQube |
| `correction.diff` | Diff de la correction |
| `tests_avant_correction.txt` | Exécution des tests sur le code vulnérable (4 échecs sur 6) |
| `tests_apres_correction.txt` | Exécution des tests sur le code corrigé (6 tests réussis) |
| `rapport.md` | Ce compte rendu |

La correction est versionnée dans TIWAP sur la branche `fix/sql-injection-lab` (commit `413cbaa`).
Aucun jeton ni mot de passe n'apparaît dans ces livrables.

---

## 1. Architecture déployée

```
            Navigateur (hôte)
                  │  http://localhost:9000  (lié à 127.0.0.1 uniquement)
                  ▼
 ┌──────────────── réseau Docker « sonarnet » ────────────────┐
 │                                                            │
 │  scanner ── http://sonarqube:9000 ──►  sonarqube ── jdbc:postgresql://db:5432/sonar ──►  db
 │  (sonar-scanner-cli,                  (interface web,                                (PostgreSQL 15,
 │   lancé à la demande,                  moteur d'analyse,                              données SonarQube)
 │   monte ./TIWAP → /usr/src)            Elasticsearch)                                      │
 └────────────────────────────────────────────────────────────┘                             │
     volumes persistants : sonarqube_data, sonarqube_extensions, sonarqube_logs, postgresql_data
```

- `db` stocke la configuration, les projets, l'historique des analyses et les anomalies.
- `sonarqube` publie son interface uniquement sur `127.0.0.1:9000` : elle n'est pas joignable depuis le réseau local.
- `scanner` appartient au profil `scan` : il ne démarre pas avec `docker compose up -d`, seulement avec `docker compose run`.
  J'ai ajouté `SONAR_HOST_URL: http://sonarqube:9000` à ce service. Sans cette variable, le scanner vise par défaut `localhost:9000`, ce qui ne fonctionne pas depuis le conteneur.
- Le mot de passe PostgreSQL est lu depuis `.env`, qui est exclu de Git.

**Incident rencontré.** SonarQube s'est arrêté au démarrage avec l'erreur `password authentication failed for user "sonar"`.
La variable `POSTGRES_PASSWORD` avait été modifiée dans `.env` après la création du volume PostgreSQL. Or l'image PostgreSQL ne lit cette variable qu'à l'initialisation d'un volume vide.
Correction : `ALTER USER sonar WITH PASSWORD …` dans le conteneur `db`, pour réaligner la base sur `.env`, sans perte de données.

**Configuration de l'analyse** (`TIWAP/sonar-project.properties`) :

```properties
sonar.projectKey=tiwap
sonar.projectName=TIWAP
sonar.projectVersion=1.0
sonar.sources=.
sonar.sourceEncoding=UTF-8
sonar.python.version=3
# Répertoires non pertinents (IDE, binaires, uploads, sauvegardes, tests)
sonar.exclusions=.idea/**,uploads/**,backups/**,certificate/**,**/__pycache__/**,tests/**
```

Le jeton d'analyse (type *Global Analysis Token*) est transmis uniquement par la variable d'environnement `SONAR_TOKEN`.

---

## 2. État initial (analyse du 06/11/2026 à 14h46, code d'origine)

### 2.1 Vue d'ensemble

| Mesure | Valeur |
|---|---|
| Lignes de code (ncloc) | 2 367 |
| Vulnérabilités | **30** — note de sécurité **E** |
| Security Hotspots | 0 *(dans cette version, les règles sensibles apparaissent comme vulnérabilités)* |
| Bugs (fiabilité) | 5 |
| Code smells (maintenabilité) | 16 |
| Duplication | 6,2 % |

### 2.2 Anomalies de sécurité pertinentes

| Identifiant (clé SonarQube) | Fichier : ligne | Règle | Type / gravité | Impact potentiel | Confiance après revue du code | Action |
|---|---|---|---|---|---|---|
| `531d72c9…` | `app.py:29` | python:S6779 — clé secrète Flask divulguée | Vulnérabilité / Blocker | Falsification des cookies de session, donc usurpation de compte | **Confirmé** : `app.secret_key = 'l0G1n_53cR37_k3y'` en clair | Corriger (secret externalisé) |
| `3e7beff9…` | `helper/auth.py:39` | python:S5659 — JWT non vérifié | Vulnérabilité / Critical | Jeton forgé accepté, donc contournement de l'authentification | **Confirmé** : décodage sans vérification de signature | Corriger |
| `29dc4eeb…` | `app.py:28` | python:S4502 — protection CSRF désactivée | Vulnérabilité / Critical | Actions forcées à l'insu de l'utilisateur | Confirmé : aucune protection CSRF globale | Corriger |
| `23efd796…` (+2) | `app.py:723, 728, 731` | python:S4830 — certificat TLS non vérifié | Vulnérabilité / Critical | Interception (attaque de l'homme du milieu) | Confirmé (`verify=False`) | Corriger |
| `f43b8ade…` | `vulnerabilities/SQLi.py:151` | python:S4790 — hachage faible | Vulnérabilité / Critical | Mots de passe MD5 cassables hors ligne | Confirmé (MD5 sans sel) | Corriger (bcrypt/argon2) |
| `2968ab26…`, `695c5b09…` | `helper/db_manager.py:47, 55` | python:S4790 | Vulnérabilité / Critical | Idem | Confirmé | Corriger |
| `5c9664c3…` | `app.py:913` | python:S8392 — écoute sur toutes les interfaces | Vulnérabilité / Blocker | Exposition réseau non maîtrisée | Confirmé (`host='0.0.0.0'`) | Documenter / restreindre |
| `bba39caa…` | `app.py:913` | python:S4507 — mode debug | Vulnérabilité / Minor | Console de débogage, fuite d'informations | Confirmé | Corriger avant production |
| `4237482f…`, `bdd05568…` | `helper/mongodb_manager.py:68`, `init-db.js:8` | S2068 — identifiants en dur | Vulnérabilité / Major | Fuite d'identifiants via le dépôt | Confirmé : comptes de démonstration avec condensat MD5 en dur (`admin`) | Corriger |

L'export complet (30 vulnérabilités, 5 bugs, 16 code smells) est dans `sonarqube_resultats.csv`.

### 2.3 Injection SQL : non signalée par SonarQube

**SonarQube n'a signalé aucune injection SQL**, ni dans `vulnerabilities/SQLi.py` ni ailleurs. Pourtant, le fichier contient **six requêtes construites par interpolation et exploitables** : `sqli_low`, `sqli_medium`, `sqli_hard` et les trois variantes `blind_sqli_*`. Une septième, `secure_login`, est aussi construite par f-string. Elle retire les guillemets de l'entrée, donc n'est pas exploitable par ce biais, mais sa sécurité ne repose que sur ce filtrage fragile.

Cause, vérifiée dans la description des règles de l'instance :
- La règle `python:S2077` (« SQL queries should not be dynamically formatted ») est active. Mais elle ne couvre que **Django** (`connection.cursor().execute`, `RawSQL`, `.extra()`) et les pilotes **OracleDB / cx_Oracle**. TIWAP utilise `sqlite3`, et en plus via un objet métier (`DBManager.get_db_connection()`) : l'appel n'est pas reconnu.
- La règle d'analyse de flux (*taint analysis*) `python:S3649`, qui suit une donnée de `request.form` jusqu'à `cursor.execute`, **n'existe pas dans l'édition Community**. Elle est réservée aux éditions commerciales.

Il s'agit donc d'un **faux négatif** de l'outil. Le résultat ci-dessous provient d'une **analyse manuelle du code**, comme le demande l'énoncé. Je n'ai inventé aucun résultat du scanner.

D'autres vulnérabilités volontaires de TIWAP ne sont pas signalées non plus : injection de commandes (`CommandInjection.py`), XXE, désérialisation non sûre, NoSQL. Le même constat s'applique à elles.

---

## 3. Analyse manuelle de l'injection SQL retenue

### 3.1 Chemin de données

| Étape | Code |
|---|---|
| Source (entrée utilisateur) | `app.py:145-146` : `username = request.form.get('username')`, `password = request.form.get('password')` |
| Transmission | `app.py:147` : `sqli.sqli_low(username=username, password=password)` (route `/sql-injection`, niveau 0) |
| Point d'injection | `vulnerabilities/SQLi.py:22-23` : interpolation `%` dans le texte SQL |
| Exécution (sink) | `vulnerabilities/SQLi.py:25` : `cur.execute(stmt)` sur une connexion `sqlite3` |
| Restitution | `app.py:149` : le résultat, ou l'exception SQL brute, est affiché dans la page |

Ma recherche de pistes initiale :
`grep -RInE "execute\(|SELECT|request\.args|request\.form" TIWAP --include="*.py"`.
Elle montre que `helper/db_manager.py` utilise partout des requêtes paramétrées (`?`), qui ne sont **pas** vulnérables. En revanche, `vulnerabilities/SQLi.py` construit toutes ses requêtes par formatage de chaîne.

### 3.2 Code vulnérable (`vulnerabilities/SQLi.py`, fonction `sqli_low`)

```python
    if dbmanager.check_user(username=username):
        return "User Exists"

    try:
        stmt = "SELECT userid, username FROM users WHERE username='%s' AND password='%s'" \
               % (str(username), str(password))

        result = cur.execute(stmt)

    except sqlite3.OperationalError as e:
        return e

    return result.fetchall()
```

### 3.3 Mécanisme

Les valeurs saisies sont copiées **dans le texte** de la requête avant son envoi à SQLite. Une apostrophe dans l'entrée ferme la chaîne SQL, et la suite est interprétée comme du SQL. Avec `username = ' OR '1'='1' --`, la requête devient :

```sql
SELECT userid, username FROM users WHERE username='' OR '1'='1' --' AND password='x'
```

`OR '1'='1'` rend la condition toujours vraie, et `--` met en commentaire le contrôle du mot de passe. Le contrôle `check_user` placé avant ne protège pas : il cherche un utilisateur nommé littéralement `' OR '1'='1' --`, qui n'existe pas, donc il laisse passer la requête.

Effets constatés par les tests sur le code d'origine (`tests_avant_correction.txt`) :
- **Contournement du contrôle** : la requête renvoie les 5 comptes de la table `users`.
- **Exfiltration** : avec `' UNION SELECT username, password FROM users --`, elle renvoie le condensat MD5 du compte `admin`.
- **Fuite d'informations techniques** : une simple apostrophe (`o'brien`) casse la requête, et l'objet `sqlite3.OperationalError` est renvoyé puis affiché à l'utilisateur.

---

## 4. Correction

### 4.1 Code corrigé

```python
    try:
        # Requête paramétrée : la structure SQL est fixe, les valeurs sont
        # transmises séparément au pilote sqlite3 (marqueur « ? »).
        stmt = "SELECT userid, username FROM users WHERE username = ? AND password = ?"

        result = cur.execute(stmt, (str(username), str(password)))

    except sqlite3.OperationalError as e:
        return e

    return result.fetchall()
```

Diff complet : `correction.diff`.

### 4.2 Explication technique

- Le texte SQL est désormais **constant**. Les valeurs sont passées en second argument de `execute()`, et `sqlite3` les lie aux marqueurs `?` comme des **données**. Elles ne sont jamais analysées comme du SQL : `' OR '1'='1' --` est cherché tel quel comme nom d'utilisateur.
- Le marqueur `?` est celui du pilote `sqlite3` (paramstyle `qmark`). D'autres pilotes utilisent `%s` ou `:nom`.
- Le comportement fonctionnel est conservé : même retour `"User Exists"`, liste vide pour un compte inconnu, mêmes conversions `str()`. Seule la fonction concernée a été modifiée, comme le demande l'énoncé.
- Je n'ai volontairement **pas** remplacé la correction par un filtrage de caractères. `sqli_hard` montre qu'un filtrage se contourne : `#` est transformé en `'` après le contrôle.

### 4.3 Tests de non-régression

Le dépôt TIWAP ne contient aucun test. J'ai ajouté `TIWAP/tests/test_sqli_low.py`, basé sur `unittest` (aucune dépendance à installer). Il construit une base SQLite **temporaire** à partir de `helper/sqlite_db_reset.txt`. Il ne touche donc ni à `TIWAP.db` ni à l'application Flask, qui n'est jamais lancée.

| Test | Vérifie |
|---|---|
| `test_existing_user_is_reported` | comportement d'origine conservé (`"User Exists"`) |
| `test_unknown_user_returns_no_row` | utilisateur inconnu → `[]` |
| `test_tautology_in_username_does_not_bypass` | `' OR '1'='1' --` dans l'identifiant → `[]` |
| `test_tautology_in_password_does_not_bypass` | `' OR '1'='1` dans le mot de passe → `[]` |
| `test_union_payload_does_not_leak_password_hashes` | `UNION SELECT …` → aucun condensat renvoyé |
| `test_quote_in_input_is_treated_as_data` | une apostrophe ne provoque plus d'erreur SQL |

Commande : `python3 -m unittest discover -s tests -v` (depuis `TIWAP/`).

| | Résultat |
|---|---|
| Code d'origine | **FAILED (failures=4)** : les 4 tests de sécurité échouent, ce qui prouve qu'ils détectent bien la faille |
| Code corrigé | **OK** : 6 tests réussis sur 6 |

Ce test reste dans le dépôt. Il échouera si quelqu'un réintroduit une concaténation, ce qui garantit que la correction **dure dans le temps**.

---

## 5. Comparaison avant / après

Seconde analyse le 06/11/2026 à 14h58, sur le code corrigé.

| Critère | Avant correction | Après correction |
|---|---|---|
| Anomalie étudiée | Injection SQL dans `sqli_low` (route `/sql-injection`, niveau Low) | Idem, corrigée |
| Règle concernée | Aucune règle déclenchée. `python:S2077` est active mais ne couvre pas `sqlite3`, et `python:S3649` (taint) est absente de l'édition Community | Aucune règle déclenchée |
| Emplacement | `vulnerabilities/SQLi.py:22-25` | `vulnerabilities/SQLi.py:22-26` |
| Code vulnérable présent ? | **Oui** : interpolation `%` dans la requête (revue de code et tests) | **Non** pour `sqli_low` : requête paramétrée |
| Tests de régression | 4 échecs sur 6 (contournement, `UNION`, erreur SQL exposée) | 6 réussis sur 6 |
| Mesures SonarQube | 30 vulnérabilités, note E, 2 367 lignes | 30 vulnérabilités, note E, 2 366 lignes |
| Risque résiduel | Élevé | Faible pour `sqli_low`. **Élevé pour l'application** : 5 autres requêtes injectables dans `SQLi.py` (lignes 41, 64, 83, 101 et 124 après correction), plus `secure_login` (ligne 146) non paramétrée. S'y ajoutent MD5 sans sel, secret Flask et JWT non vérifié |

**Interprétation.** Le tableau de bord SonarQube **ne change pas**, et c'est normal : la règle qui aurait dû détecter la faille ne s'est jamais déclenchée, il n'y a donc rien à fermer. On a pourtant la preuve que la seconde analyse porte bien sur le code corrigé. Le nombre de lignes passe de 2 367 à 2 366, parce que la requête tient désormais sur une seule ligne. L'anomalie S4790 (MD5) de `SQLi.py` est suivie et passe de la ligne 151 à la ligne 152.

L'efficacité de la correction est donc démontrée par la **revue de code** et par les **tests**, et non par le scanner. C'est le cas prévu par l'énoncé : un résultat inchangé ne signifie pas que la correction est mauvaise.

---

## 6. Fiche de traitement de l'anomalie (contexte NOVA SERVICES)

Hypothèse : la même construction de requête existe dans une application métier de NOVA SERVICES exposée à Internet, par exemple le portail de gestion des clients.

| Champ | Valeur |
|---|---|
| Référence | NOVA-SEC-2026-001 |
| Actif concerné | Module d'authentification (`sqli_low`), application de type « gestion clients » |
| Source de détection | Revue de code manuelle lors de l'audit interne. **Non détectée** par SonarQube Community 26.10 |
| Description | Injection SQL par interpolation de `username` et `password` dans une requête SQLite (CWE-89, OWASP A03:2021 Injection) |
| Exploitabilité | Triviale : une seule requête HTTP, sans outil spécifique. Accessible à tout utilisateur connecté (route protégée par `is_logged`) |
| Impact C / I / D | **C : élevé** (liste des comptes, condensats de mots de passe) · **I : faible à moyen** (requête `SELECT`, et `sqlite3.execute()` refuse les requêtes multiples. Mais les condensats obtenus permettent d'usurper des comptes, et donc de modifier des données avec leurs droits) · **D : faible** |
| Mesures compensatoires existantes | Aucune : pas de WAF, erreurs SQL affichées, compte de base de données avec tous les droits |
| **Priorité** | **P1 — Critique** (exposition Internet + données clients + exploitation triviale) |
| Responsable de correction | Responsable technique de l'équipe de développement de l'application |
| Responsable de vérification | Référent sécurité applicative (indépendant du développeur) |
| Échéance | **7 jours calendaires** après la détection pour une P1 (correction en production) |
| Statut | Corrigé en environnement de laboratoire, en attente de recette |
| Preuves de correction | Commit `413cbaa` sur `fix/sql-injection-lab`, `correction.diff`, `tests_avant_correction.txt` (4 échecs), `tests_apres_correction.txt` (6 réussis), analyse SonarQube du 06/11/2026 14h58 |
| Preuve de vérification attendue | Revue de code par une seconde personne, tests ajoutés à la CI, test dynamique (DAST) de la route après déploiement |
| Risque résiduel | 5 autres requêtes injectables dans le même module, plus `secure_login` non paramétrée : à traiter dans la même échéance. Mots de passe MD5 sans sel (anomalie distincte, P2). Angle mort du scanner sur les injections SQL : ajouter une règle complémentaire (par exemple Semgrep ou Bandit `B608`) |
| Actions de fond | Interdire `execute()` avec une f-string ou `%` (règle d'outil + revue de code), compte de base de données en lecture seule pour ce module, masquer les erreurs SQL |

---

## 7. Mini-tableau de bord de pilotage

| # | Indicateur | Définition | Source de données | Fréquence | Responsable | Décision permise | Valeur actuelle (TIWAP) |
|---|---|---|---|---|---|---|---|
| 1 | Vulnérabilités ouvertes par priorité | Nombre de vulnérabilités au statut ouvert, réparties P1 à P4 après qualification (pas la gravité brute de l'outil) | SonarQube (API `issues/search`) + registre des anomalies qualifiées | Hebdomadaire | Référent sécurité applicative | Allouer l'effort de correction, bloquer une mise en production en présence de P1 | 30 vulnérabilités SonarQube (2 Blocker, 10 Critical, 6 Major, 12 Minor) + 6 injections SQL hors outil, dont 1 corrigée |
| 2 | Vulnérabilités P1/P2 hors délai | Nombre d'anomalies P1 (7 j) et P2 (30 j) dont l'échéance est dépassée | Registre des anomalies (date de détection, échéance, statut) | Hebdomadaire | RSSI | Escalader auprès de la direction, réaffecter des ressources, accepter formellement un risque | 0 (détection du jour) |
| 3 | Délai médian de correction (MTTR) | Médiane, en jours, entre la détection et la vérification de la correction, par priorité | Registre (horodatages) + historique des analyses SonarQube | Mensuelle | RSSI | Évaluer si les délais cibles sont tenables, ajuster les processus | < 1 jour en laboratoire (1 anomalie) |
| 4 | Taux de corrections vérifiées | Part des anomalies déclarées corrigées qui ont une preuve de vérification : nouvelle analyse **et** test de non-régression ou revue | Registre + CI (résultats des tests) + SonarQube | Mensuelle | Référent sécurité applicative | Refuser la clôture d'une anomalie sans preuve, renforcer les tests | 100 % (1/1 : tests + nouvelle analyse) |
| 5 | Taux de réouverture | Part des anomalies corrigées qui réapparaissent dans une analyse ou un test ultérieur | SonarQube (statut *Reopened*) + échecs des tests de non-régression | Trimestrielle | Responsables techniques des équipes | Identifier les équipes ou modules à accompagner (formation, revue renforcée) | 0 % |
| 6 | Couverture de l'analyse | Part des dépôts applicatifs du périmètre analysés au moins une fois par sprint **et** couverts par une règle d'injection adaptée à leur pile | Inventaire applicatif + SonarQube (liste des projets, dates d'analyse) | Mensuelle | RSSI | Étendre le périmètre, financer un outil complémentaire (taint analysis) | 1 projet. Couverture des injections SQL `sqlite3` : 0 % par SonarQube Community |

L'indicateur 6 complète le simple nombre d'anomalies. Ici, SonarQube affiche 30 vulnérabilités avant et après correction, alors que le risque réel a baissé. Inversement, six injections SQL n'apparaissent dans aucun compteur. Un tableau de bord qui ne montrerait que le total donnerait donc une image fausse dans les deux sens.

---

## 8. Réponses aux questions

**Q1 (§5) / Q1 (§16) — Rôle de PostgreSQL, et pourquoi ne pas tout stocker dans le conteneur ?**
PostgreSQL est la base persistante de SonarQube : configuration, utilisateurs, profils qualité, projets, historique des analyses, anomalies et leur statut de revue. Le conteneur `sonarqube` est jetable : il est recréé à chaque mise à jour d'image. La base, sur son propre volume, survit à ces recréations, se sauvegarde indépendamment et supporte la charge. La base H2 intégrée n'est prévue que pour l'évaluation et ne permet pas de mise à jour.

**Q2 (§5) / Q2 (§16) — Pourquoi `sonarqube:9000` entre conteneurs et `localhost:9000` dans le navigateur ?**
Dans un conteneur, `localhost` désigne le conteneur lui-même : le scanner se chercherait lui-même et ne trouverait rien sur le port 9000. Sur le réseau `sonarnet`, le DNS interne de Docker résout le nom du service `sonarqube` vers l'adresse IP de ce conteneur. Le navigateur, lui, tourne sur l'hôte et passe par la publication de port `127.0.0.1:9000 → 9000`.

**Q3 — Analyse statique contre test d'intrusion dynamique ?**
L'analyse statique (SAST) lit le code source sans l'exécuter. Elle est précoce, couvre tout le code, situe la ligne exacte, mais ignore le contexte d'exécution (configuration, déploiement) et produit faux positifs et faux négatifs. Le test dynamique (DAST, pentest) attaque l'application en fonctionnement, sans voir le code. Il prouve l'exploitabilité réelle, mais ne couvre que les chemins atteints et intervient plus tard. Les deux sont complémentaires. Ici, le test aurait trouvé l'injection SQL que le SAST a manquée.

**Q4 — Pourquoi la concaténation d'une entrée dans une requête crée-t-elle un risque ?**
Parce que la base reçoit une seule chaîne où code et données sont mélangés. Un caractère de syntaxe dans l'entrée (`'`, `--`, `UNION`) change la structure de la requête : condition toujours vraie, requête ajoutée, commentaire qui neutralise un contrôle. C'est ce que montre la section 3.3.

**Q5 — En quoi une requête paramétrée réduit-elle ce risque ?**
La structure SQL est envoyée et analysée séparément. Les valeurs sont ensuite liées aux marqueurs comme des littéraux typés. Quel que soit son contenu, une valeur ne peut plus modifier la requête. Ce n'est pas un échappement : la séparation est structurelle.

**Q6 — Pourquoi la validation d'entrée ne remplace-t-elle pas les requêtes paramétrées ?**
Une liste noire est toujours incomplète : TIWAP le montre avec `sqli_hard` : il bloque quelques chaînes connues, comme `1' OR 1=1`, mais transforme ensuite `#` en `'`, ce qui rouvre l'injection. Quant à `secure_login`, elle tient seulement parce que tous les guillemets sont supprimés : la moindre évolution du filtre ou de la requête la rendrait vulnérable. Une liste blanche dépend du besoin métier : un nom comme `O'Brien` est légitime et contient une apostrophe. La validation est une défense en profondeur. Seul le paramétrage traite la cause. Pour un nom de table ou de colonne dynamique, en revanche, seule une liste blanche convient.

**Q7 — Pourquoi un résultat SonarQube doit-il être vérifié et qualifié ?**
Une règle détecte un motif, pas un risque. Il faut confirmer le résultat (atteignabilité, donnée réellement contrôlée par l'utilisateur), écarter les faux positifs, et fixer la priorité selon le contexte : exposition, données, mesures compensatoires. Ici, S4790 est signalée en Critical sur MD5 dans `db_manager.py`. C'est justifié pour des mots de passe, mais le serait beaucoup moins pour un MD5 d'intégrité de fichier. Inversement, l'outil classe en Blocker une écoute sur `0.0.0.0` qui peut être normale dans un conteneur.

**Q8 — Que faire si aucune vulnérabilité SQL n'est signalée ?**
Ne pas conclure à l'absence de faille, comme dans ce TP. Il faut faire une revue manuelle des points d'exécution SQL (le `grep` du §9), comprendre pourquoi l'outil ne voit rien (ici, une règle limitée à Django/Oracle et pas de taint analysis en Community), ajouter un outil ou des règles complémentaires (Semgrep, Bandit, édition avec analyse de flux), faire un test dynamique, et documenter l'angle mort.

**Q9 — Comment prioriser une vulnérabilité sur une application métier critique ?**
On croise la criticité de l'application et des données, l'exposition (Internet ou interne), l'exploitabilité (prérequis, complexité, exploit public), l'impact sur la confidentialité, l'intégrité et la disponibilité, et les mesures compensatoires. Exemple : la fiche de la section 6 aboutit à une P1 avec une échéance de 7 jours. La gravité de l'outil sert d'entrée, pas de conclusion.

**Q10 — Pourquoi le nombre total d'anomalies n'est-il pas un indicateur suffisant ?**
Il mélange des anomalies de poids très différents : un code smell ne vaut pas une injection SQL. Il dépend du périmètre et des règles activées. Il ignore ce que l'outil ne voit pas, et il ne dit rien de la vitesse de correction ni de l'exposition. Ce TP le démontre : 30 avant, 30 après, alors que le risque a baissé, et zéro injection SQL comptée pour six présentes. Il faut des indicateurs de délai, de couverture et de vérification (section 7).

**Q11 — Protections autour du scanner et de son jeton en CI/CD ?**
- Jeton limité au projet (*Project Analysis Token*), avec une date d'expiration et une rotation régulière.
- Jeton stocké dans le coffre de secrets de la CI (variable masquée et protégée), jamais dans le dépôt ni dans `sonar-project.properties`.
- Jeton exposé uniquement aux branches protégées, et pas aux pipelines déclenchés par des contributions externes.
- Image du scanner épinglée par version ou empreinte, plutôt que `latest` comme dans ce laboratoire.
- Flux réseau limités vers le serveur SonarQube, en HTTPS.
- Révocation immédiate du jeton en cas de fuite, et journalisation de son usage.
- Quality Gate obligatoire pour fusionner.

**Q12 — Comment prouver qu'une correction est effective et durable ?**
- **Effective** : revue du diff par une seconde personne, test qui échoue sur l'ancien code et réussit sur le nouveau (section 4.3), nouvelle analyse statique, et si possible test dynamique de la route.
- **Durable** : ces tests restent dans le dépôt et tournent à chaque commit en CI, le Quality Gate bloque les régressions, le taux de réouverture est suivi (indicateur 5), et la cause racine est traitée (règle interdisant `execute()` avec une chaîne formatée, formation).

---

## 9. Conclusion : limites de l'analyse statique

Ce TP illustre concrètement l'avertissement de l'énoncé. SonarQube Community a relevé 30 vulnérabilités réelles et utiles : secret Flask en dur, JWT non vérifié, MD5, TLS non vérifié, CSRF. Mais il **n'a vu aucune des six injections SQL** d'un fichier pourtant nommé `SQLi.py`, ni l'injection de commandes, ni les failles XXE ou de désérialisation.

Ce n'est pas un défaut de configuration. La règle SQL disponible ne reconnaît que certains frameworks, et l'analyse de flux nécessaire est absente de cette édition. À l'inverse, certaines alertes, comme l'écoute sur `0.0.0.0`, dépendent du contexte et demandent une qualification.

Pour NOVA SERVICES, il en découle trois conclusions :
1. Un rapport SAST vide ou inchangé n'est **pas une preuve d'absence de vulnérabilité**.
2. La preuve d'une correction repose sur la combinaison **revue de code + tests de non-régression + nouvelle analyse**, et l'outil n'en est qu'une partie.
3. Le pilotage doit suivre aussi la **couverture réelle des outils** (indicateur 6) et compléter SonarQube par d'autres moyens : règles complémentaires, test dynamique, revue manuelle des zones sensibles.
