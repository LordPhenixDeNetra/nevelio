# Nevelio — Tutoriel complet

> **Nevelio** est un scanner de sécurité d'API REST/GraphQL écrit en Rust.
> Il automatise les tests de pénétration sur la couche applicative (couche 7) :
> authentification, injection, contrôle d'accès, infrastructure, logique métier.

---

## Table des matières

1. [Installation](#1-installation)
2. [Premier lancement et disclaimer légal](#2-premier-lancement-et-disclaimer-légal)
3. [Configuration avec `nevelio init`](#3-configuration-avec-nevelio-init)
4. [Commande `scan` — référence complète](#4-commande-scan--référence-complète)
5. [TUI Dashboard](#5-tui-dashboard)
6. [Les 6 modules d'attaque](#6-les-6-modules-dattaque)
7. [Formats de sortie](#7-formats-de-sortie)
8. [Suggestions IA via Claude](#8-suggestions-ia-via-claude)
9. [Commande `report` / `convert`](#9-commande-report--convert)
10. [Commande `modules`](#10-commande-modules)
11. [Reprise de scan (`--resume`)](#11-reprise-de-scan---resume)
12. [Mode simulation (`--dry-run`)](#12-mode-simulation---dry-run)
13. [Intégration CI/CD](#13-intégration-cicd)
14. [Scénarios pratiques complets](#14-scénarios-pratiques-complets)
15. [Référence rapide des flags](#15-référence-rapide-des-flags)

---

## 1. Installation

### Prérequis

- Rust stable ≥ 1.75 (`rustup update stable`)
- Accès réseau vers la cible
- **Autorisation explicite et écrite** pour tester la cible (obligation légale)

### Compilation depuis les sources

```bash
git clone https://github.com/your-org/nevelio.git
cd nevelio
cargo build --release
```

Le binaire est généré dans `target/release/nevelio`.

### Installation globale (optionnel)

```bash
# Linux / macOS
cp target/release/nevelio ~/.local/bin/
# ou
cargo install --path crates/cli
```

### Vérification

```bash
nevelio --version
# nevelio 0.1.0

nevelio --help
```

---

## 2. Premier lancement et disclaimer légal

### Avertissement obligatoire

Au **premier lancement** de toute commande qui effectue un scan, Nevelio
affiche un avertissement légal et demande une confirmation explicite :

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                  AVERTISSEMENT LEGAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Nevelio est un outil de pentest d'API conçu EXCLUSIVEMENT
pour des systèmes que vous possédez ou sur lesquels vous
avez une autorisation écrite explicite.

En continuant, vous confirmez que :
  1. Vous avez une autorisation explicite pour tester la cible.
  2. Vous acceptez l'entière responsabilité légale de vos actes.
  3. Vous traiterez toutes les découvertes comme confidentielles.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Acceptez-vous ces conditions ? [o/N] :
```

Répondez `o` ou `oui` (ou `y` / `yes` en anglais) pour continuer.

### Persistance de l'acceptation

Une fois accepté, Nevelio écrit un marqueur dans :

```
~/.config/nevelio/legal_accepted
```

Les lancements suivants **ne demandent plus confirmation**. Le fichier contient
la date d'acceptation au format RFC3339.

```bash
cat ~/.config/nevelio/legal_accepted
# 2026-05-02T14:23:45.123456789Z
```

### Mode non interactif (`--accept-legal`)

Pour les pipelines CI/CD où il n'y a pas de terminal interactif, utilisez
le flag global `--accept-legal` :

```bash
nevelio scan --target https://api.example.com --accept-legal
```

Ce flag accepte le disclaimer et le persiste pour les lancements futurs.

### Réinitialiser l'acceptation

```bash
rm ~/.config/nevelio/legal_accepted
```

---

## 3. Configuration avec `nevelio init`

### Générer un fichier de configuration

```bash
cd mon-projet
nevelio init
```

Crée `.nevelio.toml` dans le répertoire courant avec **tous les champs
documentés** sous forme de commentaires. Nevelio charge automatiquement
ce fichier si il est présent dans le répertoire de travail.

### Structure du fichier `.nevelio.toml`

```toml
# URL de base de l'API cible (obligatoire si --target absent)
target = "https://api.example.com"

# Chemin local ou URL vers la spec OpenAPI/Swagger (JSON ou YAML)
# spec = "./openapi.yaml"
# spec = "https://api.example.com/openapi.json"

# Profil de scan : stealth | normal | aggressive
profile = "normal"

# Modules à exécuter (défaut : tous)
# modules = ["auth", "injection", "access-control", "graphql", "infra", "business-logic"]

# Requêtes simultanées (écrase le défaut du profil)
# concurrency = 5

# Requêtes par seconde max (écrase le défaut du profil)
# rate_limit = 10

# Timeout par requête en secondes
# timeout = 10

# Token d'authentification
# auth_token = "Bearer eyJhbGciOiJIUzI1NiJ9..."
# auth_token = "Basic dXNlcjpwYXNz"

# Proxy HTTP (Burp Suite, mitmproxy, etc.)
# proxy = "http://127.0.0.1:8080"

# Répertoire de sortie pour les rapports
out_dir = "./results"

# Sévérité minimale pour quitter avec code 1 (CI/CD)
# fail_on = "high"   # none | low | medium | high | critical
```

### Référence des champs

| Champ | Type | Défaut profil | Description |
|---|---|---|---|
| `target` | string | — | URL de base de l'API cible |
| `spec` | string | — | Spec OpenAPI (fichier local ou URL) |
| `profile` | `stealth`/`normal`/`aggressive` | `normal` | Profil de scan |
| `modules` | liste de strings | tous | Modules à exécuter |
| `concurrency` | entier | stealth=1, normal=5, aggressive=20 | Requêtes simultanées |
| `rate_limit` | entier | stealth=2, normal=10, aggressive=50 | Req/s maximum |
| `timeout` | entier (secondes) | 10 | Timeout par requête |
| `auth_token` | string | — | Header `Authorization` complet |
| `proxy` | URL | — | Proxy HTTP (ex. Burp Suite) |
| `out_dir` | chemin | `.` | Répertoire où écrire les rapports |
| `fail_on` | `none`/`low`/`medium`/`high`/`critical` | — | Seuil d'échec CI |

### Priorité de configuration

Les flags CLI **écrasent toujours** le fichier `.nevelio.toml` :

```
CLI flags > .nevelio.toml > valeurs par défaut du profil
```

---

## 4. Commande `scan` — référence complète

```
nevelio scan [OPTIONS]
```

### 4.1 Cible

| Flag | Description | Exemple |
|---|---|---|
| `--target URL` | URL de base de l'API | `--target https://api.example.com` |
| `--url URL` | Alias de `--target` | `--url https://api.example.com` |
| `--spec FILE\|URL` | Spec OpenAPI/Swagger (JSON ou YAML) | `--spec ./openapi.yaml` |

Sans `--spec`, Nevelio tente une **découverte automatique** des endpoints
via des chemins communs (`/api`, `/v1`, `/graphql`, etc.).

```bash
# Avec spec — couverture maximale
nevelio scan --target https://api.example.com --spec ./openapi.yaml --accept-legal

# Sans spec — découverte automatique
nevelio scan --target https://api.example.com --accept-legal
```

### 4.2 Profils de scan

| Profil | Concurrence | Req/s | Usage |
|---|---|---|---|
| `stealth` | 1 | 2 | Production sensible, éviter les alertes IDS |
| `normal` | 5 | 10 | Environnement de staging — défaut recommandé |
| `aggressive` | 20 | 50 | Lab ou environnement dédié, scan rapide |

```bash
nevelio scan --target https://api.example.com --profile stealth --accept-legal
nevelio scan --target https://api.example.com --profile aggressive --accept-legal
```

### 4.3 Sélection de modules

Par défaut, **tous les modules** sont exécutés. Pour restreindre :

```bash
# Un seul module
nevelio scan --target https://api.example.com --module auth --accept-legal

# Plusieurs modules
nevelio scan --target https://api.example.com \
             --module auth injection access-control \
             --accept-legal
```

Noms de modules disponibles : `auth`, `injection`, `access-control`,
`graphql`, `infra`, `business-logic`.

### 4.4 Contrôle réseau fin

```bash
nevelio scan --target https://api.example.com \
             --concurrency 3 \
             --rate-limit 5 \
             --timeout 30 \
             --accept-legal
```

| Flag | Description | Défaut |
|---|---|---|
| `--concurrency N` | Requêtes simultanées | Dépend du profil |
| `--rate-limit N` | Requêtes par seconde max | Dépend du profil |
| `--timeout S` | Timeout par requête (secondes) | 10 |

### 4.5 Authentification

Nevelio injecte le token dans le header `Authorization` de chaque requête.

```bash
# JWT Bearer token
nevelio scan --target https://api.example.com \
             --auth-token "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
             --accept-legal

# Basic auth (base64 de "user:password")
nevelio scan --target https://api.example.com \
             --auth-token "Basic dXNlcjpwYXNz" \
             --accept-legal
```

### 4.6 Proxy HTTP

Utile avec **Burp Suite**, **mitmproxy**, ou **OWASP ZAP** pour inspecter
le trafic généré par Nevelio.

```bash
# Avec Burp Suite en écoute sur le port 8080
nevelio scan --target https://api.example.com \
             --proxy http://127.0.0.1:8080 \
             --accept-legal
```

### 4.7 Sortie et rapports

```bash
# Format HTML (défaut si --output absent)
nevelio scan --target https://api.example.com --accept-legal
# → ./findings.json + ./report.html

# Format JSON uniquement
nevelio scan --target https://api.example.com --output json --accept-legal

# Format SARIF (GitHub Security)
nevelio scan --target https://api.example.com \
             --output sarif \
             --out-dir ./sarif-results \
             --accept-legal

# Répertoire de sortie personnalisé
nevelio scan --target https://api.example.com \
             --out-dir /tmp/pentest-$(date +%Y%m%d) \
             --accept-legal
```

Formats disponibles : `json`, `html`, `markdown`, `junit`, `sarif`.
Le fichier `findings.json` est **toujours écrit** quel que soit le format choisi.

### 4.8 Seuil d'échec CI (`--fail-on`)

Quitte avec le code de retour **1** si au moins un finding atteint
la sévérité spécifiée :

```bash
nevelio scan --target https://api.example.com \
             --fail-on high \
             --accept-legal
echo $?   # 1 si HIGH ou CRITICAL trouvé, 0 sinon
```

| Valeur | Bloque sur |
|---|---|
| `none` | Jamais (toujours 0) |
| `low` | LOW, MEDIUM, HIGH, CRITICAL |
| `medium` | MEDIUM, HIGH, CRITICAL |
| `high` | HIGH, CRITICAL |
| `critical` | CRITICAL uniquement |

### 4.9 Modes spéciaux

```bash
# Reprendre un scan interrompu
nevelio scan --target https://api.example.com \
             --out-dir ./results \
             --resume \
             --accept-legal

# Simuler sans envoyer de requêtes réelles
nevelio scan --target https://api.example.com \
             --dry-run \
             --accept-legal

# Désactiver le TUI (terminal non interactif)
nevelio scan --target https://api.example.com \
             --no-tui \
             --accept-legal

# Suggestions IA après le scan (nécessite ANTHROPIC_API_KEY)
nevelio scan --target https://api.example.com \
             --ai-suggestions \
             --accept-legal
```

### 4.10 Flags globaux

Ces flags s'appliquent à **toutes les commandes** :

| Flag | Description |
|---|---|
| `--verbose` | Affiche les requêtes HTTP et les logs détaillés |
| `--accept-legal` | Accepte le disclaimer sans prompt interactif |
| `--no-color` | Désactive les couleurs ANSI (pour pipes, logs, CI) |

```bash
# CI/CD — combinaison recommandée
nevelio scan --target https://api.example.com \
             --accept-legal \
             --no-tui \
             --no-color \
             --fail-on high

# Debug — voir toutes les requêtes
nevelio scan --target https://api.example.com \
             --verbose \
             --accept-legal
```

---

## 5. TUI Dashboard

### Activation automatique

Le dashboard ratatui s'active automatiquement quand :
- La sortie standard est un **terminal interactif** (TTY détecté)
- Le flag `--no-tui` est **absent**

En CI/CD, la sortie redirigée vers un pipe ou un fichier log désactive
automatiquement le TUI.

### Interface

```
┌─ Nevelio — API Security Scanner ────────────────────────────────┐
│ Progression  [████████████░░░░░░░░░░░░░░░░░░]  45%   ETA: 1m23s│
├─ Modules ────────────────────────────────────────┬─ Findings ───┤
│  ✓ auth          (5 checks)     2 findings       │ HIGH   JWT alg│
│  ✓ injection     (4 checks)     1 finding        │ MEDIUM SQLi   │
│  ▶ access-control (5 checks)    en cours...      │ LOW    CORS   │
│  ○ graphql       en attente                      │               │
│  ○ infra         en attente                      │               │
│  ○ business-logic en attente                     │               │
├──────────────────────────────────────────────────┴───────────────┤
│  Target: https://api.example.com    Profil: normal    Req: 47/s  │
└──────────────────────────────────────────────────────────────────┘
```

- **Panneau progression** — barre de progression globale avec ETA en temps réel
- **Panneau modules** — état de chaque module (en attente, en cours, terminé)
- **Panneau findings** — table des vulnérabilités trouvées en direct

### Désactivation

```bash
# Forcer le mode texte simple (stdout)
nevelio scan --target https://api.example.com --no-tui --accept-legal
```

---

## 6. Les 6 modules d'attaque

Chaque module est indépendant et peut être exécuté seul avec `--module`.

---

### 6.1 Module `auth` — Authentification

```bash
nevelio scan --target https://api.example.com --module auth --accept-legal
```

#### Missing Authentication — CWE-306

Teste chaque endpoint **sans header `Authorization`**. Un code 200 ou 201
sur un endpoint qui devrait être protégé indique une authentification manquante.

*Exemple de finding :*
```
[HIGH] Missing Authentication — GET /api/v1/users
Endpoint accessible sans authentification. CWE-306.
Recommandation : Implémenter un middleware d'authentification obligatoire.
```

#### JWT Algorithm None — CWE-327

Envoie un JWT dont l'en-tête `alg` est `none` et la signature vide.
Si le serveur accepte ce token, il ne valide pas la signature.

*Payload forgé :*
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.
```

#### JWT Weak Secret — CWE-330

Tente de valider la signature HMAC-SHA256 avec une liste de secrets faibles
(`secret`, `password`, `123456`, `changeme`, etc.).

#### JWT Claims Manipulation — CWE-269

Modifie le claim `role` (user → admin, is_admin: false → true) et re-signe
le token avec le secret faible découvert précédemment.

#### Basic Auth Brute Force — CWE-521

Sur les endpoints qui renvoient `WWW-Authenticate: Basic`, teste un dictionnaire
de couples `user:password` communs.

---

### 6.2 Module `injection` — Injection

```bash
nevelio scan --target https://api.example.com --module injection --accept-legal
```

#### SQL Injection — CWE-89

Teste 4 techniques sur chaque paramètre de requête et corps JSON :

| Technique | Payload exemple | Détection |
|---|---|---|
| **Time-based** | `' OR SLEEP(5)--` | Délai de réponse ≥ 4s |
| **Error-based** | `' OR 1=1--` | Message d'erreur SQL dans la réponse |
| **Union-based** | `' UNION SELECT NULL--` | Données injectées dans la réponse |
| **Boolean-based** | `' AND 1=1--` vs `' AND 1=2--` | Différence de contenu |

#### NoSQL Injection — CWE-943

Injecte des opérateurs MongoDB dans les paramètres JSON :

```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}}
```

#### Server-Side Template Injection (SSTI) — CWE-94

Teste des payloads de rendu de templates dans les paramètres de type string :

| Moteur | Payload | Résultat attendu |
|---|---|---|
| Jinja2 / Twig | `{{7*7}}` | `49` dans la réponse |
| FreeMarker | `${7*7}` | `49` dans la réponse |
| Pebble | `{{7*'7'}}` | `7777777` dans la réponse |

#### Command Injection — CWE-77

Injecte des séparateurs de commandes shell dans les paramètres string :

```
; id
| whoami
`id`
$(id)
& ping -c 1 127.0.0.1
```

Détection par délai (commandes sleep) ou présence de `uid=` dans la réponse.

---

### 6.3 Module `access-control` — Contrôle d'accès

```bash
nevelio scan --target https://api.example.com --module access-control --accept-legal
```

#### IDOR Numérique — CWE-639

Pour chaque endpoint contenant un ID numérique dans l'URL, substitue
des IDs voisins (`/users/42` → `/users/41`, `/users/43`) et compare
les réponses pour détecter un accès non autorisé aux ressources d'autres utilisateurs.

#### IDOR UUID — CWE-639

Même logique avec des UUIDs aléatoirement générés pour les endpoints
contenant un UUID dans le chemin.

#### BFLA — Broken Function Level Authorization — CWE-285

Teste les endpoints d'administration (`/admin/*`, `/management/*`, `/internal/*`)
avec le token de l'utilisateur standard. Un code 200 indique une autorisation
mal configurée par rôle.

Les réponses contenant des indicateurs d'erreur métier (`"not found"`,
`"does not exist"`, `"invalid"`) sont filtrées pour réduire les faux positifs.

#### Élévation de privilèges verticale — CWE-269

Envoie des requêtes d'administration (création d'utilisateur, modification
de rôle) avec un token standard et détecte les codes 200/201 inattendus.

#### Mass Assignment — CWE-915

Injecte des champs sensibles supplémentaires dans les corps de requêtes PUT/PATCH :

```json
{
  "name": "John",
  "role": "admin",
  "is_admin": true,
  "credits": 999999
}
```

Un code 200 avec les champs reflétés dans la réponse indique une vulnérabilité.

---

### 6.4 Module `graphql` — GraphQL

```bash
nevelio scan --target https://api.example.com --module graphql --accept-legal
```

Nevelio détecte automatiquement les endpoints GraphQL (`/graphql`, `/api/graphql`,
`/query`, etc.) avant d'exécuter les vérifications.

#### Introspection exposée — CWE-200

```graphql
{ __schema { types { name fields { name } } } }
```

Si le serveur répond avec le schéma complet, l'introspection est active en production.
Cela expose la structure interne de l'API à un attaquant.

#### Field Suggestions — CWE-209

Envoie des noms de champs invalides proches de noms réels. GraphQL expose parfois
des suggestions `"Did you mean 'password'?"` qui révèlent des champs internes.

#### Depth DoS — CWE-400

Envoie des requêtes récursives profondément imbriquées pour tester les limites
de profondeur :

```graphql
{ user { friends { friends { friends { friends { id name } } } } } }
```

Sans limite de profondeur, le serveur peut subir une surcharge CPU/mémoire.

---

### 6.5 Module `infra` — Infrastructure

```bash
nevelio scan --target https://api.example.com --module infra --accept-legal
```

#### CORS Misconfiguration

Envoie `Origin: https://evil.com` et vérifie si la réponse contient
`Access-Control-Allow-Origin: *` ou reflète l'origine hostile.

#### HSTS Absent

Vérifie la présence du header `Strict-Transport-Security` sur les réponses HTTPS.

#### Security Headers

Vérifie la présence et la validité de :
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` ou `SAMEORIGIN`
- `X-XSS-Protection`

#### Server Version Disclosure

Détecte les headers `Server:` et `X-Powered-By:` qui exposent la version
exacte du serveur ou du framework (ex. `nginx/1.18.0`, `Express 4.17.1`).

#### Debug Endpoints

Teste 20+ chemins de diagnostic courants :

```
/actuator          /actuator/health   /actuator/env
/debug             /debug/pprof       /metrics
/swagger-ui        /swagger-ui.html   /api-docs
/graphql-playground /playground       /console
/admin             /admin/login       /management
/.env              /config            /info
/status            /healthz
```

#### Content-Security-Policy

Vérifie la présence du header `Content-Security-Policy` et signale
les politiques permissives (`unsafe-inline`, `unsafe-eval`, `*`).

#### Referrer-Policy

Vérifie la présence du header `Referrer-Policy`.

#### Cookie Flags

Pour chaque `Set-Cookie` dans les réponses, vérifie :
- Flag `Secure` (cookie non transmis en HTTP clair)
- Flag `HttpOnly` (inaccessible depuis JavaScript)
- Attribut `SameSite` (protection CSRF)

#### TLS Version Obsolète

Détecte les serveurs acceptant TLS 1.0 ou TLS 1.1 (obsolètes depuis RFC 8996).

#### Secrets dans les Réponses

Recherche des patterns de secrets dans les corps de réponse :
- Clés AWS (`AKIA...`)
- Tokens GitHub (`ghp_...`)
- Clés privées PEM
- Chaînes de connexion de base de données

#### Stack Traces

Détecte les traces d'exception dans les réponses d'erreur :
`NullPointerException`, `at java.lang.`, `Traceback (most recent call last)`,
`Error:` suivi d'un chemin de fichier, etc.

---

### 6.6 Module `business-logic` — Logique métier

```bash
nevelio scan --target https://api.example.com --module business-logic --accept-legal
```

#### Rate Limiting Absent

Envoie 20 requêtes rapides vers le même endpoint et vérifie si une réponse
`429 Too Many Requests` est renvoyée. Sans rate limiting, les endpoints
sensibles (login, reset mot de passe, OTP) sont vulnérables au brute force.

#### X-Forwarded-For Bypass

Si le rate limiting est actif, teste le contournement via :

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
CF-Connecting-IP: 192.168.1.1
```

#### User-Agent Bypass

Teste le contournement avec des User-Agents de bots connus ou de navigateurs
mobiles pour détecter des rate limits basés uniquement sur l'UA.

#### Race Condition

Envoie simultanément 10 requêtes identiques (achat, réservation, coupon)
et détecte si plusieurs répondent avec succès alors qu'une seule devrait l'être.

#### Valeurs Négatives / Manipulation de Prix

Injecte des valeurs négatives ou nulles dans les paramètres numériques
des transactions : `{"quantity": -1}`, `{"amount": 0}`, `{"price": -100}`.

---

## 7. Formats de sortie

### 7.1 JSON — `findings.json`

Toujours écrit, format canonique et source de vérité pour les autres formats.

```json
[
  {
    "id": "auth-jwt-alg-none-001",
    "title": "JWT Algorithm None Accepted",
    "severity": "Critical",
    "cwe": "CWE-327",
    "endpoint": "POST /api/v1/auth/token",
    "description": "L'endpoint accepte des tokens JWT avec alg:none...",
    "recommendation": "Rejeter explicitement l'algorithme 'none'. Utiliser RS256 ou ES256."
  }
]
```

### 7.2 HTML — `report.html`

Rapport interactif généré avec le moteur de templates Tera.
**Format par défaut** quand `--output` est absent.

Fonctionnalités :
- **Filtre par sévérité** — boutons Critical / High / Medium / Low / Info
- **Thème clair/sombre** — toggle en haut à droite, persisté en localStorage
- **Accordéon** — chaque finding est collapsible pour une lecture claire
- **Recherche** — filtre instantané par mot-clé dans les titres

```bash
# Ouvrir le rapport dans le navigateur
open results/report.html          # macOS
xdg-open results/report.html     # Linux
```

### 7.3 Markdown — `report.md`

Format texte structuré, idéal pour :
- Copier-coller dans une Pull Request GitHub/GitLab
- Importer dans Confluence, Notion, ou un wiki
- Envoyer par email sous forme de rapport

```bash
nevelio scan --target https://api.example.com --output markdown --accept-legal
```

### 7.4 JUnit — `report.xml`

Chaque finding est représenté comme un `<testcase>` en échec.
Compatible avec Jenkins, GitLab CI, CircleCI.

```bash
nevelio scan --target https://api.example.com --output junit --accept-legal
```

Structure XML générée :
```xml
<testsuites>
  <testsuite name="nevelio" tests="5" failures="3">
    <testcase name="JWT Algorithm None Accepted" classname="auth">
      <failure message="CWE-327 — CRITICAL">
        Endpoint: POST /api/v1/auth/token
        Recommandation: Rejeter l'algorithme 'none'...
      </failure>
    </testcase>
  </testsuite>
</testsuites>
```

### 7.5 SARIF — `report.sarif`

Static Analysis Results Interchange Format — standard de l'industrie pour
les outils d'analyse statique. Compatible avec :
- **GitHub Advanced Security** — apparaît dans l'onglet Security du dépôt
- **VS Code** — extension SARIF Viewer
- **Azure DevOps**

```bash
nevelio scan --target https://api.example.com --output sarif --accept-legal
```

Upload vers GitHub Security :
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/report.sarif
```

---

## 8. Suggestions IA via Claude

Nevelio peut générer des **recommandations de remédiation détaillées** pour
chaque finding, en utilisant l'API Claude d'Anthropic.

### Prérequis

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...
```

Modèle utilisé : **`claude-haiku-4-5-20251001`** (rapide et économique).

### Utilisation

```bash
nevelio scan --target https://api.example.com \
             --ai-suggestions \
             --out-dir ./results \
             --accept-legal
```

Si `ANTHROPIC_API_KEY` est absent, Nevelio affiche un avertissement
**avant le scan** et continue sans les suggestions :

```
⚠  --ai-suggestions ignoré : ANTHROPIC_API_KEY non défini
```

### Fichier de sortie

Les suggestions sont sauvegardées dans `<out-dir>/ai_suggestions.md` :

```markdown
# Suggestions de remédiation IA — Nevelio

## JWT Algorithm None Accepted (CRITICAL)
**Endpoint :** POST /api/v1/auth/token

### Analyse
Cette vulnérabilité permet à un attaquant de forger des tokens JWT valides
sans connaître le secret, en spécifiant `"alg": "none"` dans l'en-tête...

### Remédiation recommandée
1. Utiliser une liste blanche d'algorithmes acceptés : `["RS256", "ES256"]`
2. Ne jamais faire confiance au champ `alg` fourni dans le token...
```

---

## 9. Commande `report` / `convert`

Convertit un fichier `findings.json` existant en un autre format,
**sans relancer le scan**.

```bash
nevelio report --input ./results/findings.json \
               --format html \
               --out-dir ./rapports

# Alias "convert" — même fonctionnement
nevelio convert --input findings.json --format sarif
```

| Flag | Requis | Description |
|---|---|---|
| `--input FILE` | Oui | Chemin vers le `findings.json` source |
| `--format FORMAT` | Non (défaut: html) | Format cible |
| `--out-dir PATH` | Non (défaut: `.`) | Répertoire de sortie |

Formats disponibles : `json`, `html`, `markdown`, `junit`, `sarif`.

**Usage typique :** générer un rapport HTML à partir du JSON stocké en CI,
ou produire un SARIF pour upload dans GitHub Security sans rescanner.

---

## 10. Commande `modules`

Inspecter les modules disponibles sans lancer de scan.

### Lister tous les modules

```bash
nevelio modules list
```

Sortie :
```
Modules disponibles :
  auth           — Authentification et gestion des sessions (5 vérifications)
  injection      — Injection SQL, NoSQL, SSTI, Command (4 vérifications)
  access-control — IDOR, BFLA, mass assignment (5 vérifications)
  graphql        — Introspection, field suggestions, depth DoS (3 vérifications)
  infra          — Headers, CORS, debug endpoints, TLS (11 vérifications)
  business-logic — Rate limiting, race condition, logique métier (4+ vérifications)
```

### Détail d'un module

```bash
nevelio modules show auth
nevelio modules show injection
nevelio modules show access-control
nevelio modules show graphql
nevelio modules show infra
nevelio modules show business-logic
```

---

## 11. Reprise de scan (`--resume`)

Si un scan est interrompu (crash, timeout réseau, Ctrl+C), il peut être
repris sans recommencer depuis le début.

```bash
# Premier scan — interrompu
nevelio scan --target https://api.example.com \
             --out-dir ./results \
             --accept-legal
# ^C interrompu après le module auth et injection

# Reprise — charge les findings existants, saute auth et injection
nevelio scan --target https://api.example.com \
             --out-dir ./results \
             --resume \
             --accept-legal
```

**Comment ça marche :**
1. Nevelio charge `<out-dir>/findings.json` s'il existe.
2. Identifie les modules qui ont produit des résultats (considérés comme complétés).
3. Exécute uniquement les modules restants.
4. Fusionne les nouveaux findings avec les anciens.

---

## 12. Mode simulation (`--dry-run`)

Valide la configuration et affiche les requêtes qui **seraient** envoyées,
sans effectuer aucun appel réseau réel.

```bash
nevelio scan --target https://api.example.com \
             --spec ./openapi.yaml \
             --module auth injection \
             --dry-run \
             --accept-legal
```

Sortie :
```
[DRY-RUN] Cible     : https://api.example.com
[DRY-RUN] Spec      : ./openapi.yaml
[DRY-RUN] Modules   : auth, injection
[DRY-RUN] Profil    : normal (5 concurrent, 10 req/s)
[DRY-RUN] Endpoints détectés : 23

[DRY-RUN] Requêtes qui seraient envoyées :
  POST https://api.example.com/api/v1/auth/token   (auth: jwt-alg-none)
  POST https://api.example.com/api/v1/auth/token   (auth: jwt-weak-secret)
  GET  https://api.example.com/api/v1/users        (auth: missing-auth)
  POST https://api.example.com/api/v1/login        (injection: sqli-time-based)
  ...
```

---

## 13. Intégration CI/CD

### Combinaison de flags recommandée pour la CI

```bash
nevelio scan \
  --target "$API_URL" \
  --spec openapi.yaml \
  --output sarif \
  --out-dir results \
  --fail-on high \
  --accept-legal \
  --no-tui \
  --no-color
```

- `--accept-legal` — pas de prompt interactif
- `--no-tui` — désactive le dashboard terminal
- `--no-color` — sortie texte propre pour les logs CI
- `--fail-on high` — bloque le pipeline sur findings HIGH/CRITICAL

### 13.1 GitHub Actions

```yaml
name: API Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  nevelio-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build Nevelio
        run: cargo build --release --bin nevelio

      - name: Run API Security Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          ./target/release/nevelio scan \
            --target ${{ vars.API_STAGING_URL }} \
            --spec openapi.yaml \
            --output sarif \
            --out-dir sarif-results \
            --fail-on high \
            --accept-legal \
            --no-tui \
            --no-color \
            --ai-suggestions

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()   # uploader même si le scan a échoué
        with:
          sarif_file: sarif-results/report.sarif

      - name: Upload AI Suggestions
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ai-suggestions
          path: sarif-results/ai_suggestions.md
```

### 13.2 GitLab CI

```yaml
api-security-scan:
  stage: test
  image: rust:latest
  before_script:
    - cargo build --release --bin nevelio
  script:
    - ./target/release/nevelio scan
        --target "$API_STAGING_URL"
        --output junit
        --out-dir results
        --fail-on medium
        --accept-legal
        --no-tui
        --no-color
  artifacts:
    when: always
    reports:
      junit: results/report.xml
    paths:
      - results/
  variables:
    ANTHROPIC_API_KEY: "$ANTHROPIC_API_KEY"
```

### 13.3 Docker

```dockerfile
FROM rust:1.75 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin nevelio

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/nevelio /usr/local/bin/nevelio
ENTRYPOINT ["nevelio"]
```

```bash
docker build -t nevelio .
docker run --rm nevelio scan \
  --target https://api.example.com \
  --accept-legal \
  --no-tui \
  --no-color
```

### 13.4 Bonnes pratiques CI

| Pratique | Pourquoi |
|---|---|
| Toujours `--accept-legal` | Évite le blocage sur prompt interactif |
| Toujours `--no-tui` | Le TUI nécessite un TTY que la CI n'a pas |
| Toujours `--no-color` | Les codes ANSI polluent les logs CI |
| `--fail-on high` | Bloque les PR avec vulnérabilités critiques |
| `--profile normal` ou `stealth` | Ne pas saturer l'environnement de staging |
| `ANTHROPIC_API_KEY` en secret | Ne jamais écrire la clé en clair |
| `--output sarif` sur GitHub | Intégration native avec GitHub Security |
| `--output junit` sur GitLab/Jenkins | Intégration native des rapports de test |

---

## 14. Scénarios pratiques complets

### Scénario A — Audit express sans spec

Idéal pour une première prise en main ou une cible sans spec disponible.

```bash
# 1. Initialiser la configuration
nevelio init
# Éditer .nevelio.toml selon la cible

# 2. Scan avec découverte automatique des endpoints
nevelio scan --target https://api.example.com \
             --profile stealth \
             --accept-legal

# 3. Ouvrir le rapport
open report.html
```

### Scénario B — Audit professionnel avec spec OpenAPI

```bash
# 1. Configurer l'auth (token JWT obtenu depuis l'app)
TOKEN="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Scan complet sur le staging
nevelio scan \
  --target https://staging.api.example.com \
  --spec ./openapi.yaml \
  --profile normal \
  --auth-token "$TOKEN" \
  --out-dir ./pentest-$(date +%Y%m%d) \
  --output html \
  --fail-on high \
  --accept-legal

# 3. Ouvrir le rapport interactif
open ./pentest-$(date +%Y%m%d)/report.html
```

### Scénario C — Audit ciblé avec interception Burp Suite

```bash
# Burp Suite en écoute sur 127.0.0.1:8080
nevelio scan \
  --target https://api.example.com \
  --module auth injection \
  --proxy http://127.0.0.1:8080 \
  --no-tui \
  --verbose \
  --accept-legal
# Les requêtes Nevelio apparaissent dans l'historique Burp
```

### Scénario D — Scan avec suggestions IA et rapport multi-format

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...

nevelio scan \
  --target https://api.example.com \
  --spec ./openapi.yaml \
  --ai-suggestions \
  --out-dir ./results \
  --accept-legal

# Résultats dans ./results/ :
# ├── findings.json       (données brutes)
# ├── report.html         (rapport interactif)
# └── ai_suggestions.md   (remédiation IA)

# Générer en plus un SARIF pour GitHub
nevelio convert --input ./results/findings.json \
                --format sarif \
                --out-dir ./results
```

### Scénario E — Reprise après interruption et audit de logique métier

```bash
# Scan initial — interrompu
nevelio scan --target https://api.example.com \
             --spec ./openapi.yaml \
             --out-dir ./results \
             --accept-legal
# <interrompu>

# Reprise + focus logique métier
nevelio scan --target https://api.example.com \
             --spec ./openapi.yaml \
             --out-dir ./results \
             --resume \
             --module business-logic \
             --accept-legal
```

### Scénario F — Test d'une API GraphQL

```bash
nevelio scan \
  --target https://api.example.com \
  --module graphql infra \
  --auth-token "Bearer $TOKEN" \
  --verbose \
  --accept-legal
```

---

## 15. Référence rapide des flags

### Commande `nevelio scan`

| Flag | Type | Description |
|---|---|---|
| `--target URL` | string | URL de base de l'API |
| `--url URL` | string | Alias de `--target` |
| `--spec FILE\|URL` | string | Spec OpenAPI (JSON ou YAML) |
| `--profile PROFIL` | `stealth`/`normal`/`aggressive` | Profil de scan |
| `--module MOD...` | liste | Modules à exécuter (espace-séparés) |
| `--concurrency N` | entier | Requêtes simultanées |
| `--rate-limit N` | entier | Requêtes par seconde max |
| `--timeout S` | entier | Timeout par requête (secondes) |
| `--auth-token TOKEN` | string | Header Authorization |
| `--proxy URL` | URL | Proxy HTTP |
| `--output FORMAT` | `json`/`html`/`markdown`/`junit`/`sarif` | Format de sortie |
| `--out-dir PATH` | chemin | Répertoire de sortie |
| `--fail-on SEV` | `none`/`low`/`medium`/`high`/`critical` | Seuil d'échec |
| `--resume` | booléen | Reprendre un scan interrompu |
| `--dry-run` | booléen | Simuler sans requêtes réelles |
| `--no-tui` | booléen | Désactiver le dashboard TUI |
| `--ai-suggestions` | booléen | Suggestions IA (nécessite ANTHROPIC_API_KEY) |

### Flags globaux (toutes commandes)

| Flag | Description |
|---|---|
| `--verbose` | Logs détaillés et requêtes HTTP |
| `--accept-legal` | Accepter le disclaimer sans prompt |
| `--no-color` | Désactiver les couleurs ANSI |

### Commande `nevelio report` / `nevelio convert`

| Flag | Requis | Défaut | Description |
|---|---|---|---|
| `--input FILE` | Oui | — | Fichier `findings.json` source |
| `--format FORMAT` | Non | `html` | Format cible |
| `--out-dir PATH` | Non | `.` | Répertoire de sortie |

### Commande `nevelio modules`

```bash
nevelio modules list           # lister tous les modules
nevelio modules show <nom>     # détail d'un module
```

### Variables d'environnement

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Clé API Claude (requis pour `--ai-suggestions`) |

---

*Généré pour Nevelio v0.1 — Scanner d'API de sécurité*
