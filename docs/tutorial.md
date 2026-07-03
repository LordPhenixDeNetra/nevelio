# Nevelio — Tutoriel complet

> **Nevelio** est un scanner de sécurité d'API REST/GraphQL écrit en Rust.
> Il automatise les tests de pénétration sur la couche applicative (couche 7) :
> authentification, injection, contrôle d'accès, infrastructure, logique métier,
> XXE, SSRF, OAuth2, Prototype Pollution et bien plus.
>
> **Version couverte : v0.6.0** — 13 modules, 180 tests, scripting Rhai, intégrations Slack/GitHub/Jira.

---

## Table des matières

1. [Installation](#1-installation)
2. [Premier lancement et disclaimer légal](#2-premier-lancement-et-disclaimer-légal)
2bis. [Configuration globale — `nevelio config init`](#2bis-configuration-globale--nevelio-config-init)
3. [Configuration avec `nevelio init`](#3-configuration-avec-nevelio-init)
4. [Commande `scan` — référence complète](#4-commande-scan--référence-complète)
5. [TUI Dashboard](#5-tui-dashboard)
6. [Les 10 modules d'attaque](#6-les-10-modules-dattaque)
7. [Formats de sortie](#7-formats-de-sortie)
8. [Fonctionnalités IA](#8-fonctionnalités-ia) (`--ai-triage` / `--ai-remediation` / `--ai-report` / `--ai-payloads`)
8bis. [Commande `agent` — Agent autonome](#8bis-commande-agent--agent-de-sécurité-autonome)
8ter. [Commande `mcp serve` — Serveur MCP](#8ter-commande-mcp-serve--serveur-mcp)
9. [Commande `report` / `convert`](#9-commande-report--convert)
10. [Commande `modules`](#10-commande-modules)
11. [Reprise de scan (`--resume`)](#11-reprise-de-scan---resume)
12. [Mode simulation (`--dry-run`)](#12-mode-simulation---dry-run)
13. [Intégration CI/CD](#13-intégration-cicd)
14. [Scénarios pratiques complets](#14-scénarios-pratiques-complets)
15. [Référence rapide des flags](#15-référence-rapide-des-flags)
16. [Internationalisation (`--lang`)](#16-internationalisation---lang)
17. [Import Postman / HAR / Insomnia](#17-import-postman--har--insomnia)
18. [Commande `diff` — Comparaison de scans](#18-commande-diff--comparaison-de-scans)
19. [Commande `watch` — Scan périodique](#19-commande-watch--scan-périodique)
20. [Commande `shell` — REPL interactif](#20-commande-shell--repl-interactif)
21. [Commande `serve` — Dashboard web](#21-commande-serve--dashboard-web)
22. [Commande `notify` — Alertes Slack/Teams](#22-commande-notify--alertes-slackteams)
23. [Commande `issue` — Tickets GitHub/Jira](#23-commande-issue--tickets-githubjira)
24. [Suppressions de faux positifs](#24-suppressions-de-faux-positifs)
25. [Scripting Rhai (`--script`)](#25-scripting-rhai---script)

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

## 2bis. Configuration globale — `nevelio config init`

### Pourquoi configurer ?

Nevelio intègre des fonctionnalités IA (triage, remédiation, rapport narratif,
génération de payloads, agent autonome). Elles nécessitent un provider LLM configuré
une seule fois dans un fichier global `~/.config/nevelio/config.toml`.

### Premier lancement automatique

Dès la première commande, si la config globale n'existe pas et que vous êtes dans
un terminal interactif, Nevelio lance automatiquement l'assistant de configuration :

```
Bienvenue ! Nevelio a besoin d'une configuration initiale.

Provider IA [anthropic/openai/ollama/mistral/groq] : anthropic
Modèle [claude-opus-4-8] : 
Langue d'interface [fr/en/es] : fr

Configuration enregistrée dans ~/.config/nevelio/config.toml
```

### Lancement manuel

```bash
nevelio config init
```

### Afficher la configuration actuelle

```bash
nevelio config show
```

### Modifier une valeur

```bash
nevelio config set ai.provider openai
nevelio config set ai.providers.openai.model gpt-4o
```

### Tester la connexion au provider

```bash
# Tous les providers configurés
nevelio config ai ping

# Un provider spécifique
nevelio config ai ping anthropic
```

### Fichier de config généré

```toml
# ~/.config/nevelio/config.toml

[ai]
enabled = true
provider = "anthropic"   # provider actif

[ai.providers.anthropic]
model        = "claude-opus-4-8"
api_key_env  = "ANTHROPIC_API_KEY"
max_tokens   = 4096
temperature  = 0.2

[ai.routing]
# Providers dédiés par tâche (optionnel)
# triage   = "groq"      # provider rapide pour le triage
# report   = "anthropic" # provider puissant pour les rapports
# payloads = "mistral"   # provider pour la génération de payloads
# fallback = "ollama"    # fallback local si le cloud est indisponible
```

### Variables d'environnement

| Provider   | Variable         |
|------------|-----------------|
| Anthropic  | `ANTHROPIC_API_KEY` |
| OpenAI     | `OPENAI_API_KEY`    |
| Mistral    | `MISTRAL_API_KEY`   |
| Groq       | `GROQ_API_KEY`      |
| Ollama     | aucune (local)      |

### En CI/CD

En environnement non interactif, la config IA est optionnelle. Sans elle,
les flags `--ai-*` sont silencieusement ignorés (pas d'erreur fatale).

Configurez en CI via variables d'environnement :

```yaml
# GitHub Actions
env:
  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
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

# ── Suppressions de faux positifs ──────────────────────────
# Chaque règle [[suppress]] supprime les findings correspondants
# après le scan. Les critères sont combinés en AND.
# [[suppress]]
# module = "infra"
# severity = "informative"
# reason = "endpoints de monitoring acceptés"
#
# [[suppress]]
# title_contains = "JWT"
# endpoint_prefix = "/public/"
# reason = "endpoints publics — pas d'auth requise"
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
| `[[suppress]]` | tableau | — | Règles de suppression de faux positifs (voir §24) |

#### Champs d'une règle `[[suppress]]`

| Champ | Description |
|---|---|
| `title_contains` | Le titre du finding doit contenir cette chaîne |
| `module` | Nom exact du module (`auth`, `infra`, etc.) |
| `severity` | `critical`/`high`/`medium`/`low`/`informative` (minuscules) |
| `endpoint_prefix` | L'URL du finding doit commencer par ce préfixe |
| `reason` | Commentaire libre (non évalué) |

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
`graphql`, `infra`, `business-logic`, `xxe`, `ssrf`, `oauth2`, `prototype-pollution`,
`websocket`, `grpc`, `soap`.

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

### 4.9 Filtrage post-scan avec scripts Rhai (`--script`)

Applique un ou plusieurs scripts Rhai pour filtrer les findings après le scan.
Un finding est conservé uniquement si **tous** les scripts retournent `true`.

```bash
# Script unique
nevelio scan --target https://api.example.com \
             --script ./filtres/no-infra.rhai \
             --accept-legal

# Plusieurs scripts chaînés (logique AND)
nevelio scan --target https://api.example.com \
             --script ./filtres/no-infra.rhai \
             --script ./filtres/min-cvss-7.rhai \
             --accept-legal
```

Exemple de script `filtres/no-infra.rhai` :

```rhai
// Supprime tous les findings du module infra
finding_module != "infra"
```

Variables disponibles dans un script :

| Variable | Type | Description |
|---|---|---|
| `title` | string | Titre du finding |
| `severity` | string | `"Critical"` / `"High"` / `"Medium"` / `"Low"` / `"Informative"` |
| `finding_module` | string | Nom du module (`"auth"`, `"infra"`, etc.) |
| `endpoint` | string | URL de l'endpoint vulnérable |
| `method` | string | Méthode HTTP (`"GET"`, `"POST"`, etc.) |
| `description` | string | Description du finding |
| `cvss` | float | Score CVSS (0.0–10.0) |

> **Note :** En cas d'erreur dans un script, le finding est **conservé** (comportement fail-safe).
> `module` est un mot réservé Rhai — utiliser `finding_module`.

---

### 4.10 Modes spéciaux

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

## 6. Les 10 modules d'attaque

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

## 8. Fonctionnalités IA

Nevelio intègre plusieurs fonctionnalités IA activées via des flags de scan.
Chacune nécessite un provider configuré (`nevelio config init`).

### 8.0 Prérequis

Configurer au moins un provider (Anthropic, OpenAI, Mistral, Groq, Ollama ou Bedrock) :

```bash
nevelio config init            # assistant interactif
nevelio config ai ping         # vérifier la connexion
```

Variables d'environnement directes (sans fichier de config) :

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...   # Anthropic Claude
export OPENAI_API_KEY=sk-...                # OpenAI / Azure
export MISTRAL_API_KEY=...                  # Mistral AI
export GROQ_API_KEY=gsk_...                 # Groq (inférence rapide)
# Ollama ne requiert pas de clé (local)
# Bedrock : AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_REGION
```

---

### 8.1 Triage IA — `--ai-triage`

Classe chaque finding en **vrai positif / faux positif / incertain** avec
un score de confiance et une justification.

```bash
nevelio scan --target https://api.example.com \
             --ai-triage \
             --out-dir ./results \
             --accept-legal
```

**Sorties :**
- Table colorisée dans le terminal (vert = faux positif, rouge = vrai positif)
- `<out-dir>/ai_triage.json` — résultats structurés

```json
[
  {
    "finding_id": "jwt-alg-none-1",
    "verdict": "true_positive",
    "confidence": 0.95,
    "reason": "L'endpoint accepte effectivement alg:none sans rejeter le token."
  }
]
```

---

### 8.2 Remédiation IA — `--ai-remediation`

Génère des **étapes de remédiation détaillées** avec exemples de code pour
chaque finding.

```bash
nevelio scan --target https://api.example.com \
             --ai-remediation \
             --out-dir ./results \
             --accept-legal
```

**Sortie :** `<out-dir>/ai_remediation.md`

```markdown
## JWT Algorithm None Accepted — Remédiation

**Priorité :** Critique

### Étapes
1. Définir une liste blanche d'algorithmes : `["RS256", "ES256"]`
2. Valider l'en-tête `alg` côté serveur avant toute vérification de signature

### Exemple (Node.js / jsonwebtoken)
\```js
jwt.verify(token, secret, { algorithms: ['RS256'] });
\```
```

---

### 8.3 Rapport narratif IA — `--ai-report`

Génère un **rapport exécutif complet** en Markdown : résumé, chaîne d'attaque
narrative, priorités, contexte métier.

```bash
nevelio scan --target https://api.example.com \
             --ai-report \
             --out-dir ./results \
             --accept-legal
```

**Sortie :** `<out-dir>/ai_narrative_report.md`

```markdown
# Rapport de Sécurité — api.example.com

## Résumé Exécutif
L'audit a révélé 3 vulnérabilités critiques permettant une compromission
complète de l'authentification...

## Chaîne d'Attaque Principale
1. Exploitation du bypass JWT (CRITICAL) → accès admin sans credentials
2. IDOR sur /api/users/{id} (HIGH) → exfiltration de données utilisateurs
...
```

---

### 8.4 Payloads IA — `--ai-payloads`

Génère des **payloads d'attaque contextuels** adaptés au framework et aux
endpoints découverts, avant ou pendant le scan.

```bash
nevelio scan --target https://api.example.com \
             --ai-payloads \
             --out-dir ./results \
             --accept-legal
```

**Sortie :** `<out-dir>/ai_payloads.json`

Les payloads sont générés pour les types de vulnérabilité : SQLi, NoSQLi, XSS,
SSRF, SSTI, Path Traversal, Command Injection, LDAP, XXE, Open Redirect.

---

### 8.5 Combinaison de flags IA

Tous les flags IA sont cumulables et fonctionnent en parallèle :

```bash
nevelio scan --target https://api.example.com \
             --ai-triage \
             --ai-remediation \
             --ai-report \
             --ai-payloads \
             --out-dir ./results \
             --accept-legal
```

Chaque tâche peut utiliser un provider différent via le routing :

```toml
# ~/.config/nevelio/config.toml
[ai.routing]
triage   = "groq"       # rapide pour le triage
report   = "anthropic"  # qualitatif pour le rapport
payloads = "ollama"     # local pour les payloads
fallback = "openai"     # si le provider principal est indisponible
```

---

### 8.6 Ancien flag `--ai-suggestions`

Le flag `--ai-suggestions` reste disponible pour compatibilité ascendante.
Il est équivalent à `--ai-remediation` avec le provider Anthropic uniquement.
Préférer `--ai-remediation` avec la configuration globale de provider.

---

## 8bis. Commande `agent` — Agent de sécurité autonome

L'agent autonome pilote une boucle LLM → outils → analyse sans intervention
humaine. Il découvre les endpoints, les sonde, identifie les vulnérabilités
et produit un rapport.

### Usage

```bash
nevelio agent <TARGET> \
    --max-iterations 10 \
    --max-requests  100 \
    --accept-legal
```

| Option | Défaut | Description |
|---|---|---|
| `TARGET` | — | URL de base de l'API cible |
| `--max-iterations N` | 20 | Nombre maximum de tours LLM |
| `--max-requests N` | 100 | Nombre maximum de requêtes HTTP |
| `--ai-budget TOKENS` | — | Limite de tokens consommés (coût) |
| `--dry-run` | `false` | Planifie sans envoyer de requêtes réelles |
| `--out-dir PATH` | — | Répertoire de sortie du rapport |

### Exemple — Audit complet

```bash
nevelio agent https://api.example.com \
    --max-iterations 15 \
    --max-requests 200 \
    --ai-budget 50000 \
    --out-dir ./agent-report \
    --accept-legal
```

### Exemple — Mode simulation

```bash
nevelio agent https://api.example.com \
    --dry-run \
    --max-iterations 5 \
    --accept-legal
```

### Guardrails de sécurité

L'agent est soumis à des guardrails inviolables :

| Guardrail | Comportement |
|---|---|
| **Scope** | Refuse toute requête hors du domaine cible déclaré |
| **Max requests** | Arrêt propre une fois la limite atteinte |
| **Budget tokens** | Arrêt si le budget IA est dépassé |
| **Dry run** | Simule les requêtes sans les envoyer |
| **Legal** | Refuse de démarrer sans `--accept-legal` |

### Outils disponibles pour l'agent LLM

| Outil | Description |
|---|---|
| `list_endpoints` | Découvre les endpoints de la cible |
| `probe_endpoint` | Envoie une requête HTTP et analyse la réponse |
| `report_finding` | Enregistre une vulnérabilité détectée |
| `finish` | Termine la session et produit le rapport |

---

## 8ter. Commande `mcp serve` — Serveur MCP

Expose les outils Nevelio via le **Model Context Protocol (MCP)**, permettant
à Claude Desktop, Continue.dev ou tout agent compatible MCP d'orchestrer
Nevelio directement depuis une conversation.

### Usage

```bash
nevelio mcp serve --target https://api.example.com --accept-legal
```

| Option | Description |
|---|---|
| `--target URL` | URL de base de l'API (optionnel, peut être fourni par le LLM) |
| `--timeout N` | Timeout HTTP en secondes (défaut : 30) |

### Configuration Claude Desktop

Ajouter dans `~/.config/claude/claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "nevelio": {
      "command": "nevelio",
      "args": [
        "mcp", "serve",
        "--target", "https://api.example.com",
        "--accept-legal"
      ]
    }
  }
}
```

Claude peut alors demander : *"Audite l'API cible et liste les
vulnérabilités"* — Nevelio exécute le crawling et les probes directement.

### Outils exposés via MCP

| Outil MCP | Description |
|---|---|
| `list_endpoints` | Crawle la cible et retourne les endpoints découverts |
| `probe_endpoint` | Sonde un endpoint (méthode, headers, body configurables) |
| `report_finding` | Enregistre une vulnérabilité dans la session courante |
| `finish` | Retourne le rapport JSON complet de la session |

### Transport

Le serveur utilise le transport **stdio** (stdin → requêtes JSON-RPC,
stdout → réponses). Il est compatible avec tout client MCP utilisant
le protocole version `2024-11-05`.

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
  auth                — Authentification et gestion des sessions (5 vérifications)
  injection           — Injection SQL, NoSQL, SSTI, Command, XXE (9 vérifications)
  access-control      — IDOR, BFLA, mass assignment (5 vérifications)
  graphql             — Introspection, field suggestions, depth DoS (3 vérifications)
  infra               — Headers, CORS, debug endpoints, TLS (11 vérifications)
  business-logic      — Rate limiting, race condition, logique métier (4+ vérifications)
  xxe                 — XML External Entity Injection in-band et out-of-band (2 vérifications)
  ssrf                — Server-Side Request Forgery, bypass techniques (3 vérifications)
  oauth2              — Open redirect, PKCE, token leakage, scope creep (4 vérifications)
  prototype-pollution — JSON body et query string pollution (2 vérifications)
  websocket           — Origin, auth handshake, injection, rate limiting (4 vérifications)
  grpc                — Réflexion, plaintext, health check, métadonnées (4 vérifications)
  soap                — WSDL disclosure, XXE, SQLi, WS-Security (4 vérifications)
```

### Détail d'un module

```bash
nevelio modules show auth
nevelio modules show injection
nevelio modules show access-control
nevelio modules show graphql
nevelio modules show infra
nevelio modules show business-logic
nevelio modules show ssrf
nevelio modules show oauth2
nevelio modules show prototype-pollution
nevelio modules show websocket
nevelio modules show grpc
nevelio modules show soap
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

### 6.7 Module `xxe` — XML External Entity

```bash
nevelio scan --target https://api.example.com --module xxe --accept-legal
```

#### XXE In-Band — CWE-611

Injecte des entités XML externes dans les endpoints acceptant du XML ou du contenu multipart.
Détecte si le serveur résout les entités et reflète le contenu du fichier `/etc/passwd` ou une
réponse réseau vers un hôte contrôlé.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

#### XXE Out-of-Band (Blind) — CWE-611

Utilise un payload DTD externe pour déclencher une connexion DNS/HTTP sortante,
détectable même lorsque le contenu n'est pas reflété dans la réponse.

---

### 6.8 Module `ssrf` — Server-Side Request Forgery

```bash
nevelio scan --target https://api.example.com --module ssrf --accept-legal
```

#### SSRF via paramètres URL — CWE-918

Injecte des URLs pointant vers des ressources internes dans tous les paramètres
de type string contenant des mots-clés (`url`, `callback`, `redirect`, `src`, `href`, `uri`).

Cibles testées :
- `http://169.254.169.254/latest/meta-data/` — AWS IMDSv1
- `http://metadata.google.internal/computeMetadata/v1/` — GCP
- `http://127.0.0.1/admin` — services internes

#### SSRF via en-têtes HTTP — CWE-918

Teste les en-têtes `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`
pour détecter les SSRF côté infrastructure.

---

### 6.9 Module `oauth2` — OAuth2 / OpenID Connect

```bash
nevelio scan --target https://api.example.com --module oauth2 --accept-legal
```

#### Open Redirect dans le paramètre `redirect_uri` — CWE-601

Injecte des URIs malveillantes dans `redirect_uri` pour voler des codes d'autorisation.

#### Token Leakage via Referrer — CWE-200

Détecte les endpoints qui transmettent des tokens OAuth2 dans l'URL (fragment ou query),
les exposant dans les logs et le header `Referer`.

#### PKCE Absent — CWE-345

Vérifie que les flux d'autorisation sans secret client exigent le challenge PKCE
(`code_challenge` / `code_verifier`), obligatoire pour les clients publics (SPAs, mobiles).

#### Scope Creep — CWE-269

Teste si le serveur accepte des scopes non autorisés en les ajoutant dans la
requête d'autorisation.

---

### 6.10 Module `prototype-pollution` — Pollution de prototype

```bash
nevelio scan --target https://api.example.com --module prototype-pollution --accept-legal
```

#### JSON Body Pollution — CWE-1321

Injecte des clés `__proto__` et `constructor.prototype` dans les corps JSON :

```json
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
```

Détecte si ces propriétés sont reflétées dans la réponse ou modifient le comportement
de l'application (code 200 sur un endpoint d'admin).

#### Query String Pollution

Injecte via les paramètres GET : `?__proto__[admin]=true&constructor[prototype][admin]=true`.

---

### 6.11 Module `websocket` — WebSocket

```bash
nevelio scan --target https://api.example.com --module websocket --accept-legal
```

Nevelio détecte automatiquement les endpoints WebSocket courants (`/ws`, `/websocket`,
`/socket.io/`, `/stream`, `/events`, etc.) et les endpoints marqués comme tels dans la spec.

#### Validation d'Origin — CWE-346

Envoie un handshake WebSocket avec un header `Origin: https://evil.example.com`.
Si la connexion réussit, le serveur n'applique pas de liste blanche d'origines autorisées —
n'importe quel site tiers peut ouvrir une connexion WebSocket au nom d'un utilisateur authentifié.

#### Handshake sans authentification — CWE-306

Tente une connexion WebSocket sans header `Authorization` ni token de session.
Un succès indique que des utilisateurs non authentifiés peuvent interagir avec le service.

#### Injection dans les messages (XSS, SQLi, SSTI) — CWE-79

Envoie des payloads via WebSocket et analyse les réponses :

```json
{"msg": "<script>alert(1)</script>"}
{"query": "' OR '1'='1"}
{"input": "{{7*7}}"}
```

Si le serveur réfléchit le payload non filtré, un attaquant peut déclencher du XSS,
de l'injection SQL, ou de l'exécution de template côté serveur.

#### Rate Limiting sur les connexions — CWE-770

Ouvre 10 connexions WebSocket consécutives. Si toutes réussissent sans aucun rejet,
l'absence de rate limiting expose le service à l'épuisement de ressources ou au brute force.

---

### 6.12 Module `grpc` — gRPC / Protobuf

```bash
nevelio scan --target https://api.example.com --module grpc --accept-legal
```

#### gRPC en clair (sans TLS) — CWE-319

Tente d'envoyer une requête gRPC sur `http://` (sans TLS). Un serveur répondant avec
`content-type: application/grpc` confirme que les payloads Protobuf et les métadonnées
d'authentification transitent en clair.

#### Réflexion gRPC exposée — CWE-200

Envoie une requête `ServerReflection/ServerReflectionInfo` sans authentification.
Si le serveur répond avec `grpc-status: 0`, l'API de réflexion est active — équivalent
de l'introspection GraphQL : un attaquant peut énumérer tous les services et méthodes Protobuf.

```
/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
```

#### Health Check sans authentification — CWE-200

Appelle `Health/Check` sans header `Authorization`. Une réponse positive expose l'état
des dépendances internes (bases de données, services tiers) à un attaquant non authentifié.

#### Appels RPC sans vérification d'authentification — CWE-306

Teste des chemins RPC courants (`/api.UserService/GetUser`, `/api.v1.AdminService/ListUsers`)
sans token. Si le serveur répond `grpc-status: 0` (OK) ou `12` (UNIMPLEMENTED) au lieu de
`16` (UNAUTHENTICATED) ou `7` (PERMISSION_DENIED), l'authentification n'est pas appliquée.

---

### 6.13 Module `soap` — SOAP / WSDL

```bash
nevelio scan --target https://api.example.com --module soap --accept-legal
```

Nevelio détecte les endpoints SOAP via leur chemin (`.asmx`, `.svc`, `/soap/`, `/rpc/`, etc.)
et teste les suffixes WSDL courants (`?wsdl`, `?WSDL`, `.wsdl`).

#### WSDL exposé publiquement — CWE-200

Vérifie si le WSDL est accessible sans authentification. La présence des balises
`<wsdl:definitions>`, `<portType>`, `<types>` confirme que la structure complète du
service (opérations, types de données) est lisible par n'importe qui.

#### XXE dans les enveloppes SOAP — CWE-611

Injecte une entité XML externe dans le body SOAP :

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope>
  <soapenv:Body><data>&xxe;</data></soapenv:Body>
</soapenv:Envelope>
```

La présence de `root:`, `/bin/bash` ou `nobody:` dans la réponse confirme la lecture
du fichier `/etc/passwd`.

#### Injection SQL dans les paramètres SOAP — CWE-89

Injecte `' OR '1'='1' --` dans un champ du body SOAP et détecte les messages d'erreur SQL
(`SQL syntax`, `ORA-`, `pg_query`, `SQLSTATE`).

#### Absence de WS-Security — CWE-306

Envoie une enveloppe SOAP anonyme (sans header WS-Security, UsernameToken ou SAML).
Un code de réponse HTTP 200 avec un body SOAP valide indique que le service accepte
les requêtes non authentifiées.

---

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
| `--ai-suggestions` | booléen | Suggestions IA Anthropic (compatibilité — préférer `--ai-remediation`) |
| `--ai-triage` | booléen | Triage vrai/faux positif par LLM |
| `--ai-remediation` | booléen | Étapes de remédiation détaillées par LLM |
| `--ai-report` | booléen | Rapport narratif exécutif par LLM |
| `--ai-payloads` | booléen | Génération de payloads contextuels par LLM |
| `--script FILE` | liste | Scripts Rhai de filtrage post-scan (répétable) |

### Flags globaux (toutes commandes)

| Flag | Description |
|---|---|
| `--verbose` | Logs détaillés et requêtes HTTP |
| `--accept-legal` | Accepter le disclaimer sans prompt |
| `--no-color` | Désactiver les couleurs ANSI |
| `--lang LANG` | Langue de l'interface : `fr` \| `en` \| `es` (détection auto si absent) |

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

### Commande `nevelio agent`

```
nevelio agent <TARGET> [OPTIONS]
```

| Option | Défaut | Description |
|---|---|---|
| `--max-iterations N` | 20 | Tours LLM maximum |
| `--max-requests N` | 100 | Requêtes HTTP maximum |
| `--ai-budget TOKENS` | — | Limite de tokens consommés |
| `--dry-run` | false | Simulation sans HTTP réel |
| `--out-dir PATH` | — | Répertoire de sortie |

### Commande `nevelio mcp serve`

```
nevelio mcp serve [OPTIONS]
```

| Option | Défaut | Description |
|---|---|---|
| `--target URL` | — | URL de base de l'API cible |
| `--timeout N` | 30 | Timeout HTTP en secondes |

### Variables d'environnement

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Clé API Claude (Anthropic) |
| `OPENAI_API_KEY` | Clé API OpenAI |
| `MISTRAL_API_KEY` | Clé API Mistral AI |
| `GROQ_API_KEY` | Clé API Groq |
| `OLLAMA_HOST` | URL du serveur Ollama local (défaut : `http://localhost:11434`) |
| `AWS_ACCESS_KEY_ID` | Clé d'accès AWS (Bedrock) |
| `AWS_SECRET_ACCESS_KEY` | Clé secrète AWS (Bedrock) |
| `AWS_SESSION_TOKEN` | Token de session AWS (optionnel, pour credentials temporaires) |
| `AWS_REGION` | Région AWS pour Bedrock (ex: `us-east-1`) |
| `NEVELIO_LANG` | Forcer la langue (`fr`/`en`/`es`) sans passer par `--lang` |

---

## 16. Internationalisation (`--lang`)

Nevelio supporte **3 langues** : français (`fr`), anglais (`en`) et espagnol (`es`).
Tous les messages CLI, le TUI, le disclaimer légal, les suggestions IA et le rapport HTML
sont traduits automatiquement.

### Détection automatique de la langue

La langue est déterminée dans l'ordre de priorité suivant :

| Priorité | Source | Exemple |
|---|---|---|
| 1 | Flag `--lang` | `nevelio --lang es scan …` |
| 2 | Variable `NEVELIO_LANG` | `NEVELIO_LANG=fr nevelio scan …` |
| 3 | Variable système `$LANGUAGE` ou `$LANG` | `LANG=fr_FR.UTF-8` → détecte `fr` |
| 4 | Défaut | `en` |

La normalisation est automatique : `fr_FR.UTF-8`, `fr-FR` et `fr` donnent tous `fr`.

### Exemples

**Français (via `$LANG` système) :**

```bash
LANG=fr_FR.UTF-8 nevelio scan --target https://api.example.com --dry-run
# Cible       : https://api.example.com
# Profil      : Normal
# Résumé  :  0 Critical  0 High  0 Medium  0 Low  0 Informative
```

**Anglais (via flag) :**

```bash
nevelio --lang en scan --target https://api.example.com --dry-run
# Target      : https://api.example.com
# Profile     : Normal
# Summary  :  0 Critical  0 High  0 Medium  0 Low  0 Informative
```

**Espagnol (via variable) :**

```bash
NEVELIO_LANG=es nevelio scan --target https://api.example.com --dry-run
# Objetivo    : https://api.example.com
# Perfil      : Normal
# Resumen  :  0 Crítico  0 Alto  0 Medio  0 Bajo  0 Informativo
```

### Disclaimer légal multilingue

Le texte légal affiché au premier lancement est lui aussi traduit.
La réponse positive acceptée varie selon la langue :

| Langue | Réponses acceptées |
|---|---|
| Français | `o`, `oui` |
| Anglais | `y`, `yes` |
| Espagnol | `s`, `sí`, `si` |

### Rapport HTML localisé

Le rapport HTML généré (`report.html`) reprend la langue du scan :
ses labels (Cible / Target / Objetivo, Description, Recommandation…)
sont automatiquement traduits dans la langue sélectionnée.

### Suggestions IA localisées

Avec `--ai-suggestions`, le prompt envoyé à Claude est rédigé dans la langue
sélectionnée — les suggestions reçues sont donc dans la même langue.

```bash
nevelio --lang es scan --target https://api.example.com \
  --ai-suggestions --accept-legal
# → Les suggestions IA seront en espagnol
```

---

---

## 17. Import Postman / HAR / Insomnia

Nevelio détecte automatiquement le format de la spec passée à `--spec` et
sélectionne le bon parseur. Aucun flag supplémentaire n'est nécessaire.

### Formats supportés

| Extension / Signature | Format | Commande |
|---|---|---|
| `.yaml` / `.json` contenant `"openapi"` | OpenAPI 3.x / Swagger 2.0 | `--spec ./openapi.yaml` |
| `.json` contenant `"_postman_schema"` | Postman v2.1 | `--spec ./collection.json` |
| `.json` contenant `"__export_format": 4` | Insomnia v4 | `--spec ./insomnia.json` |
| `.har` ou JSON contenant `"log"."entries"` | HAR (HTTP Archive) | `--spec ./capture.har` |

### Exemples

```bash
# Depuis une collection Postman exportée
nevelio scan --target https://api.example.com \
             --spec ./postman-collection.json \
             --accept-legal

# Depuis un export Insomnia
nevelio scan --target https://api.example.com \
             --spec ./insomnia-export.json \
             --accept-legal

# Depuis un fichier HAR capturé via Burp Suite / navigateur
nevelio scan --target https://api.example.com \
             --spec ./burp-traffic.har \
             --accept-legal
```

### Variables Postman

Les variables `{{base_url}}` et `{{ base_url }}` sont résolues automatiquement
à partir du bloc `variable` de la collection. Si `--target` est fourni, il écrase
la valeur résolue.

### Dossiers imbriqués Postman

Les dossiers Postman imbriqués (plusieurs niveaux) sont parcourus récursivement —
tous les endpoints sont extraits quel que soit leur profondeur d'imbrication.

### Filtrage HAR

Les ressources statiques sont exclues automatiquement (`.css`, `.js`, `.png`, `.jpg`,
`.woff`, `.svg`, `.ico`, `.map`) pour ne conserver que les appels API significatifs.

---

## 18. Commande `diff` — Comparaison de scans

```
nevelio diff <before.json> <after.json> [OPTIONS]
```

Compare deux fichiers `findings.json` produits par Nevelio et affiche
les **nouvelles vulnérabilités**, les **vulnérabilités résolues** et les **régresions**.

### Usage

```bash
# Scan de référence (avant déploiement)
nevelio scan --target https://staging.api.example.com \
             --out-dir ./baseline \
             --accept-legal

# Scan post-déploiement
nevelio scan --target https://staging.api.example.com \
             --out-dir ./after-deploy \
             --accept-legal

# Comparer les deux
nevelio diff ./baseline/findings.json ./after-deploy/findings.json
```

### Sortie

```
  ✅ Résolues (2)
     - JWT Algorithm None Accepted  [CRITICAL]
     - CORS Misconfiguration        [HIGH]

  🆕 Nouvelles (1)
     + SQLi détecté sur /api/search  [CRITICAL]

  ━━ Inchangées (4)
```

### Flag `--fail-on`

Retourne un code de sortie non-zéro si des nouvelles vulnérabilités d'une
certaine sévérité ont été introduites — idéal pour bloquer les déploiements CI.

```bash
nevelio diff baseline/findings.json current/findings.json --fail-on high
# Exit code 0 → aucune nouvelle HIGH/CRITICAL
# Exit code 1 → nouvelles vulnérabilités détectées
# Exit code 2 → erreur de lecture des fichiers
```

---

## 19. Commande `watch` — Scan périodique

```
nevelio watch --url <URL> --interval <INTERVAL> [OPTIONS]
```

Lance des scans répétés à intervalles réguliers et envoie une notification
webhook si de nouveaux findings apparaissent entre deux scans.

### Usage

```bash
# Scan toutes les 6 heures, notification Slack sur changement
nevelio watch \
  --url https://api.example.com \
  --interval 6h \
  --webhook https://hooks.slack.com/services/T.../B.../... \
  --accept-legal

# Scan quotidien, seuil minimum MEDIUM pour notifier
nevelio watch \
  --url https://api.example.com \
  --interval 24h \
  --min-severity medium \
  --accept-legal
```

### Intervalles supportés

| Format | Exemple | Description |
|---|---|---|
| `Xm` | `30m` | Toutes les X minutes |
| `Xh` | `6h` | Toutes les X heures |
| `Xd` | `1d` | Tous les X jours |

### Comportement

1. Nevelio lance un premier scan immédiatement au démarrage.
2. Stocke les findings dans `<out-dir>/watch_baseline.json`.
3. À chaque intervalle, relance un scan et compare au baseline.
4. Si de nouveaux findings HIGH/CRITICAL apparaissent → envoie la notification webhook.
5. Met à jour le baseline avec les résultats du dernier scan.

---

## 20. Commande `shell` — REPL interactif

```
nevelio shell [--url <URL>] [OPTIONS]
```

REPL interactif pour explorer et tester une API manuellement, sans relancer
une commande complète à chaque fois.

### Démarrage

```bash
nevelio shell --url https://api.example.com
# nevelio shell> _
```

### Commandes REPL disponibles

| Commande | Description |
|---|---|
| `target <URL>` | Changer l'URL cible |
| `spec <path>` | Charger une spec OpenAPI/Postman/HAR |
| `token <TOKEN>` | Définir le token d'authentification |
| `scan [<module>...]` | Lancer un scan (tous les modules ou sélection) |
| `list` | Lister les endpoints découverts |
| `show <N>` | Afficher le détail du Nème endpoint |
| `findings` | Afficher les findings du dernier scan |
| `replay <N>` | Rejouer la Nème requête du scan |
| `export <format>` | Exporter les findings (`json`/`html`/`sarif`) |
| `help` | Afficher l'aide |
| `exit` / `quit` | Quitter le REPL |

### Exemple de session

```
nevelio shell --url https://api.example.com
nevelio shell> spec ./openapi.yaml
  ✓ 23 endpoints chargés
nevelio shell> token "Bearer eyJhbGciOiJIUzI1NiJ9..."
  ✓ Token défini
nevelio shell> scan auth injection
  ► auth...  2 findings
  ► injection...  1 finding
nevelio shell> findings
  [CRITICAL] JWT Algorithm None Accepted — POST /api/auth/token
  [HIGH]     SQLi détecté — GET /api/search
  [HIGH]     Missing Authentication — GET /api/users
nevelio shell> export html
  ✓ report.html généré
nevelio shell> exit
```

---

## 21. Commande `serve` — Dashboard web

```
nevelio serve [--port <PORT>] [OPTIONS]
```

Lance un serveur HTTP local qui sert le dernier rapport HTML généré
et ouvre automatiquement le navigateur.

### Usage

```bash
# Après un scan (report.html présent)
nevelio serve
# → Ouverture de http://127.0.0.1:3000 dans le navigateur

# Port personnalisé
nevelio serve --port 4000
# → Ouverture de http://127.0.0.1:4000

# Depuis un répertoire de résultats spécifique
nevelio serve --out-dir ./results/2026-06-27
```

### Fonctionnement

1. Charge `<out-dir>/report.html` s'il existe.
2. Sinon, régénère le rapport depuis `<out-dir>/findings.json` à la volée.
3. Ouvre le navigateur automatiquement (`open` macOS, `xdg-open` Linux, `cmd start` Windows).
4. Le serveur reste actif jusqu'à `Ctrl+C`.

> Le rapport HTML est interactif : filtre par sévérité, thème clair/sombre,
> accordéon par finding, recherche instantanée.

---

## 22. Commande `notify` — Alertes Slack/Teams

```
nevelio notify [--slack <URL>] [--teams <URL>] [--webhook <URL>] [OPTIONS]
```

Envoie les findings du dernier scan vers un ou plusieurs canaux de notification.

### Usage

```bash
# Notification Slack
nevelio notify \
  --slack https://hooks.slack.com/services/T.../B.../... \
  --min-severity high

# Notification Teams
nevelio notify \
  --teams https://outlook.office.com/webhook/...

# Les deux + webhook générique JSON
nevelio notify \
  --slack https://hooks.slack.com/... \
  --teams https://outlook.office.com/webhook/... \
  --webhook https://my-alerting-system.example.com/hooks/nevelio \
  --min-severity medium

# Depuis un fichier findings spécifique
nevelio notify \
  --input ./results/findings.json \
  --slack https://hooks.slack.com/...
```

### Options

| Flag | Description |
|---|---|
| `--slack URL` | Incoming Webhook Slack |
| `--teams URL` | Incoming Webhook Teams (MessageCard) |
| `--webhook URL` | Webhook générique JSON (POST) |
| `--min-severity SEV` | Sévérité minimale à notifier (`low`/`medium`/`high`/`critical`) |
| `--input FILE` | Fichier findings.json source (défaut : `./findings.json`) |

### Format Slack

Le message Slack inclut un `attachment` coloré par sévérité (rouge = CRITICAL,
orange = HIGH, jaune = MEDIUM, vert = LOW) avec la liste des findings.

---

## 23. Commande `issue` — Tickets GitHub/Jira

```
nevelio issue github --repo <owner/repo> [OPTIONS]
nevelio issue jira --jira-url <URL> --project <KEY> [OPTIONS]
```

Crée automatiquement des issues/tickets pour chaque finding du dernier scan.
La **déduplication** est intégrée : si un ticket avec le même titre existe déjà
(label `nevelio`), il n'est pas recréé.

### GitHub Issues

```bash
# Créer des issues dans un dépôt GitHub
GITHUB_TOKEN=ghp_... nevelio issue github \
  --repo monorg/mon-api \
  --min-severity high

# Labels ajoutés automatiquement : security, nevelio, severity:critical (etc.)
```

Variables d'environnement :

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` | Personal Access Token avec scope `repo` |

Chaque issue créée reçoit les labels `security`, `nevelio` et `severity:<sev>`.
La déduplication cherche les issues ouvertes avec le label `nevelio` et le même titre.

### Jira Cloud

```bash
# Créer des tickets Jira
nevelio issue jira \
  --jira-url https://monorg.atlassian.net \
  --project SEC \
  --min-severity medium
```

Variables d'environnement :

| Variable | Description |
|---|---|
| `JIRA_EMAIL` | Email du compte Jira (utilisé pour l'auth Basic) |
| `JIRA_API_TOKEN` | Token API Jira Cloud |

La description des tickets est formatée en **ADF** (Atlassian Document Format).
La priorité est mappée automatiquement :

| Sévérité Nevelio | Priorité Jira |
|---|---|
| Critical | Highest |
| High | High |
| Medium | Medium |
| Low | Low |
| Informative | Lowest |

---

## 24. Suppressions de faux positifs

Les règles `[[suppress]]` dans `.nevelio.toml` filtrent les findings
**après le scan**, avant l'écriture des rapports.

### Syntaxe

```toml
[[suppress]]
# Tous les critères sont optionnels et combinés en logique AND.
# Un finding est supprimé si TOUS les critères présents correspondent.
title_contains = "JWT alg:none"      # le titre contient cette chaîne
module = "auth"                       # le module est exactement "auth"
severity = "high"                     # la sévérité en minuscules
endpoint_prefix = "/public/"          # l'URL commence par ce préfixe
reason = "Commentaire libre"          # ignoré par le moteur de suppression
```

### Exemple complet

```toml
# .nevelio.toml

target = "https://api.example.com"
profile = "normal"

# Supprimer les findings infra informatifs (monitoring accepté)
[[suppress]]
module = "infra"
severity = "informative"
reason = "endpoints /health et /metrics acceptés par la politique"

# Supprimer les warnings JWT sur les endpoints publics (pas d'auth requise)
[[suppress]]
title_contains = "JWT"
endpoint_prefix = "/public/"
reason = "endpoints publics — authentification non requise"

# Supprimer un finding très spécifique
[[suppress]]
title_contains = "CORS Misconfiguration"
endpoint_prefix = "/internal/healthz"
reason = "CORS permissif intentionnel pour le monitoring interne"
```

### Comptage

Après le scan, Nevelio affiche le nombre de findings supprimés :

```
  ↩ 3 finding(s) supprimé(s).
```

---

## 25. Scripting Rhai (`--script`)

> Voir aussi §4.9 pour la référence rapide des flags.

Le scripting Rhai permet un filtrage **programmatique** des findings,
complémentaire aux règles `[[suppress]]` déclaratives.

### Différence avec `[[suppress]]`

| | `[[suppress]]` | `--script` |
|---|---|---|
| Format | TOML déclaratif | Script Rhai |
| Logique | AND simple | Arbitrairement complexe |
| Variables | 4 champs fixes | 7 variables + expressions |
| Cas d'usage | Suppressions simples et lisibles | Filtres conditionnels, scores CVSS, regex |

### Exemple avancé

```rhai
// Conserver uniquement les findings CRITICAL et HIGH
// OU les findings MEDIUM avec CVSS > 6.5
if severity == "Critical" || severity == "High" {
    true
} else if severity == "Medium" && cvss > 6.5 {
    true
} else {
    false
}
```

```rhai
// Exclure les endpoints de monitoring
!endpoint.contains("/health") && !endpoint.contains("/metrics") && !endpoint.contains("/actuator")
```

### Chargement de scripts

Les scripts sont lus depuis le disque à l'initialisation du scan.
Un chemin invalide provoque une erreur avant le démarrage du scan.

```bash
nevelio scan --target https://api.example.com \
             --script ./filtres/seuil-cvss.rhai \
             --script ./filtres/no-monitoring.rhai \
             --accept-legal
```

Les scripts sont appliqués dans l'ordre spécifié. Pour qu'un finding soit conservé,
il doit passer **tous** les scripts (logique AND entre scripts).

---

## Extension Hardware Security (`nevelio-hw`)

En complément du scanner API, l'extension `nevelio-hw` audite les vulnérabilités
au niveau matériel, firmware, noyau et canaux auxiliaires.

```bash
# Depuis hardware/
make install-deps
make

# Audit passif (sans root)
./target/release/nevelio-hw scan --accept-legal

# Rapport compatible nevelio
./target/release/nevelio-hw scan --accept-legal --output nevelio-json
```

**Modules disponibles (v0.6.0) :**

| Module | Couverture |
|---|---|
| `hw-cpu` | Spectre, Meltdown, Retbleed, microcode, NX/SMEP/SMAP |
| `hw-firmware` | Secure Boot, flashrom, mises à jour BIOS |
| `hw-dma` | IOMMU/VT-d, Thunderbolt, PCIe |
| `hw-sidechannel` | Timing oracle, Flush+Reload, AES-NI |
| `hw-jtag` | Sondes JTAG/UART, STM32 RDP, firmware (binwalk+angr) |
| `hw-memory` | Rowhammer, ECC, swap, KASLR, Volatility forensics |
| `hw-dma-fpga` | leechcore FFI, Verilog TLP, IOMMU strict |

**Internationalisation (i18n) :**

Tous les messages de findings sont traduits via `rust-i18n v3`. La langue suit le
flag `--lang` global de `nevelio-hw` (`fr` par défaut, `en`, `es` disponibles) :

```bash
./target/release/nevelio-hw scan --lang en --accept-legal
./target/release/nevelio-hw scan --lang es --accept-legal
```

Les locales YAML sont dans `hardware/crates/hw-cli/locales/`. Chaque crate bibliothèque
déclare `rust_i18n::i18n!("../hw-cli/locales", fallback = "fr")` dans son `lib.rs`
pour résoudre les clés dans le scope du crate.

Voir [hardware-security-extensions.md](hardware-security-extensions.md) pour la documentation complète,
[hardware/INSTALL.md](../hardware/INSTALL.md) pour l'installation,
[hardware/LEGAL.md](../hardware/LEGAL.md) pour les obligations légales.

---

*Généré pour Nevelio v0.6 — Scanner d'API de sécurité*
