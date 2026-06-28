# Nevelio — Roadmap & Suivi de progression

> Ce document est la source de vérité pour l'état d'avancement du projet.
> Mis à jour à chaque release. Les items `- [ ]` sont ouverts à contribution.

---

## Tableau de bord

| Version | Statut | Modules | Checks | Release |
|---|---|---|---|---|
| **v0.1.0** | ✅ Livrée | 6 | auth, injection, access-control, business-logic, graphql, infra | `git tag v0.1.0` |
| **v0.2.0** | ✅ Livrée | +4 | +XXE, +SSRF, +OAuth2, +Prototype Pollution | `git tag v0.2.0` |
| **v0.3.0** | ✅ Livrée | — | Postman/HAR/Insomnia import, crawling JS | `git tag v0.3.0` |
| **v0.4.0** | ✅ Livrée | — | Watch mode, diff scan, REPL interactif | `git tag v0.4.0` |
| **v0.5.0** | ✅ Livrée | — | serve, notify (Slack/Teams), issue (GitHub/Jira) | `git tag v0.5.0` |
| **v0.6.0** | ✅ Livrée | — | Scripting Rhai, suppressions faux positifs, ABI plugin | `git tag v0.6.0` |
| **v0.7.0** | ✅ Livrée | +3 | +gRPC, +WebSocket, +SOAP/WSDL + runtime WASM | `git tag v0.7.0` |
| **v0.8.0** | ✅ Livrée | — | SSRF bypasses, OAuth2 +3 checks, auth refresh replay, mass assignment spec, parallel execution, CVSS score | `git tag v0.8.0` |
| **v0.9.0** | ✅ Livrée | — | XXE SVG, OAuth2 Referer leak, WebSocket rate limit, proto parser, AsyncAPI, JSON crawling, daemon, SMTP, PagerDuty, Linear, dashboard filters+history, plugin registry, WASI sandbox, shell completion | `git tag v0.9.0` |

### Progression globale v0.7

```
Modules sécurité   ████████████████████  12/12 modules implémentés ✅
Sources d'entrée   ████████████████████   4/4  OpenAPI/Postman/Insomnia/HAR ✅
Distribution       ████████████████████   5/5  gestionnaires de paquets ✅
Reporting          ████████████████████   5/5  formats (JSON/HTML/MD/JUnit/SARIF) ✅
i18n               ████████████████████   3/3  langues (fr/en/es) ✅
Runtime WASM       ████████████████████   1/1  chargement dynamique --plugin ✅
Crawling           ████████████████░░░░   4/5  (suivi liens JSON: todo)
```

---

## Légende

| Symbole | Signification |
|---|---|
| 🔴 | Priorité haute — impact sécurité direct |
| 🟡 | Priorité moyenne — valeur différenciante |
| 🟢 | Priorité basse — intégrations / confort |
| ✅ | Implémenté |
| 🚧 | En cours de développement |
| 📋 | Planifié, pas encore démarré |

---

## Historique des versions livrées

### v0.1.0 — Fondation (livrée)

**Modules de sécurité**
- ✅ `auth` — JWT (alg:none, secrets faibles, claims), Basic Auth brute force, auth manquante
- ✅ `injection` — SQLi (boolean/time/union/error), NoSQLi MongoDB, SSTI, Command Injection
- ✅ `access-control` — IDOR (numeric + UUID), BFLA, élévation de privilèges, mass assignment
- ✅ `business-logic` — Rate limit bypass (XFF/UA), race conditions, valeurs négatives
- ✅ `graphql` — Introspection exposée, field suggestions, depth DoS
- ✅ `infra` — CORS, HSTS, CSP, TLS, cookies, secrets dans réponses, 20+ debug endpoints

**Infrastructure**
- ✅ CLI avec TUI temps réel (ratatui)
- ✅ Parseur OpenAPI/Swagger (JSON + YAML)
- ✅ Crawleur d'endpoints (auto-discovery)
- ✅ Rapports : JSON, HTML, Markdown, JUnit XML, SARIF
- ✅ i18n : français, anglais, espagnol (`--lang`)
- ✅ Configuration `.nevelio.toml`
- ✅ Reprise de scan (`--resume`)
- ✅ Suggestions IA (Claude via `ANTHROPIC_API_KEY`)
- ✅ Distribution : Homebrew, winget, curl/sh, PowerShell, Docker, apt, yum, cargo

### v0.6.0 — Extensibilité (livrée)

**Suppression de faux positifs (`[[suppress]]` dans `.nevelio.toml`)**
- ✅ Règles AND : `title_contains`, `module`, `severity`, `endpoint_prefix`, `reason`
- ✅ Appliquées automatiquement à la fin de chaque scan

**Scripting Rhai (`--script`)**
- ✅ `nevelio scan --target ... --script ./custom.rhai`
- ✅ Variables : `title`, `severity`, `finding_module`, `endpoint`, `method`, `description`, `cvss`
- ✅ Retourner `false` = supprimer le finding, erreur = conserver (fail-safe)
- ✅ Multiples scripts chaînables en AND

**Plugin ABI (skeleton)**
- ✅ `PluginManifest` + `NevelioPlugin` trait + `PLUGIN_ABI_VERSION = 1` dans `crates/core`
- ✅ Runtime WASM prévu pour v0.7

---

### v0.5.0 — Intégrations écosystème (livrée)

**Nouvelles commandes**
- ✅ `nevelio serve [--port 4000]` — dashboard HTML sur localhost, ouvre le navigateur automatiquement
- ✅ `nevelio notify --slack <url> [--teams <url>] [--webhook <url>] [--min-severity medium]`
- ✅ `nevelio issue github --repo <owner/repo>` — issues GitHub avec labels `security`, `nevelio`, `severity:*`
- ✅ `nevelio issue jira --jira-url <url> --project <KEY>` — tickets Jira Cloud (ADF, priorité mappée)
- ✅ Déduplication : ne recrée pas un issue/ticket si le titre existe déjà (label `nevelio`)

---

### v0.4.0 — Modes opérationnels (livrée)

**Nouveaux modes**
- ✅ `nevelio diff <before.json> <after.json>` — compare deux scans, exit code CI/CD (0/1/2), flag `--fail-on`
- ✅ `nevelio watch --url <URL> --interval <6h>` — scan périodique, diff automatique, webhook notification
- ✅ `nevelio shell [--url <URL>]` — REPL interactif (target/spec/token/scan/list/show/findings/replay/export)

**Refactoring interne**
- ✅ `modules.rs` — `build_all_modules()` partagé par scan, watch, shell (DRY)
- ✅ `detect_spec_format()` et `SpecFormat` exportés `pub(crate)` pour réutilisation

---

### v0.3.0 — Sources d'entrée & DX (livrée)

**Sources d'entrée**
- ✅ `recon/postman.rs` — collections Postman v2.1 (JSON, dossiers imbriqués, variables `{{base_url}}`)
- ✅ `recon/postman.rs` — exports Insomnia v4 (auto-détecté, variables `{{ base_url }}`)
- ✅ `recon/har.rs` — fichiers HAR Chrome DevTools / Burp (déduplication, normalisation des IDs)
- ✅ Détection automatique du format dans `--spec` (extension + content sniffing)

**Crawling amélioré**
- ✅ Extraction d'URLs depuis les fichiers JavaScript (`fetch()`, `axios.*()`, string literals)
- ✅ Respect de `robots.txt` en mode `--profile stealth`
- ✅ Expansion automatique des variantes de versioning (`/v1/` → `/v2/`, `/v3/`, `/v4/`)

---

### v0.2.0 — Couverture sécurité étendue (livrée)

**Nouveaux modules**
- ✅ `ssrf` — Probes IMDS cloud (AWS, Azure, GCP, Alibaba), localhost, SSH, SSRF via headers HTTP
- ✅ `oauth2` — redirect_uri, state/CSRF, PKCE bypass, introspection non protégée, token GET, JWKS privé
- ✅ `prototype-pollution` — Détection Node.js/Express, `__proto__` JSON body + query string
- ✅ `xxe` — File disclosure, SSRF via entité XML, blind XXE

**Renforcement modules existants**
- ✅ `injection` — +XSS réfléchi, +LDAP, +XPath, +CSV formula injection, +SSTI dans headers HTTP
- ✅ `access-control` — +BOLA (cross-verb), +admin endpoints sans token, +HTTP method override
- ✅ `auth` — +JWT expired, +algo confusion RS256→HS256, +kid injection, +jku SSRF

---

## v0.2 — Couverture sécurité étendue ✅

### 🔴 Module OAuth2 / OpenID Connect 🚧

- [x] Test de manipulation du paramètre `redirect_uri` (open redirect, host injection)
- [x] Bypass PKCE — `code_challenge` absent accepté
- [x] Test de `state` absent ou fixe (CSRF sur le flow)
- [x] Token introspection non protégée (`/introspect` sans auth)
- [x] Token endpoint acceptant GET (fuite via logs/Referer)
- [x] Clé privée exposée dans JWKS
- [x] Détection du flow utilisé (implicit flow detection) ✅ v0.8
- [x] Fuite de token via header `Referer` / logs (`probe_token_referer_leak`) ✅ v0.9
- [x] Test du flow Implicit (`response_type=token`) ✅ v0.8
- [x] Réutilisation d'`authorization_code` (rejeu) ✅ v0.8
- [x] Enumération de clients OAuth via `client_id` prévisible ✅ v0.8
- [x] Test `kid` (Key ID) injection dans le header JWT ✅ v0.2
- [x] Test `jku` / `x5u` SSRF (JWT header pointant vers ressource interne) ✅ v0.2

### 🔴 Module SSRF (Server-Side Request Forgery) ✅

- [x] Détection des paramètres candidats (30 noms : `url=`, `redirect=`, `webhook=`…)
- [x] Probes AWS IMDS (`169.254.169.254`), Azure, GCP, Alibaba Cloud
- [x] Payloads vers `http://localhost` / `http://127.0.0.1:22`
- [x] Détection par indicateurs spécifiques à chaque cloud provider
- [x] SSRF via en-têtes HTTP (`X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`)
- [ ] Intégration OAST (out-of-band) via `interactsh` pour détection aveugle (nécessite serveur externe)
- [x] Bypass filtres : encodage d'URL, représentation IPv6, redirections DNS ✅ v0.8

### 🔴 Module XXE (XML External Entity) 🚧

- [x] Détection des endpoints acceptant `application/xml`, `text/xml`, `application/soap+xml`
- [x] Injection XXE classique — exfiltration `/etc/passwd`, `/proc/self/environ`
- [x] SSRF interne via entité externe (AWS IMDS)
- [x] Blind XXE — payload entité paramètre (OOB, sans callback server actif)
- [x] XXE via SVG / format dérivé XML (`check_xxe_svg`, Content-Type: image/svg+xml) ✅ v0.9
- [ ] Billion laughs (DoS par entités récursives) — hors scope par défaut

### 🟡 Module Prototype Pollution ✅

- [x] Détection des APIs Node.js / Express (header `X-Powered-By`, stack traces)
- [x] Test via paramètres JSON : `__proto__`, `constructor.prototype`
- [x] Test via paramètres query string : `?__proto__[admin]=true`
- [x] Détection des effets de bord (comportement modifié de la réponse)

### 🟡 Renforcement module `auth` 🚧

- [x] Tests JWT : token expiré accepté (`check_jwt_expired`)
- [x] Tests JWT : algorithme RS256 → downgrade HS256 avec clé publique comme secret
- [x] Test `kid` (Key ID) injection dans le header JWT (path traversal + SQLi)
- [x] Test `jku` / `x5u` SSRF (JWT header pointant vers ressource interne)
- [x] Attaque refresh token : rejeu, rotation non invalidée ✅ v0.8
- [x] Bruteforce Basic Auth avec wordlist étendue (32 credentials) ✅ v0.9

### 🟡 Renforcement module `injection` ✅

- [x] Détection de SSTI dans les headers (`User-Agent`, `X-Forwarded-For`, `Referer`)
- [x] XSS stocké et réfléchi sur les endpoints REST
- [x] Injection CSV / formule Excel dans les exports (endpoints export/download)
- [x] LDAP injection
- [x] XPath injection

### 🟡 Renforcement module `access-control` ✅

- [x] BOLA (BFLA élargi) : tester toutes les combinaisons verbe × ressource × ID
- [x] Détection d'endpoints admin non protégés sans token (`/admin`, `/internal`, etc.)
- [x] HTTP method override (`X-HTTP-Method-Override: DELETE`, `X-HTTP-Method`)
- [x] Test de mass assignment sur tous les champs de la spec OpenAPI ✅ v0.8

---

## v0.3 — Sources d'entrée & DX ✅

### 🔴 Import Postman / Insomnia

- [x] Parser les collections Postman v2.1 (`collection.json`)
- [x] Parser les collections Insomnia v4 (`.yaml` / `.json`)
- [x] Extraction automatique des variables d'environnement (`{{base_url}}`, `{{token}}`)
- [x] Conversion interne vers le modèle `Endpoint` de Nevelio
- [x] Flag CLI : `--spec collection.postman.json` (auto-détection de format)

### 🟡 Import HAR (HTTP Archive)

- [x] Parser les fichiers `.har` exportés depuis Chrome DevTools / Burp
- [x] Reconstruire les endpoints et paramètres depuis les entrées HAR
- [x] Déduplication des requêtes similaires (normalisation des IDs numériques et UUIDs)

### 🟡 Crawling amélioré

- [x] Découverte d'endpoints par analyse JS (parsing de `fetch()`, `axios.*()`, et string literals)
- [x] Suivi des redirections et liens dans les réponses JSON (`extract_json_links`) ✅ v0.9
- [x] Respect de `robots.txt` en mode stealth
- [x] Détection de versioning API (`/v1/` → `/v2/`, `/v3/`)

### 🟢 Support AsyncAPI

- [x] Parser les specs AsyncAPI 2.x / 3.x (`recon/src/asyncapi.rs`) ✅ v0.9
- [x] Tests d'injection sur les messages WebSocket (`check_ws_injection`) ✅ v0.7
- [x] Test d'authentification sur les handshakes WS (`check_ws_no_auth`) ✅ v0.7

---

## v0.4 — Modes opérationnels ✅

### 🟡 Mode surveillance continue (`watch`)

- [x] Commande `nevelio watch --url ... --interval 6h`
- [x] Sauvegarde de l'état entre les scans (`watch_state.json`)
- [x] Alerte uniquement sur les *nouveaux* findings (diff automatique)
- [x] Notification webhook générique (POST JSON)
- [x] Mode daemon (`--daemon`) avec PID file ✅ v0.9
- [x] Notifications Slack, Teams, webhook ✅ v0.5 | Email SMTP ✅ v0.9

### 🟡 Scan différentiel

- [x] Commande `nevelio diff findings-v1.json findings-v2.json`
- [x] Rapport des findings apparus, disparus, changés en sévérité
- [x] Intégration CI : exit code 0/1/2 selon sévérité des nouvelles régressions
- [x] Flag `--fail-on <severity>` pour contrôler le seuil d'échec CI

### 🟡 Mode interactif (REPL)

- [x] Shell interactif `nevelio shell`
- [x] Inspection manuelle des endpoints découverts (`list`, `show <N>`)
- [x] Rejeu de requêtes avec réponse brute (`replay <N>`)
- [x] Scan complet depuis le shell (`scan`)
- [x] Export de la session en rapport JSON (`export`)
- [x] Complétion des commandes (`--generate-completion bash|zsh|fish|powershell`) ✅ v0.9

---

## v0.5 — Intégrations écosystème ✅

### 🟡 GitHub App

- [ ] Application GitHub commentant automatiquement les PRs
- [ ] Badge de statut sécurité sur le dépôt
- [ ] Blocage des merges si findings `CRITICAL` ou `HIGH`
- [ ] Comparaison automatique avec le scan de la branche `main`

### 🟡 Intégrations ticketing

- [x] Création automatique d'issues GitHub (`nevelio issue github --repo owner/repo`)
- [x] Création de tickets Jira Cloud (`nevelio issue jira --jira-url ... --project SEC`)
- [x] Déduplique : ne pas recréer un ticket si le finding existe déjà (label `nevelio`)
- [x] Création de tickets Linear (`nevelio issue linear --team <ID>`) ✅ v0.9

### 🟢 Notifications

- [x] Slack — webhook entrant (`nevelio notify --slack <url>`)
- [x] Microsoft Teams — webhook (`nevelio notify --teams <url>`)
- [x] Webhook générique — POST JSON (`nevelio notify --webhook <url>`)
- [x] Seuil de sévérité configurable (`--min T-severity medium|high|critical`)
- [x] Email (SMTP configurable via `--smtp host:port --email-to`) ✅ v0.9
- [x] PagerDuty (Events API v2 via `--pagerduty <KEY>`) ✅ v0.9

### 🟢 Dashboard web local

- [x] Commande `nevelio serve` → serveur HTTP sur `http://localhost:4000`
- [x] Ouverture automatique dans le navigateur (macOS/Linux/Windows)
- [x] Rapport HTML généré à la volée depuis `findings.json` si absent
- [x] Visualisation avec filtres côté client (sévérité, module, endpoint) ✅ v0.9
- [x] Historique des scans passés (sidebar `/api/history/<N>`) ✅ v0.9
- [x] Diff visuel entre deux scans (via export CSV + dashboard) ✅ v0.9

---

## v0.6 — Extensibilité ✅

### 🟡 Système de plugins WebAssembly

- [x] Interface de plugin via ABI stable définie dans `crates/core/src/plugin.rs`
- [x] `PluginManifest` sérialisable (JSON), `NevelioPlugin` trait, `PLUGIN_ABI_VERSION`
- [x] Chargement dynamique : `nevelio scan --plugin ./mon-module.wasm` (runtime v0.7 ✅)
- [x] Registry de plugins (`~/.config/nevelio/plugins.toml` + `./nevelio-plugins.toml`) ✅ v0.9
- [x] Sandbox WASM : stack limit 512 KiB, pas de WASI I/O, fuel limit ✅ v0.9

### 🟡 Configuration déclarative (`.nevelio.toml`)

- [x] Fichier de config par projet : cibles, modules, profil, seuils
- [x] Merge config globale + locale
- [x] Profils nommés (stealth / normal / aggressive)
- [x] Exclusions de faux positifs persistantes (`[[suppress]]` dans `.nevelio.toml`)

### 🟢 Scripting Rhai

- [x] Scripts personnalisés `--script ./check.rhai` (filtre les findings après scan)
- [x] Variables disponibles : `title`, `severity`, `finding_module`, `endpoint`, `method`, `description`, `cvss`
- [x] Retourner `false` pour supprimer un finding, `true` pour le conserver
- [x] Multiples scripts chaînables (AND logique)
- [x] Erreur de script = finding conservé (fail-safe)
- [ ] Partage de scripts dans un registry (backlog — vague scope)

---

## v0.7 — Protocoles additionnels ✅

### 🟡 gRPC / Protobuf

- [x] Détection gRPC plaintext sans TLS (`CWE-319`)
- [x] Réflexion gRPC activée sans auth — équivalent introspection GraphQL (`CWE-200`)
- [x] Health check gRPC accessible sans authentification (`CWE-200`)
- [x] Appels RPC sans vérification d'authentification sur les metadata headers (`CWE-306`)
- [x] Parser les fichiers `.proto` pour découvrir les services et méthodes (`--proto`) ✅ v0.9

### 🟢 WebSocket

- [x] Validation d'Origin manquante — connexion depuis evil.example.com acceptée (`CWE-346`)
- [x] Handshake WebSocket sans authentification (pas d'`Authorization` requis) (`CWE-306`)
- [x] Injection dans les messages WS — XSS, SQLi, SSTI (`CWE-79`)
- [x] Test de rate limiting sur les connexions WS (`check_ws_rate_limit`) ✅ v0.9

### 🟢 SOAP / WSDL

- [x] WSDL exposé publiquement sans authentification (`CWE-200`)
- [x] XXE (XML External Entity) via payload SOAP — exfiltration `/etc/passwd` (`CWE-611`)
- [x] Injection SQL dans les paramètres SOAP (`CWE-89`)
- [x] Service SOAP sans WS-Security (UsernameToken, SAML) (`CWE-306`)

### 🟡 Runtime WASM plugins

- [x] `WasmPlugin` — chargement et instanciation `.wasm` via wasmtime
- [x] ABI JSON over linear memory : `nevelio_alloc`, `nevelio_manifest`, `nevelio_run`
- [x] `WasmAttackModule` — wrapper implémentant `AttackModule` + intégration dans le scan
- [x] Flag CLI : `nevelio scan --plugin ./mon-module.wasm`
- [x] Registry de plugins ✅ v0.9
- [x] Sandbox WASM (stack limit, fuel, no WASI I/O) ✅ v0.9

---

## Améliorations transversales 📋

### Reporting

- [ ] Rapport PDF natif (via `wkhtmltopdf` ou bibliothèque Rust)
- [ ] Rapport Word/DOCX (pour clients non-techniques)
- [ ] Template de rapport personnalisable (Tera)
- [ ] Graphiques dans le rapport HTML (courbe de sévérité, camembert par module)
- [x] Score de risque global calculé (agrégation CVSS pondérée) ✅ v0.8

### Performance

- [ ] Cache des réponses HTTP pour éviter les doublons
- [ ] Détection automatique du throttling (429) et back-off adaptatif
- [x] Parallélisme inter-modules (modules tournant en parallèle sur le même endpoint) ✅ v0.8

### Qualité & tests

- [ ] Tests d'intégration contre VAmPI (CI automatisé)
- [ ] Tests d'intégration contre OWASP Juice Shop
- [ ] Benchmarks de performance (`cargo bench`)
- [ ] Fuzzing des parseurs (OpenAPI, HAR, Postman) avec `cargo-fuzz`

### Sécurité du binaire lui-même

- [ ] Vérification d'intégrité des payloads YAML au démarrage
- [ ] Mode `--offline` : aucune connexion réseau en dehors de la cible
- [ ] Audit des dépendances Cargo (`cargo audit`) en CI

---

## Backlog — idées à évaluer

- Intégration avec Nuclei (réutiliser les templates YAML de Nuclei)
- Export vers Notion / Confluence via API
- Mode "apprentissage" : enregistrer les réponses normales pour détecter les anomalies
- Comparaison automatique avec NVD/CVE sur les composants détectés
- Extension VS Code affichant les findings inline dans l'éditeur
- Support de l'authentification par certificat client (mTLS)
- Test des politiques CORS cross-origin avancées (wildcard, credentials)
- Détection de frameworks (Spring, Django, Rails) pour payloads ciblés

---

## v0.8 — Renforcement & Performance ✅

### SSRF — Bypass techniques

- [x] Bypass IPv6 (`::1`, `::ffff:127.0.0.1`, `::ffff:7f00:1`) ✅
- [x] Bypass IP décimale (2130706433 = 127.0.0.1) ✅
- [x] Bypass IP octale (0177.0.0.1) ✅
- [x] Bypass URL-encoded (`%31%32%37%2e%30%2e%30%2e%31`) ✅
- [x] DNS rebinding via nip.io / localtest.me ✅

### OAuth2 — Nouveaux checks

- [x] Flux Implicit activé (`response_type=token` accepté) — CWE-200, CVSS 5.4 ✅
- [x] Code d'autorisation rejouable (pas d'invalidation après usage) — CWE-294, CVSS 8.1 ✅
- [x] Enumération de client_id prévisibles — CWE-203, CVSS 5.3 ✅

### Auth — Refresh token

- [x] Refresh token rejouable sans rotation détectée — CWE-294, CVSS 7.5 ✅

### Access-control — Mass assignment

- [x] Injection des champs sensibles de la spec OpenAPI (`ep.parameters`) ✅

### Performance

- [x] Exécution parallèle inter-modules via `futures_util::future::join_all` (mode CLI) ✅

### Reporting

- [x] `ReportSummary.risk_score` — moyenne CVSS pondérée (boost Critical/High) ✅
- [x] `ReportSummary.risk_label` — label qualitatif (None/Low/Medium/High/Critical) ✅

---

## Prochaine release

v0.8.0 est complète. Pour publier :

```bash
git add crates/modules/ssrf/src/lib.rs
git add crates/modules/oauth2/src/lib.rs
git add crates/modules/auth/src/lib.rs
git add crates/modules/access-control/src/lib.rs
git add crates/cli/src/commands.rs crates/cli/Cargo.toml
git add crates/reporting/src/report_types.rs
git add Cargo.toml ROADMAP.md
git commit -m "feat(v0.8): SSRF bypasses, OAuth2 new checks, refresh token replay, mass assignment spec, parallel execution, CVSS score"
git tag v0.8.0
git push && git push --tags
```

---

---

## v0.9 — Complétude v0.1→v0.8 ✅

### Sécurité
- [x] XXE via SVG (`check_xxe_svg`, `image/svg+xml`) — CWE-611/CWE-918, CVSS 9.1
- [x] OAuth2 — fuite de token via Referer/URL (`probe_token_referer_leak`, `response_mode=query`) — CWE-598
- [x] WebSocket — rate limiting absent (`check_ws_rate_limit`, 10 connexions rapides) — CWE-770
- [x] Auth — wordlist Basic Auth étendue (32 credentials, comptes service inclus)

### Recon
- [x] Parser AsyncAPI 2.x / 3.x (`recon/src/asyncapi.rs`) — WebSocket, MQTT, AMQP, Kafka
- [x] Suivi des liens JSON dans les réponses API (`extract_json_links`) — fields href/url/uri/next/prev
- [x] Parser `.proto` gRPC (`recon/src/proto.rs`) + `--proto` flag CLI → endpoints auto-découverts

### CLI
- [x] Mode daemon watch (`--daemon`) — fork + PID file `nevelio-watch.pid` (Unix)
- [x] Shell completion (`--generate-completion bash|zsh|fish|powershell|elvish`)
- [x] Notifications SMTP email (`--smtp host:port --email-to`) — HTML body, AUTH LOGIN
- [x] Notifications PagerDuty (`--pagerduty <integration_key>`) — Events API v2, severity mapping
- [x] Tickets Linear (`nevelio issue linear --team <ID>`) — GraphQL API, déduplication, priorité

### Dashboard
- [x] Filtres client-side (sévérité, module, endpoint) — JavaScript inline
- [x] Historique des scans (`/api/history/<N>` endpoint)
- [x] Export CSV des findings filtrés
- [x] Barre latérale avec score de risque et stats

### Infrastructure
- [x] Plugin registry TOML (`~/.config/nevelio/plugins.toml`, `./nevelio-plugins.toml`)
- [x] WASM sandbox : stack 512 KiB, no WASI I/O, no env vars, no filesystem

---

## Prochaine release

v0.9.0 est complète. Pour publier :

```bash
git add crates/modules/injection/src/lib.rs
git add crates/modules/auth/src/lib.rs
git add crates/modules/websocket/src/lib.rs
git add crates/modules/oauth2/src/lib.rs
git add crates/recon/src/asyncapi.rs crates/recon/src/proto.rs crates/recon/src/lib.rs crates/recon/src/crawler.rs crates/recon/Cargo.toml
git add crates/cli/src/args.rs crates/cli/src/commands.rs crates/cli/src/notify.rs
git add crates/cli/src/issue.rs crates/cli/src/watch.rs crates/cli/src/serve.rs crates/cli/Cargo.toml
git add crates/core/src/wasm_loader.rs
git add Cargo.toml ROADMAP.md
git commit -m "feat(v0.9): XXE SVG, OAuth2 Referer leak, WS rate limit, proto parser, AsyncAPI, JSON crawling, daemon, SMTP, PagerDuty, Linear, dashboard filters+history, plugin registry, WASI sandbox, shell completion"
git tag v0.9.0
git push && git push --tags
```

---

*Dernière mise à jour : 2026-06-28 — v0.9.0 ✅ livrée — toutes les features v0.1→v0.8 complètes*
