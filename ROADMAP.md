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
| **v0.5.0** | 📋 Planifiée | — | GitHub App, Jira, dashboard web | — |
| **v0.6.0** | 📋 Planifiée | — | Plugins WASM, scripting | — |
| **v0.7.0** | 📋 Planifiée | — | gRPC, WebSocket, SOAP | — |

### Progression globale v0.3

```
Modules sécurité   ████████████████████  9/9  modules implémentés ✅
Sources d'entrée   ████████████████████  4/4  OpenAPI/Postman/Insomnia/HAR ✅
Distribution       ████████████████████  5/5  gestionnaires de paquets ✅
Reporting          ████████████████████  5/5  formats (JSON/HTML/MD/JUnit/SARIF) ✅
i18n               ████████████████████  3/3  langues (fr/en/es) ✅
Crawling           ████████████████░░░░  4/5  (suivi liens JSON: todo)
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
- [ ] Détection du flow utilisé (Authorization Code, Implicit, Client Credentials)
- [ ] Fuite de token via header `Referer` / logs (test actif)
- [ ] Test du flow Implicit (token dans URL fragment)
- [ ] Réutilisation d'`authorization_code` (rejeu)
- [ ] Enumération de clients OAuth via `client_id` prévisible
- [ ] Test `kid` (Key ID) injection dans le header JWT
- [ ] Test `jku` / `x5u` SSRF (JWT header pointant vers clé distante)

### 🔴 Module SSRF (Server-Side Request Forgery) ✅

- [x] Détection des paramètres candidats (30 noms : `url=`, `redirect=`, `webhook=`…)
- [x] Probes AWS IMDS (`169.254.169.254`), Azure, GCP, Alibaba Cloud
- [x] Payloads vers `http://localhost` / `http://127.0.0.1:22`
- [x] Détection par indicateurs spécifiques à chaque cloud provider
- [x] SSRF via en-têtes HTTP (`X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`)
- [ ] Intégration OAST (out-of-band) via `interactsh` pour détection aveugle
- [ ] Bypass filtres : encodage d'URL, représentation IPv6, redirections DNS -

### 🔴 Module XXE (XML External Entity) 🚧

- [x] Détection des endpoints acceptant `application/xml`, `text/xml`, `application/soap+xml`
- [x] Injection XXE classique — exfiltration `/etc/passwd`, `/proc/self/environ`
- [x] SSRF interne via entité externe (AWS IMDS)
- [x] Blind XXE — payload entité paramètre (OOB, sans callback server actif)
- [ ] XXE via SVG / DOCX / format dérivé XML
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
- [ ] Attaque refresh token : rejeu, rotation non invalidée
- [ ] Bruteforce Basic Auth multithread avec wordlist configurable

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
- [ ] Test de mass assignment sur tous les champs de la spec OpenAPI

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
- [ ] Suivi des redirections et liens dans les réponses JSON
- [x] Respect de `robots.txt` en mode stealth
- [x] Détection de versioning API (`/v1/` → `/v2/`, `/v3/`)

### 🟢 Support AsyncAPI

- [ ] Parser les specs AsyncAPI 2.x / 3.x (WebSocket, MQTT, Kafka)
- [ ] Tests d'injection sur les messages WebSocket
- [ ] Test d'authentification sur les handshakes WS

---

## v0.4 — Modes opérationnels ✅

### 🟡 Mode surveillance continue (`watch`)

- [x] Commande `nevelio watch --url ... --interval 6h`
- [x] Sauvegarde de l'état entre les scans (`watch_state.json`)
- [x] Alerte uniquement sur les *nouveaux* findings (diff automatique)
- [x] Notification webhook générique (POST JSON)
- [ ] Mode daemon (`--daemon`) avec PID file
- [ ] Notifications Slack, Teams, email

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
- [ ] Complétion des commandes

---

## v0.5 — Intégrations écosystème 📋

### 🟡 GitHub App

- [ ] Application GitHub commentant automatiquement les PRs
- [ ] Badge de statut sécurité sur le dépôt
- [ ] Blocage des merges si findings `CRITICAL` ou `HIGH`
- [ ] Comparaison automatique avec le scan de la branche `main`

### 🟡 Intégrations ticketing

- [ ] Création automatique d'issues GitHub pour chaque finding
- [ ] Création de tickets Jira (API REST Jira Cloud)
- [ ] Création de tickets Linear
- [ ] Déduplique : ne pas recréer un ticket si le finding existe déjà

### 🟢 Notifications

- [ ] Slack (webhook entrant)
- [ ] Microsoft Teams (webhook)
- [ ] Email (SMTP configurable)
- [ ] Webhook générique (payload JSON POST)
- [ ] PagerDuty (pour les findings CRITICAL en production)

### 🟢 Dashboard web local

- [ ] Commande `nevelio serve` → interface sur `http://localhost:4000`
- [ ] Visualisation des findings avec filtres (sévérité, module, endpoint)
- [ ] Historique des scans passés
- [ ] Diff visuel entre deux scans
- [ ] Export PDF depuis l'interface

---

## v0.6 — Extensibilité 📋

### 🟡 Système de plugins WebAssembly

- [ ] Interface de plugin via WASM (ABI stable défini dans `core`)
- [ ] Chargement dynamique : `nevelio --plugin ./mon-module.wasm scan ...`
- [ ] Registry de plugins (similaire à crates.io mais pour les modules Nevelio)
- [ ] Sandbox sécurisée (pas d'accès filesystem ni réseau non autorisé)
- [ ] Documentation d'écriture de plugin

### 🟡 Configuration déclarative (`.nevelio.toml`)

- [x] Fichier de config par projet : cibles, modules, profil, seuils
- [x] Merge config globale + locale
- [x] Profils nommés (stealth / normal / aggressive)
- [ ] Exclusions de faux positifs persistantes

### 🟢 Scripting Lua / Rhai

- [ ] Scripts personnalisés pour des checks métier spécifiques
- [ ] Accès à l'objet `request` / `response` dans le script
- [ ] Partage de scripts dans le registry

---

## v0.7 — Protocoles additionnels 📋

### 🟡 gRPC / Protobuf

- [ ] Parser les fichiers `.proto` pour découvrir les services et méthodes
- [ ] Injection dans les champs protobuf (string, bytes, int)
- [ ] Test d'authentification gRPC (metadata headers)
- [ ] Réflexion gRPC (équivalent introspection GraphQL)

### 🟢 WebSocket

- [ ] Test d'authentification sur le handshake (Origin, token)
- [ ] Injection dans les messages WS (JSON, texte brut)
- [ ] Test de rate limiting sur les connexions WS

### 🟢 SOAP / WSDL

- [ ] Parser les fichiers WSDL pour extraire les opérations
- [ ] XXE via payloads SOAP
- [ ] Injection dans les paramètres SOAP

---

## Améliorations transversales 📋

### Reporting

- [ ] Rapport PDF natif (via `wkhtmltopdf` ou bibliothèque Rust)
- [ ] Rapport Word/DOCX (pour clients non-techniques)
- [ ] Template de rapport personnalisable (Tera)
- [ ] Graphiques dans le rapport HTML (courbe de sévérité, camembert par module)
- [ ] Score de risque global calculé (agrégation CVSS pondérée)

### Performance

- [ ] Cache des réponses HTTP pour éviter les doublons
- [ ] Détection automatique du throttling (429) et back-off adaptatif
- [ ] Parallélisme inter-modules (modules tournant en parallèle sur le même endpoint)

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

## Prochaine release

v0.4.0 est complète. Pour publier :

```bash
git add -A
git commit -m "feat(v0.4): diff scan CI/CD, watch mode, REPL interactif, modules.rs DRY"
git tag v0.4.0
git push && git push --tags
```

---

*Dernière mise à jour : 2026-06-27 — v0.4.0 ✅ livrée — prochaine : v0.5.0 (GitHub App, Jira, dashboard web)*
