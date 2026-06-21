# Nevelio — Roadmap des évolutions futures

> Ce document liste les fonctionnalités planifiées, classées par priorité et par thème.
> Les items sans assignation sont ouverts à contribution.

---

## Légende

| Symbole | Signification |
|---|---|
| 🔴 | Priorité haute — impact sécurité direct |
| 🟡 | Priorité moyenne — valeur différenciante |
| 🟢 | Priorité basse — intégrations / confort |
| ✅ | Implémenté |
| 🚧 | En cours |

---

## v0.2 — Couverture sécurité étendue

### 🔴 Module OAuth2 / OpenID Connect

- [ ] Détection du flow utilisé (Authorization Code, Implicit, Client Credentials, PKCE)
- [ ] Test de manipulation du paramètre `redirect_uri` (open redirect, host injection)
- [ ] Bypass PKCE (code_challenge faible ou absent)
- [ ] Fuite de token via header `Referer` / logs
- [ ] Test du flow Implicit (token dans URL fragment)
- [ ] Réutilisation d'`authorization_code` (rejeu)
- [ ] Enumération de clients OAuth via `client_id` prévisible
- [ ] Test de `state` absent ou fixe (CSRF sur le flow)
- [ ] Token introspection non protégée (`/introspect` sans auth)

### 🔴 Module SSRF (Server-Side Request Forgery)

- [ ] Détection des paramètres candidats (`url=`, `redirect=`, `webhook=`, `callback=`, `proxy=`, `uri=`, `path=`)
- [ ] Payloads SSRF vers `http://169.254.169.254` (AWS metadata)
- [ ] Payloads vers `http://localhost` / `http://127.0.0.1`
- [ ] Intégration OAST (out-of-band) via `interactsh` pour détection aveugle
- [ ] Bypass filtres : encodage d'URL, IPv6, redirections DNS

### 🔴 Module XXE (XML External Entity)

- [ ] Détection des endpoints acceptant `Content-Type: application/xml` ou `text/xml`
- [ ] Injection XXE classique (exfiltration fichier)
- [ ] Blind XXE via out-of-band (OOB)
- [ ] XXE via SVG / DOCX / format dérivé XML
- [ ] Billion laughs (DoS par entités récursives)

### 🟡 Module Prototype Pollution

- [ ] Détection des APIs Node.js / Express (header `X-Powered-By`, stack traces)
- [ ] Test via paramètres JSON : `__proto__`, `constructor.prototype`
- [ ] Test via paramètres query string : `?__proto__[admin]=true`
- [ ] Détection des effets de bord (comportement modifié de la réponse)

### 🟡 Renforcement module `auth`

- [ ] Tests JWT : token expiré accepté
- [ ] Tests JWT : algorithme ES256/RS256 → downgrade HS256 avec clé publique comme secret
- [ ] Attaque refresh token : rejeu, rotation non invalidée
- [ ] Test `kid` (Key ID) injection dans le header JWT
- [ ] Test `jku` / `x5u` SSRF (JWT header pointant vers clé distante)
- [ ] Bruteforce Basic Auth multithread avec wordlist configurable

### 🟡 Renforcement module `injection`

- [ ] Détection de SSTI dans les headers (User-Agent, X-Forwarded-For)
- [ ] Payloads XXS stocké et réfléchi sur les endpoints REST
- [ ] Injection CSV / formule Excel dans les exports
- [ ] LDAP injection
- [ ] XPath injection

### 🟡 Renforcement module `access-control`

- [ ] Test de mass assignment sur tous les champs de la spec OpenAPI
- [ ] BOLA (BFLA élargi) : tester toutes les combinaisons verbe × ressource × rôle
- [ ] Détection d'endpoints admin non protégés (`/admin`, `/internal`, `/manage`)
- [ ] HTTP method override (`X-HTTP-Method-Override: DELETE`)

---

## v0.3 — Sources d'entrée & DX

### 🔴 Import Postman / Insomnia

- [ ] Parser les collections Postman v2.1 (`collection.json`)
- [ ] Parser les collections Insomnia v4 (`.yaml` / `.json`)
- [ ] Extraction automatique des variables d'environnement (`{{base_url}}`, `{{token}}`)
- [ ] Conversion interne vers le modèle `Endpoint` de Nevelio
- [ ] Flag CLI : `--spec collection.postman.json`

### 🟡 Import HAR (HTTP Archive)

- [ ] Parser les fichiers `.har` exportés depuis Chrome DevTools / Burp
- [ ] Reconstruire les endpoints et paramètres depuis les entrées HAR
- [ ] Déduplication des requêtes similaires

### 🟡 Crawling amélioré

- [ ] Découverte d'endpoints par analyse JS (parsing de `fetch()`, `axios`, `$.ajax`)
- [ ] Suivi des redirections et liens dans les réponses JSON
- [ ] Respect de `robots.txt` en mode stealth
- [ ] Détection de versioning API (`/v1/`, `/v2/`, `/api/v3/`)

### 🟢 Support AsyncAPI

- [ ] Parser les specs AsyncAPI 2.x / 3.x (WebSocket, MQTT, Kafka)
- [ ] Tests d'injection sur les messages WebSocket
- [ ] Test d'authentification sur les handshakes WS

---

## v0.4 — Modes opérationnels

### 🟡 Mode surveillance continue (`watch`)

- [ ] Commande `nevelio watch --url ... --interval 6h`
- [ ] Sauvegarde de l'état entre les scans (hash des findings connus)
- [ ] Alerte uniquement sur les *nouveaux* findings
- [ ] Notifications : Slack, Teams, email, webhook générique
- [ ] Mode daemon (`--daemon`) avec PID file

### 🟡 Scan différentiel

- [ ] Commande `nevelio diff findings-v1.json findings-v2.json`
- [ ] Rapport des findings apparus, disparus, changés en sévérité
- [ ] Format de sortie : Markdown, JSON, HTML
- [ ] Intégration CI : exit code non-nul si régressions détectées

### 🟡 Mode interactif (REPL)

- [ ] Shell interactif `nevelio shell` avec complétion
- [ ] Inspection manuelle des endpoints découverts
- [ ] Rejeu de requêtes avec modification des paramètres
- [ ] Export de la session en rapport

### 🟢 Reprise de scan (`--resume`)

- [ ] Sauvegarder l'état du scan dans un fichier `.nevelio-state.json`
- [ ] Reprendre après interruption sans re-scanner les endpoints déjà traités
- [ ] Afficher la progression par rapport à l'état sauvegardé

---

## v0.5 — Intégrations écosystème

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

## v0.6 — Extensibilité

### 🟡 Système de plugins WebAssembly

- [ ] Interface de plugin via WASM (ABI stable défini dans `core`)
- [ ] Chargement dynamique : `nevelio --plugin ./mon-module.wasm scan ...`
- [ ] Registry de plugins (similaire à crates.io mais pour les modules Nevelio)
- [ ] Sandbox sécurisée (pas d'accès filesystem ni réseau non autorisé)
- [ ] Documentation d'écriture de plugin

### 🟡 Configuration déclarative (`.nevelio.toml`)

- [ ] Fichier de config par projet : cibles, modules, profil, seuils
- [ ] Merge config globale (`~/.config/nevelio/config.toml`) + locale
- [ ] Profils nommés (ex: `[profile.staging]`, `[profile.prod]`)
- [ ] Exclusions de faux positifs persistantes

### 🟢 Scripting Lua / Rhai

- [ ] Scripts personnalisés pour des checks métier spécifiques
- [ ] Accès à l'objet `request` / `response` dans le script
- [ ] Partage de scripts dans le registry

---

## v0.7 — Protocoles additionnels

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

## Améliorations transversales

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

## Idées à évaluer (backlog non priorisé)

- Intégration avec Nuclei (réutiliser les templates YAML de Nuclei)
- Export vers Notion / Confluence via API
- Mode "apprentissage" : enregistrer les réponses normales pour détecter les anomalies
- Comparaison automatique avec NVD/CVE sur les composants détectés
- Extension VS Code affichant les findings inline dans l'éditeur
- Support de l'authentification par certificat client (mTLS)
- Test des politiques CORS cross-origin avancées (wildcard, credentials)
- Détection de frameworks (Spring, Django, Rails) pour payloads ciblés

---

*Dernière mise à jour : 2026-06-21*
