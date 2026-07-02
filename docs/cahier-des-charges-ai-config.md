# Cahier des charges — Intégration IA & Configuration globale (Nevelio AI Extension)

> **Statut :** 📋 Planifié — **0/0 tâches** — 0 tests — 0 crates créées
> **Cibles :** crate `nevelio-config` · crate `nevelio-ai` · feature flag `ai`
> **Dernière mise à jour :** 2026-07-02

---

## 1. Contexte et objectifs

### 1.1 Contexte

Nevelio v0.6 est un scanner API déterministe. Chaque scan produit des résultats
reproductibles à partir de payloads statiques (YAML) et de règles fixes. Cette
architecture est solide pour l'audit et le CI/CD, mais limitée pour :

- L'adaptation aux WAF et protections dynamiques
- La réduction du bruit (faux positifs) sans intervention manuelle
- La génération de rapports narratifs exploitables par un client non-technique
- L'exploration autonome d'APIs inconnues sans spécification OpenAPI

Ce cahier des charges décrit l'extension **Nevelio AI** : une surcouche optionnelle
qui intègre des LLMs et des agents IA dans le pipeline de scan, sans modifier le
moteur déterministe existant.

### 1.2 Principes fondamentaux

| Principe | Description |
|---|---|
| **Optionnel par défaut** | Sans `--ai` ou `ai.enabled = true`, zéro appel LLM, zéro dépendance |
| **Désactivable à la compilation** | `cargo build --no-default-features` exclut tout le code IA |
| **Multi-provider** | Anthropic, OpenAI, Ollama (local), Mistral, Groq, AWS Bedrock |
| **Air-gap compatible** | Via Ollama — aucun trafic sortant vers un LLM externe |
| **Couche déterministe préservée** | L'IA orchestre, Nevelio exécute — les guardrails restent dans Nevelio |
| **i18n complète** | Tous les messages, rapports IA et assistant config traduits fr/en/es |

---

## 2. Architecture globale

```
┌──────────────────────────────────────────────────────────┐
│  CLI  nevelio scan --ai --target https://api.example.com │
└───────────────────────────┬──────────────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │   nevelio-config            │
              │   Charge & fusionne :       │
              │   ~/.config/nevelio/        │
              │   ./nevelio.toml            │
              │   CLI flags                 │
              └─────────────┬──────────────┘
                            │
           ┌────────────────▼─────────────────┐
           │   nevelio-ai   (feature = "ai")  │
           │                                  │
           │   AiProvider trait               │
           │   ├── AnthropicProvider          │
           │   ├── OpenAiProvider             │
           │   ├── OllamaProvider  (local)    │
           │   ├── MistralProvider            │
           │   └── GroqProvider               │
           │                                  │
           │   Agent (boucle autonome)        │
           │   ├── Planner                    │
           │   ├── ToolCaller → Nevelio API   │
           │   └── Reviewer (triage findings) │
           └────────────────┬─────────────────┘
                            │ appelle
              ┌─────────────▼──────────────┐
              │   Nevelio (déterministe)    │
              │   Scanner · Payloads · ...  │
              └────────────────────────────┘
```

---

## 3. Crate `nevelio-config`

### 3.1 Responsabilité

Charge, fusionne et valide la configuration à deux niveaux :

| Niveau | Fichier | Scope |
|---|---|---|
| Global utilisateur | `~/.config/nevelio/config.toml` | Toutes les invocations |
| Projet | `./nevelio.toml` | Scan courant |
| Flags CLI | `--ai`, `--lang`, `--provider`… | Invocation unique |

Priorité : `flags CLI` > `nevelio.toml projet` > `~/.config/nevelio/config.toml` > défauts.

### 3.2 Structure du fichier global `~/.config/nevelio/config.toml`

```toml
# ─── Identité ────────────────────────────────────────────────
[user]
name  = "Moussa Thior"
email = "netrathior@gmail.com"
org   = ""

# ─── IA / LLMs ───────────────────────────────────────────────
[ai]
enabled  = false             # désactivé par défaut
provider = "anthropic"       # provider actif

[ai.providers.anthropic]
model       = "claude-sonnet-4-6"
api_key_env = "ANTHROPIC_API_KEY"
max_tokens  = 4096
temperature = 0.2

[ai.providers.openai]
model       = "gpt-4o"
api_key_env = "OPENAI_API_KEY"
max_tokens  = 4096

[ai.providers.ollama]
model    = "llama3.2"
base_url = "http://localhost:11434"   # air-gap / local

[ai.providers.mistral]
model       = "mistral-large-latest"
api_key_env = "MISTRAL_API_KEY"

[ai.providers.groq]
model       = "llama-3.1-70b-versatile"
api_key_env = "GROQ_API_KEY"

[ai.providers.bedrock]
model      = "anthropic.claude-3-5-sonnet-20241022-v2:0"
region_env = "AWS_REGION"             # auth via AWS SDK (env vars)

# ─── Routing par tâche (optionnel) ───────────────────────────
[ai.routing]
report    = "anthropic"    # narration, qualité rédactionnelle
payloads  = "groq"         # vitesse, génération en masse
triage    = "anthropic"    # précision, réduction faux positifs
fallback  = "ollama"       # si tous les providers cloud sont down

# ─── Scan ────────────────────────────────────────────────────
[scan]
profile      = "standard"  # stealth | standard | aggressive
dry_run      = false
timeout_secs = 30
concurrency  = 10
lang         = "fr"        # fr | en | es

# ─── Sorties ─────────────────────────────────────────────────
[output]
format   = "text"          # text | json | html | nevelio-json
dir      = "~/nevelio-reports"
colorize = true

# ─── Notifications ───────────────────────────────────────────
[notify]
slack_webhook_env = "NEVELIO_SLACK_WEBHOOK"
github_token_env  = "GITHUB_TOKEN"
jira_url          = ""
jira_token_env    = "JIRA_API_TOKEN"

# ─── Audit log ───────────────────────────────────────────────
[audit]
enabled = true
path    = "~/.local/share/nevelio/audit.log"
```

### 3.3 Commandes `nevelio config`

| Commande | Description |
|---|---|
| `nevelio config init` | Assistant interactif post-install |
| `nevelio config show` | Affiche la config résolue (global + projet + flags) |
| `nevelio config edit` | Ouvre `~/.config/nevelio/config.toml` dans `$EDITOR` |
| `nevelio config get <clé>` | Lit une valeur (`ai.provider`) |
| `nevelio config set <clé> <val>` | Modifie une valeur |
| `nevelio config ai ping` | Teste la connexion à tous les providers configurés |
| `nevelio config ai ping <provider>` | Teste un provider spécifique |
| `nevelio config reset` | Remet la config globale aux valeurs par défaut |

### 3.4 Assistant `nevelio config init`

Lancé automatiquement à la première invocation si aucun fichier global n'existe.
Pose les questions minimales, écrit la config, affiche un résumé.

```
Nevelio — Configuration initiale
─────────────────────────────────
Votre nom         : _
Langue par défaut : fr | en | es
Activer l'IA ?    : oui / non
  Provider        : anthropic | openai | ollama | groq | mistral | bedrock
  Variable d'env  : ANTHROPIC_API_KEY
  → Clé détectée ✓ / non trouvée ✗
Profil de scan    : stealth | standard | aggressive

Config écrite dans ~/.config/nevelio/config.toml ✓
```

---

## 4. Crate `nevelio-ai`

### 4.1 Trait `AiProvider`

Interface unique que tous les providers implémentent :

```rust
#[async_trait]
pub trait AiProvider: Send + Sync {
    fn name(&self)             -> &str;
    fn supports_tools(&self)   -> bool;    // function calling / tool use
    async fn complete(
        &self,
        prompt: &str,
    ) -> Result<String>;
    async fn complete_json<T: DeserializeOwned>(
        &self,
        prompt: &str,
    ) -> Result<T>;
    async fn complete_with_tools(
        &self,
        messages: &[Message],
        tools:    &[ToolDefinition],
    ) -> Result<ToolCallResponse>;
}
```

### 4.2 Providers implémentés

| Provider | Protocole | Tool use | Air-gap |
|---|---|---|---|
| `AnthropicProvider` | API REST Anthropic | ✅ | ❌ |
| `OpenAiProvider` | API REST OpenAI compatible | ✅ | ❌ |
| `OllamaProvider` | HTTP local `localhost:11434` | ✅ (models supportés) | ✅ |
| `MistralProvider` | API REST Mistral | ✅ | ❌ |
| `GroqProvider` | API REST Groq | ✅ | ❌ |
| `BedrockProvider` | AWS SDK | ✅ | ❌ |

### 4.3 Modes d'utilisation IA

#### Mode LLM ponctuel (sans agent)

Le LLM est appelé une fois après le scan pour enrichir les résultats :

- **Triage** : classe chaque finding (vrai positif / faux positif probable) avec justification
- **Remédiation** : génère une suggestion de correction par finding avec exemple de code
- **Rapport narratif** : produit un texte d'attaque synthétique (comment enchaîner les vulnérabilités)

#### Mode Agent autonome (avec `--ai-agent`)

L'agent pilote le scan de façon itérative :

1. **Planner** : analyse la cible (spec OpenAPI, réponses initiales) et définit une stratégie
2. **ToolCaller** : appelle les outils Nevelio (scan endpoint, envoyer payload, lire réponse)
3. **Reviewer** : interprète chaque réponse HTTP, décide de la suite
4. **Boucle** : itère jusqu'à un budget de tokens ou un nombre de requêtes max

Guardrails obligatoires dans l'agent :
- `max_requests` : nombre maximum de requêtes HTTP émises
- `scope` : liste de domaines autorisés (l'agent ne peut pas sortir du scope)
- `dry_run` : si actif, l'agent planifie mais n'envoie rien
- `require_legal_accept` : l'agent ne démarre pas sans `--accept-legal`

### 4.4 Feature flag

```toml
# Cargo.toml workspace
[features]
default = []
ai      = ["nevelio-ai", "tokio/full", "async-trait"]
```

Sans `--features ai`, le binaire ne contient aucun code LLM.

---

## 5. Internationalisation (i18n)

### 5.1 Scope

Tous les textes visibles de la couche IA et config doivent être traduits :

| Catégorie | Clés YAML |
|---|---|
| Assistant config init | `config.init.*` |
| Messages `nevelio config` | `config.cmd.*` |
| Statut providers (ping) | `config.ai.ping.*` |
| Triage findings | `ai.triage.*` |
| Remédiation | `ai.remediation.*` |
| Rapport narratif (structure) | `ai.report.*` |
| Erreurs provider | `ai.error.*` |
| Guardrails dépassés | `ai.guardrail.*` |

### 5.2 Fichiers locales

```
crates/nevelio-config/locales/
├── fr.yml
├── en.yml
└── es.yml
```

Chaque crate déclare dans son `lib.rs` :

```rust
rust_i18n::i18n!("locales", fallback = "fr");
```

### 5.3 Exemple fr.yml

```yaml
config:
  init:
    welcome:   "Nevelio — Configuration initiale"
    name:      "Votre nom"
    lang:      "Langue par défaut"
    ai_enable: "Activer l'IA ?"
    provider:  "Provider"
    key_env:   "Variable d'env pour la clé API"
    key_found: "Clé détectée dans l'environnement ✓"
    key_miss:  "Clé non trouvée — à définir avant utilisation"
    done:      "Config écrite dans {path} ✓"
  cmd:
    show_title: "Configuration résolue"
    get_miss:   "Clé '{key}' introuvable"
    set_ok:     "'{key}' mis à jour → {value}"
    reset_ok:   "Config réinitialisée aux valeurs par défaut"
  ai:
    ping:
      ok:      "{provider} ✓ ({ms}ms)"
      fail:    "{provider} ✗ — {error}"
      no_key:  "{provider} — clé API absente ({env})"

ai:
  triage:
    true_positive:  "Vulnérabilité confirmée"
    false_positive: "Faux positif probable"
    uncertain:      "Incertain — vérification manuelle recommandée"
  error:
    provider_down:  "Provider {provider} inaccessible — basculement sur {fallback}"
    no_provider:    "Aucun provider IA configuré. Lancez 'nevelio config init'."
    budget_exceeded: "Budget de tokens atteint ({used}/{max})"
  guardrail:
    scope_violation: "Action hors scope refusée : {url}"
    max_requests:    "Limite de requêtes atteinte ({n})"
```

---

## 6. Sécurité et confidentialité

| Risque | Mitigation |
|---|---|
| Fuite de données cible vers LLM cloud | Avertissement explicite au démarrage + `--ai-no-evidence` pour masquer les preuves |
| Clés API en clair dans config | Toujours via variable d'env, jamais stockées dans le fichier |
| Agent hors scope | Guardrail `scope` vérifié côté Nevelio, pas côté LLM |
| Tokens facturés à l'insu | `nevelio config show` affiche le provider actif, `--ai-budget <n>` limite les tokens |
| Logs contenant des données sensibles | `audit.log` n'enregistre pas le contenu des prompts/réponses LLM |

---

## 7. Compatibilité et dépendances Rust

| Crate | Usage |
|---|---|
| `reqwest` | Appels HTTP vers les APIs provider |
| `async-trait` | Trait `AiProvider` async |
| `serde` / `serde_json` | Sérialisation des prompts et réponses |
| `toml` | Parsing des fichiers de config |
| `dirs` | Résolution de `~/.config/nevelio/` cross-platform |
| `rust-i18n` | i18n (même version que les autres crates) |
| `aws-sdk-bedrockruntime` | Provider Bedrock (feature `bedrock`) |
