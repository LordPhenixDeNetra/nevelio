# Suivi des tâches — Nevelio AI & Configuration globale

> Légende statut : `[ ]` À faire · `[~]` En cours · `[x]` Terminé · `[!]` Bloqué
> Légende priorité : 🔴 Critique · 🟠 Haute · 🟡 Moyenne · 🟢 Basse

---

## Phase 1 — Configuration globale (`nevelio-config`)

> Objectif : fichier de config utilisateur persistant, assistant post-install, commandes `nevelio config`.
> Prérequis : aucun — fondation indépendante.

### Crate et structure

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| C.1 | [x] | 🔴 | Créer crate `nevelio-config` dans le workspace | 1h | — | `crates/nevelio-config/` — membre du workspace Cargo |
| C.2 | [x] | 🔴 | Définir structs `GlobalConfig`, `ProjectConfig`, `ResolvedConfig` avec serde | 4h | C.1 | `config/types.rs` — sections user, ai, scan, output, notify, audit |
| C.3 | [x] | 🔴 | Implémenter chargement `~/.config/nevelio/config.toml` via crate `dirs` | 3h | C.2 | `config/loader.rs` — cross-platform (Linux/macOS/Windows) |
| C.4 | [x] | 🔴 | Implémenter chargement `./nevelio.toml` projet | 2h | C.2 | Optionnel — absent = config globale seule |
| C.5 | [x] | 🔴 | Implémenter fusion des trois niveaux (global < projet < flags CLI) | 4h | C.3 C.4 | `config/merge.rs` — priorité flags > projet > global > défauts |
| C.6 | [~] | 🟠 | Validation de la config résolue (types, valeurs autorisées) | 3h | C.5 | Validation de base via serde — validation sémantique à compléter |
| C.7 | [x] | 🟠 | Tests unitaires : chargement, fusion, priorités | 4h | C.5 | 4 tests dans `lib.rs` (default, lang, merge) |

### Commandes CLI

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| C.8 | [x] | 🔴 | `nevelio config init` — assistant interactif post-install | 6h | C.3 | Crée le fichier s'il n'existe pas — questions minimales |
| C.9 | [x] | 🔴 | Lancement auto de `config init` à la première invocation | 2h | C.8 | Auto-lance si stdin est un terminal et config absente |
| C.10 | [x] | 🟠 | `nevelio config show` — affiche la config résolue | 2h | C.5 | Colorise par niveau d'origine (global / projet / flag) |
| C.11 | [x] | 🟠 | `nevelio config get <clé>` | 2h | C.5 | Accès par chemin pointé `ai.provider` |
| C.12 | [x] | 🟠 | `nevelio config set <clé> <valeur>` | 3h | C.3 | Modifie le fichier global en place (préserve commentaires via `toml_edit`) |
| C.13 | [x] | 🟡 | `nevelio config edit` — ouvre dans `$EDITOR` | 1h | C.3 | Fallback : `nano` si `$EDITOR` absent |
| C.14 | [x] | 🟡 | `nevelio config reset` — remet les valeurs par défaut | 2h | C.3 | Demande confirmation avant écrasement |

### i18n `nevelio-config`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| C.15 | [x] | 🔴 | Créer `crates/nevelio-config/locales/fr.yml` — toutes les clés `config.*` | 3h | C.8 | Assistant init, commandes, erreurs, messages de statut |
| C.16 | [x] | 🔴 | Créer `en.yml` et `es.yml` — traductions complètes | 3h | C.15 | Même structure que fr.yml |
| C.17 | [x] | 🔴 | Ajouter `rust_i18n::i18n!("locales", fallback = "fr")` dans `lib.rs` | 1h | C.15 | + `rust-i18n = { workspace = true }` dans `Cargo.toml` |
| C.18 | [x] | 🟠 | Respecter `lang` de la config résolue dans tous les messages | 2h | C.17 C.5 | Appel `rust_i18n::set_locale()` au démarrage de la CLI |

---

## Phase 2 — Abstraction multi-provider (`nevelio-ai`)

> Objectif : trait `AiProvider` + implémentations pour chaque provider.
> Prérequis : Phase 1 terminée (config nécessaire pour lire les clés API).

### Fondations

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| A.1 | [x] | 🔴 | Créer crate `nevelio-ai` avec feature flag `ai` dans workspace | 2h | C.1 | `crates/nevelio-ai/` — `default = ["ai"]` dans CLI Cargo.toml |
| A.2 | [x] | 🔴 | Définir trait `AiProvider` : `complete`, `complete_json`, `complete_with_tools` | 4h | A.1 | `provider/mod.rs` — async-trait, Message, Role, ToolDefinition, ToolCallResponse |
| A.3 | [x] | 🔴 | Fonction `build_provider(cfg: &AiConfig) -> Box<dyn AiProvider>` | 2h | A.2 | `provider/factory.rs` — dispatch par `cfg.provider` |
| A.4 | [ ] | 🟠 | Système de fallback : si provider actif échoue → tente `ai.routing.fallback` | 3h | A.3 | `provider/fallback.rs` — max 2 tentatives, log du basculement |
| A.5 | [ ] | 🟠 | Système de routing par tâche (`ai.routing.report`, `ai.routing.payloads`…) | 3h | A.3 | `provider/router.rs` — sélectionne le provider selon le type de tâche |

### Providers

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| A.6 | [x] | 🔴 | `AnthropicProvider` — API Messages v1 + tool use | 6h | A.2 | `provider/anthropic.rs` — tool_use, system prompt, JSON mode |
| A.7 | [x] | 🔴 | `OpenAiProvider` — API ChatCompletion + function calling | 5h | A.2 | `provider/openai.rs` — JSON mode + function_calling + base_url override |
| A.8 | [x] | 🔴 | `OllamaProvider` — HTTP local + tool use (models compatibles) | 4h | A.2 | `provider/ollama.rs` — format json, tool_calls llama3.1+ |
| A.9 | [x] | 🟠 | `MistralProvider` | 3h | A.2 | Réutilise `OpenAiProvider` avec base_url mistral.ai |
| A.10 | [x] | 🟠 | `GroqProvider` | 2h | A.2 | Réutilise `OpenAiProvider` avec base_url groq.com |
| A.11 | [ ] | 🟡 | `BedrockProvider` — AWS SDK | 8h | A.2 | `provider/bedrock.rs` — feature `bedrock` séparée, auth via env AWS |

### Commandes `nevelio config ai`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| A.12 | [x] | 🟠 | `nevelio config ai ping` — teste tous les providers configurés | 3h | A.3 | Affiche latence + modèle + statut clé API |
| A.13 | [x] | 🟠 | `nevelio config ai ping <provider>` — teste un provider | 1h | A.12 | |
| A.14 | [ ] | 🟡 | `nevelio ai providers` — liste les providers disponibles et leur statut | 2h | A.3 | |

### i18n `nevelio-ai`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| A.15 | [x] | 🔴 | Créer `crates/nevelio-ai/locales/fr.yml` — clés `ai.error.*`, `ai.guardrail.*`, `ai.agent.*`, `ai.triage.*`, `ai.report.*` | 3h | A.1 | |
| A.16 | [x] | 🔴 | Créer `en.yml` et `es.yml` | 2h | A.15 | |
| A.17 | [x] | 🔴 | `rust_i18n::i18n!("locales", fallback = "fr")` dans `lib.rs` | 1h | A.15 | |

### Tests

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| A.18 | [x] | 🔴 | Tests unitaires trait + factory (mock provider) | 4h | A.3 | 5 tests dans `lib.rs` — MockProvider, complete, complete_json, tools, constructors |
| A.19 | [ ] | 🟠 | Tests d'intégration Ollama (CI local uniquement) | 3h | A.8 | Skip si `OLLAMA_HOST` absent |
| A.20 | [ ] | 🟡 | Tests d'intégration Anthropic (optionnel, coût tokens) | 2h | A.6 | Gated par `ANTHROPIC_API_KEY` + `RUN_AI_INTEGRATION_TESTS=1` |

---

## Phase 3 — Fonctionnalités LLM ponctuelles

> Objectif : enrichir les résultats de scan sans modifier le moteur déterministe.
> Prérequis : Phase 2 terminée.

### Triage des findings

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| F.1 | [ ] | 🔴 | `ai::triage::classify_finding(finding, provider)` — vrai/faux positif + justification | 6h | A.2 | Prompt structuré → JSON `{verdict, confidence, reason}` |
| F.2 | [ ] | 🔴 | Intégrer dans le pipeline post-scan : `--ai-triage` | 3h | F.1 | Ajoute `ai_verdict` à chaque finding dans le JSON de sortie |
| F.3 | [ ] | 🟠 | Affichage du triage dans le rapport HTML et texte | 3h | F.2 | Badge couleur par verdict, justification affichée |
| F.4 | [ ] | 🟠 | Clés i18n `ai.triage.*` dans les trois locales | 2h | F.2 | Verdicts, libellés de confiance, messages d'erreur |

### Remédiation par finding

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| F.5 | [ ] | 🟠 | `ai::remediation::suggest(finding, lang, provider)` | 5h | A.2 | Retourne markdown : explication + code corrigé dans la langue configurée |
| F.6 | [ ] | 🟠 | `--ai-remediation` : ajoute les suggestions au rapport | 2h | F.5 | Section dédiée dans HTML, champ `remediation_ai` dans JSON |
| F.7 | [ ] | 🟠 | Clés i18n `ai.remediation.*` | 1h | F.5 | Titres de section, messages d'attente, erreurs |

### Rapport narratif

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| F.8 | [ ] | 🟡 | `ai::report::narrative(findings, lang, provider)` — texte d'attaque synthétique | 5h | A.2 | Décrit comment un attaquant enchaînerait les vulnérabilités |
| F.9 | [ ] | 🟡 | `--ai-report` : génère un fichier `.md` narratif en plus du rapport standard | 2h | F.8 | `audit-narrative-YYYY-MM-DD.md` |
| F.10 | [ ] | 🟡 | Clés i18n `ai.report.*` | 1h | F.8 | |

### Génération de payloads contextuels

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| F.11 | [ ] | 🟡 | `ai::payloads::generate(context, vuln_type, provider)` — variantes adaptées | 8h | A.2 | Context = framework détecté, WAF identifié, type de champ |
| F.12 | [ ] | 🟡 | `--ai-payloads` : enrichit les listes YAML statiques avant le scan | 3h | F.11 | Merge avec les payloads existants, déduplication |
| F.13 | [ ] | 🟢 | Validation des payloads générés (syntaxe, longueur max) | 2h | F.11 | Rejette les payloads hallucinations évidentes |

---

## Phase 4 — Agent autonome

> Objectif : boucle d'exploration autonome pilotée par le LLM.
> Prérequis : Phases 2 + 3 terminées.

### Boucle agent

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| G.1 | [ ] | 🔴 | `agent::Planner` — analyse cible, produit un plan de scan structuré | 8h | A.2 | Entrée : spec OpenAPI ou réponses initiales. Sortie : liste d'actions ordonnées |
| G.2 | [ ] | 🔴 | `agent::ToolCaller` — appelle les outils Nevelio depuis l'agent | 6h | G.1 | Outils : `scan_endpoint`, `send_payload`, `read_response`, `list_endpoints` |
| G.3 | [ ] | 🔴 | `agent::Reviewer` — interprète chaque réponse HTTP, décide de la suite | 6h | G.2 | Détecte : succès exploit / échec / WAF / rate-limit / endpoint intéressant |
| G.4 | [ ] | 🔴 | Boucle principale : Planner → ToolCaller → Reviewer → itération | 5h | G.1 G.2 G.3 | Max configurable d'itérations (`agent.max_iterations`) |

### Guardrails

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| G.5 | [ ] | 🔴 | Guardrail `scope` : l'agent ne peut pas envoyer de requête hors des domaines autorisés | 4h | G.2 | Vérifié côté Nevelio (pas côté LLM) — refus + log |
| G.6 | [ ] | 🔴 | Guardrail `max_requests` : limite le nombre de requêtes HTTP émises | 2h | G.2 | Défaut : 100 — configurable via `agent.max_requests` |
| G.7 | [ ] | 🔴 | Guardrail `require_legal_accept` : agent ne démarre pas sans `--accept-legal` | 1h | G.4 | |
| G.8 | [ ] | 🔴 | Guardrail `dry_run` : agent planifie et simule sans envoyer de requête réelle | 2h | G.4 | `--dry-run` global s'applique aussi à l'agent |
| G.9 | [ ] | 🟠 | Guardrail `ai_budget` : limite en tokens consommés | 3h | G.4 | `--ai-budget 50000` — arrêt propre avec rapport partiel |

### Exposition MCP (optionnel)

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| G.10 | [ ] | 🟡 | Exposer les outils Nevelio via protocole MCP | 12h | G.2 | Permet à Claude Desktop / d'autres agents d'orchestrer Nevelio |
| G.11 | [ ] | 🟡 | `nevelio mcp serve` — démarre le serveur MCP | 3h | G.10 | |

### i18n agent

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| G.12 | [ ] | 🟠 | Clés i18n `ai.agent.*` dans les trois locales | 3h | G.4 | Statuts boucle, guardrails, résumé d'itération |

---

## Infrastructure transversale

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| I.1 | [x] | 🔴 | Ajouter `rust-i18n = "3"` dans `[workspace.dependencies]` si pas déjà présent | 1h | — | Mutualisé avec les crates hardware |
| I.2 | [x] | 🔴 | `nevelio-config` et `nevelio-ai` membres du workspace Cargo racine | 1h | C.1 A.1 | Les deux crates ajoutées au workspace |
| I.3 | [ ] | 🟠 | CI : `cargo build --features ai` + `cargo test --features ai` | 2h | A.18 | Ajout dans `.github/workflows/` — skip tests d'intégration LLM en CI |
| I.4 | [ ] | 🟠 | CI : `cargo build --no-default-features` — vérifie que le build sans IA compile | 1h | A.1 | |
| I.5 | [ ] | 🟡 | Documentation `nevelio config init` dans `docs/tutorial.md` | 2h | C.8 | Section dédiée |
| I.6 | [ ] | 🟡 | Mise à jour `docs/hardware-security-extensions.md` → mention config globale partagée | 1h | C.1 | |

---

## Récapitulatif

| Phase | Tâches | Terminées | Prérequis |
|---|---|---|---|
| **1 — Config globale** | 18 | 17 | Aucun |
| **2 — Multi-provider** | 20 | 14 | Phase 1 |
| **3 — LLM ponctuel** | 13 | 0 | Phase 2 |
| **4 — Agent autonome** | 12 | 0 | Phases 2 + 3 |
| **Transversal** | 6 | 2 (I.1, I.2) | — |
| **TOTAL** | **69** | **33 / 69** | |

---

## Dépendances Rust à ajouter

| Crate | Version | Usage | Feature requise |
|---|---|---|---|
| `dirs` | `5` | `~/.config/nevelio/` cross-platform | — |
| `toml_edit` | `0.22` | `config set` sans perdre les commentaires | — |
| `async-trait` | `0.1` | Trait `AiProvider` async | `ai` |
| `reqwest` | `0.12` | Appels HTTP providers cloud | `ai` |
| `aws-sdk-bedrockruntime` | `1` | Provider Bedrock | `bedrock` |
| `rust-i18n` | `3` | i18n (déjà dans workspace) | — |
