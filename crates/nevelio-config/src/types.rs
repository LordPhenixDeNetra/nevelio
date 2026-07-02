use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── User ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct UserConfig {
    pub name:  Option<String>,
    pub email: Option<String>,
    pub org:   Option<String>,
}

// ── AI providers ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProviderConfig {
    pub model:       String,
    /// Name of the env var that holds the API key (never stored in plain text)
    pub api_key_env: Option<String>,
    /// Base URL override (Ollama, Azure OpenAI, etc.)
    pub base_url:    Option<String>,
    /// AWS region env var name (Bedrock only)
    pub region_env:  Option<String>,
    pub max_tokens:  Option<u32>,
    pub temperature: Option<f32>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            model:       String::new(),
            api_key_env: None,
            base_url:    None,
            region_env:  None,
            max_tokens:  Some(4096),
            temperature: Some(0.2),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct AiRoutingConfig {
    /// Provider to use for narrative reports
    pub report:   Option<String>,
    /// Provider to use for payload generation (speed)
    pub payloads: Option<String>,
    /// Provider to use for finding triage (precision)
    pub triage:   Option<String>,
    /// Fallback provider if active provider is down
    pub fallback: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct AiConfig {
    pub enabled:   bool,
    pub provider:  Option<String>,
    pub providers: HashMap<String, ProviderConfig>,
    pub routing:   AiRoutingConfig,
}

impl AiConfig {
    pub fn active_provider_name(&self) -> &str {
        self.provider.as_deref().unwrap_or("anthropic")
    }

    pub fn active_provider(&self) -> Option<&ProviderConfig> {
        self.providers.get(self.active_provider_name())
    }

    pub fn resolved_api_key(&self) -> Option<String> {
        let prov = self.active_provider()?;
        let env_var = prov.api_key_env.as_deref()?;
        std::env::var(env_var).ok()
    }
}

// ── Scan ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ScanConfig {
    pub profile:      Option<String>,
    pub dry_run:      bool,
    pub timeout_secs: u64,
    pub concurrency:  usize,
    pub lang:         String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            profile:      None,
            dry_run:      false,
            timeout_secs: 30,
            concurrency:  10,
            lang:         "fr".to_string(),
        }
    }
}

// ── Output ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OutputConfig {
    pub format:   String,
    pub dir:      Option<String>,
    pub colorize: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format:   "text".to_string(),
            dir:      None,
            colorize: true,
        }
    }
}

// ── Notify ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct NotifyConfig {
    pub slack_webhook_env: Option<String>,
    pub github_token_env:  Option<String>,
    pub jira_url:          Option<String>,
    pub jira_token_env:    Option<String>,
}

// ── Audit log ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuditConfig {
    pub enabled: bool,
    pub path:    Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path:    None,
        }
    }
}

// ── Top-level configs ─────────────────────────────────────────────────────────

/// Global user config — `~/.config/nevelio/config.toml`
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct GlobalConfig {
    #[serde(default)]
    pub user:   UserConfig,
    #[serde(default)]
    pub ai:     AiConfig,
    #[serde(default)]
    pub scan:   ScanConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default)]
    pub audit:  AuditConfig,
}

/// Project config — `./nevelio.toml` (subset — overrides global)
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ProjectConfig {
    pub target:      Option<String>,
    pub profile:     Option<String>,
    pub dry_run:     Option<bool>,
    pub timeout:     Option<u64>,
    pub concurrency: Option<usize>,
    pub lang:        Option<String>,
    pub output:      Option<String>,
    pub out_dir:     Option<String>,
    #[serde(default)]
    pub ai:          ProjectAiConfig,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ProjectAiConfig {
    pub enabled:  Option<bool>,
    pub provider: Option<String>,
}

/// Resolved config — result of merging global + project + CLI flags
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub user:    UserConfig,
    pub ai:      AiConfig,
    pub scan:    ScanConfig,
    pub output:  OutputConfig,
    pub notify:  NotifyConfig,
    pub audit:   AuditConfig,
    pub target:  Option<String>,
}
