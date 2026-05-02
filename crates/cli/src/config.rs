use serde::Deserialize;
use std::path::PathBuf;

/// Settings loaded from `.nevelio.toml` in the working directory.
/// All fields are optional — absent fields fall back to CLI defaults.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NevelioConfig {
    /// Base URL of the target API
    pub target: Option<String>,
    /// Scan profile: stealth | normal | aggressive
    pub profile: Option<String>,
    /// Output format: json | html | markdown | junit | sarif
    pub output: Option<String>,
    /// Directory for output files
    pub out_dir: Option<PathBuf>,
    /// Request timeout in seconds
    pub timeout: Option<u64>,
    /// Attack modules to run (empty = all)
    pub modules: Option<Vec<String>>,
    /// Maximum concurrent requests
    pub concurrency: Option<usize>,
    /// Maximum requests per second
    pub rate_limit: Option<u64>,
    /// Bearer/Basic token (plain text — prefer auth_token_env)
    pub auth_token: Option<String>,
    /// Name of the env var that holds the auth token
    pub auth_token_env: Option<String>,
    /// HTTP proxy URL
    pub proxy: Option<String>,
}

impl NevelioConfig {
    /// Load `.nevelio.toml` from the current directory.
    /// Returns an empty config (all `None`) if the file is absent or unparseable.
    pub fn load() -> Self {
        let path = PathBuf::from(".nevelio.toml");
        if !path.exists() {
            return Self::default();
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: cannot read .nevelio.toml — {e}");
                return Self::default();
            }
        };
        match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Warning: invalid .nevelio.toml — {e}");
                Self::default()
            }
        }
    }

    /// Resolve the auth token: env var (recommended) takes precedence over plain value.
    pub fn resolved_auth_token(&self) -> Option<String> {
        if let Some(ref var) = self.auth_token_env {
            match std::env::var(var) {
                Ok(token) => return Some(token),
                Err(_) => eprintln!("Warning: env var {var} not set (auth_token_env in .nevelio.toml)"),
            }
        }
        self.auth_token.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_all_none() {
        let cfg = NevelioConfig::default();
        assert!(cfg.target.is_none());
        assert!(cfg.profile.is_none());
        assert!(cfg.output.is_none());
        assert!(cfg.modules.is_none());
    }

    #[test]
    fn parse_valid_toml() {
        let toml = r#"
            target = "https://staging.example.com"
            profile = "stealth"
            output = "html"
            timeout = 10
            modules = ["auth", "injection"]
        "#;
        let cfg: NevelioConfig = toml::from_str(toml).expect("should parse");
        assert_eq!(cfg.target.as_deref(), Some("https://staging.example.com"));
        assert_eq!(cfg.profile.as_deref(), Some("stealth"));
        assert_eq!(cfg.output.as_deref(), Some("html"));
        assert_eq!(cfg.timeout, Some(10));
        assert_eq!(cfg.modules.as_deref(), Some(&["auth".to_string(), "injection".to_string()][..]));
    }

    #[test]
    fn auth_token_env_resolved() {
        std::env::set_var("__NEVELIO_TEST_TOKEN", "Bearer test-token");
        let cfg = NevelioConfig {
            auth_token_env: Some("__NEVELIO_TEST_TOKEN".to_string()),
            ..Default::default()
        };
        assert_eq!(cfg.resolved_auth_token().as_deref(), Some("Bearer test-token"));
        std::env::remove_var("__NEVELIO_TEST_TOKEN");
    }

    #[test]
    fn auth_token_direct_fallback() {
        let cfg = NevelioConfig {
            auth_token: Some("Bearer direct".to_string()),
            ..Default::default()
        };
        assert_eq!(cfg.resolved_auth_token().as_deref(), Some("Bearer direct"));
    }
}
