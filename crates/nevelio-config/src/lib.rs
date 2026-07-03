pub mod loader;
pub mod merge;
pub mod types;
pub mod validate;

rust_i18n::i18n!("locales", fallback = "fr");

pub use loader::{
    global_config_exists, global_config_path, load_global, load_project, save_global,
};
pub use merge::{merge, CliOverrides};
pub use types::{
    AiConfig, AiRoutingConfig, AuditConfig, GlobalConfig, NotifyConfig, OutputConfig,
    ProjectAiConfig, ProjectConfig, ProviderConfig, ResolvedConfig, ScanConfig, UserConfig,
};
pub use validate::{validate, ValidationError};

use anyhow::{bail, Result};

/// Convenience: load + merge in one call.
/// Returns a `ResolvedConfig` from global + optional project file + CLI overrides.
/// Performs semantic validation after merging — returns an error if the config is invalid.
pub fn load(overrides: CliOverrides) -> Result<ResolvedConfig> {
    let global  = loader::load_global()?;
    let project = loader::load_project(None)?;
    let resolved = merge::merge(global, project, overrides);

    let errors = validate::validate(&resolved);
    if !errors.is_empty() {
        let msgs: Vec<String> = errors.iter().map(|e| format!("  • {}", e)).collect();
        bail!("Configuration invalide :\n{}", msgs.join("\n"));
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_global_has_ai_disabled() {
        let cfg = GlobalConfig::default();
        assert!(!cfg.ai.enabled);
    }

    #[test]
    fn default_scan_lang_is_fr() {
        let cfg = GlobalConfig::default();
        assert_eq!(cfg.scan.lang, "fr");
    }

    #[test]
    fn merge_cli_lang_wins() {
        let global  = GlobalConfig::default();
        let project = ProjectConfig::default();
        let ovr     = CliOverrides { lang: Some("en".to_string()), ..Default::default() };
        let resolved = merge(global, project, ovr);
        assert_eq!(resolved.scan.lang, "en");
    }

    #[test]
    fn merge_project_lang_over_global() {
        let global  = GlobalConfig::default(); // lang = "fr"
        let project = ProjectConfig { lang: Some("es".to_string()), ..Default::default() };
        let ovr     = CliOverrides::default();
        let resolved = merge(global, project, ovr);
        assert_eq!(resolved.scan.lang, "es");
    }

    #[test]
    fn merge_cli_ai_provider_wins() {
        let mut global  = GlobalConfig::default();
        global.ai.provider = Some("openai".to_string());
        let project = ProjectConfig::default();
        let ovr     = CliOverrides { ai_provider: Some("ollama".to_string()), ..Default::default() };
        let resolved = merge(global, project, ovr);
        assert_eq!(resolved.ai.active_provider_name(), "ollama");
    }
}
