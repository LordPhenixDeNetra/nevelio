use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::types::{GlobalConfig, ProjectConfig};

/// Returns `~/.config/nevelio/config.toml`
pub fn global_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("nevelio").join("config.toml"))
}

/// Returns the audit log default path `~/.local/share/nevelio/audit.log`
pub fn default_audit_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("nevelio").join("audit.log"))
}

/// Returns `true` if the global config file exists.
pub fn global_config_exists() -> bool {
    global_config_path().map(|p| p.exists()).unwrap_or(false)
}

/// Load and parse `~/.config/nevelio/config.toml`.
/// Returns `GlobalConfig::default()` if the file is absent.
pub fn load_global() -> Result<GlobalConfig> {
    let path = match global_config_path() {
        Some(p) => p,
        None => return Ok(GlobalConfig::default()),
    };

    if !path.exists() {
        return Ok(GlobalConfig::default());
    }

    let content =
        std::fs::read_to_string(&path).with_context(|| format!("Lecture de {}", path.display()))?;

    toml::from_str(&content).with_context(|| format!("Parsing de {}", path.display()))
}

/// Load and parse `./nevelio.toml` (project config).
/// Returns `ProjectConfig::default()` if the file is absent.
pub fn load_project(path: Option<&Path>) -> Result<ProjectConfig> {
    let resolved = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("nevelio.toml"));

    if !resolved.exists() {
        return Ok(ProjectConfig::default());
    }

    let content = std::fs::read_to_string(&resolved)
        .with_context(|| format!("Lecture de {}", resolved.display()))?;

    toml::from_str(&content).with_context(|| format!("Parsing de {}", resolved.display()))
}

/// Write a `GlobalConfig` back to `~/.config/nevelio/config.toml`.
pub fn save_global(cfg: &GlobalConfig) -> Result<()> {
    let path = global_config_path().context("Impossible de déterminer le répertoire de config")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Création de {}", parent.display()))?;
    }

    let content = toml::to_string_pretty(cfg).context("Sérialisation de la config")?;

    std::fs::write(&path, content).with_context(|| format!("Écriture de {}", path.display()))
}
