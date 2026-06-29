use serde::{Deserialize, Serialize};
use std::fmt;

mod report;
pub use report::{HwReport, HwSummary};

// ── Sévérité ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HwSeverity {
    Informative,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for HwSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical    => write!(f, "CRITICAL"),
            Self::High        => write!(f, "HIGH"),
            Self::Medium      => write!(f, "MEDIUM"),
            Self::Low         => write!(f, "LOW"),
            Self::Informative => write!(f, "INFORMATIVE"),
        }
    }
}

// ── Finding ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareFinding {
    pub title:       String,
    pub description: String,
    pub severity:    HwSeverity,
    pub module:      String,
    pub cwe:         Option<u32>,
    pub cvss:        Option<f32>,
    pub evidence:    String,
    pub remediation: String,
}

impl HardwareFinding {
    pub fn new(
        title:       impl Into<String>,
        description: impl Into<String>,
        severity:    HwSeverity,
        module:      impl Into<String>,
        cwe:         Option<u32>,
        cvss:        Option<f32>,
        evidence:    impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            title:       title.into(),
            description: description.into(),
            severity,
            module:      module.into(),
            cwe,
            cvss,
            evidence:    evidence.into(),
            remediation: remediation.into(),
        }
    }
}

// ── Trait module ──────────────────────────────────────────────────────────────

pub trait HwModule: Send + Sync {
    fn name(&self)        -> &'static str;
    fn description(&self) -> &'static str;
    fn run(&self, dry_run: bool) -> Vec<HardwareFinding>;
}

// ── Helpers subprocess ────────────────────────────────────────────────────────

/// Exécute une commande et retourne sa sortie stdout sous forme de String.
/// Retourne None si la commande n'est pas disponible ou échoue.
pub fn run_command(program: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Lit un fichier sysfs et retourne son contenu trimmé.
pub fn read_sysfs(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(HwSeverity::Critical > HwSeverity::High);
        assert!(HwSeverity::High    > HwSeverity::Medium);
        assert!(HwSeverity::Medium  > HwSeverity::Low);
        assert!(HwSeverity::Low     > HwSeverity::Informative);
    }

    #[test]
    fn finding_display() {
        let f = HardwareFinding::new(
            "Test", "desc", HwSeverity::Critical, "hw-cpu",
            Some(1342), Some(8.1), "evidence", "remediation",
        );
        assert_eq!(f.severity.to_string(), "CRITICAL");
        assert_eq!(f.cwe, Some(1342));
    }
}
