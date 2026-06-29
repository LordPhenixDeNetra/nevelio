use serde::{Deserialize, Serialize};
use crate::{HardwareFinding, HwSeverity};

#[derive(Debug, Serialize, Deserialize)]
pub struct HwSummary {
    pub total:       usize,
    pub critical:    usize,
    pub high:        usize,
    pub medium:      usize,
    pub low:         usize,
    pub informative: usize,
}

impl HwSummary {
    pub fn from_findings(findings: &[HardwareFinding]) -> Self {
        Self {
            total:       findings.len(),
            critical:    findings.iter().filter(|f| f.severity == HwSeverity::Critical).count(),
            high:        findings.iter().filter(|f| f.severity == HwSeverity::High).count(),
            medium:      findings.iter().filter(|f| f.severity == HwSeverity::Medium).count(),
            low:         findings.iter().filter(|f| f.severity == HwSeverity::Low).count(),
            informative: findings.iter().filter(|f| f.severity == HwSeverity::Informative).count(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HwReport {
    pub generated_at: String,
    pub hostname:     String,
    pub summary:      HwSummary,
    pub findings:     Vec<HardwareFinding>,
}

impl HwReport {
    pub fn build(findings: Vec<HardwareFinding>) -> Self {
        let summary  = HwSummary::from_findings(&findings);
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let generated_at = chrono::Utc::now().to_rfc3339();
        Self { generated_at, hostname, summary, findings }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
