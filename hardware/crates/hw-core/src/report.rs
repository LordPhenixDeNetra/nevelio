use serde::{Deserialize, Serialize};
use crate::{HardwareFinding, HwSeverity};

/// Résumé statistique d'un rapport d'audit.
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

    /// Sérialise le rapport en JSON (format natif nevelio-hw).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Exporte le rapport au format compatible nevelio principal.
    ///
    /// Le format nevelio principal attend :
    /// ```json
    /// { "tool": "nevelio-hw", "version": "...", "timestamp": "...",
    ///   "findings": [ { "id": "HW-001", "title": "...", "severity": "HIGH",
    ///                   "module": "hw-cpu", "description": "...", "cvss": 7.5,
    ///                   "cwe": 1342, "evidence": "...", "remediation": "..." } ] }
    /// ```
    pub fn to_nevelio_json(&self) -> String {
        #[derive(Serialize)]
        struct NevelioFinding<'a> {
            id:          String,
            title:       &'a str,
            severity:    &'a str,
            module:      &'a str,
            description: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            cvss:        Option<f32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            cwe:         Option<u32>,
            evidence:    &'a str,
            remediation: &'a str,
            source:      &'static str,
        }

        #[derive(Serialize)]
        struct NevelioReport<'a> {
            tool:        &'static str,
            version:     &'static str,
            timestamp:   &'a str,
            hostname:    &'a str,
            summary:     &'a HwSummary,
            findings:    Vec<NevelioFinding<'a>>,
        }

        let sev_str = |s: &HwSeverity| match s {
            HwSeverity::Critical    => "CRITICAL",
            HwSeverity::High        => "HIGH",
            HwSeverity::Medium      => "MEDIUM",
            HwSeverity::Low         => "LOW",
            HwSeverity::Informative => "INFORMATIVE",
        };

        let nevelio_findings: Vec<NevelioFinding<'_>> = self.findings
            .iter()
            .enumerate()
            .map(|(i, f)| NevelioFinding {
                id:          format!("HW-{:04}", i + 1),
                title:       &f.title,
                severity:    sev_str(&f.severity),
                module:      &f.module,
                description: &f.description,
                cvss:        f.cvss,
                cwe:         f.cwe,
                evidence:    &f.evidence,
                remediation: &f.remediation,
                source:      "nevelio-hw",
            })
            .collect();

        let report = NevelioReport {
            tool:      "nevelio-hw",
            version:   env!("CARGO_PKG_VERSION"),
            timestamp: &self.generated_at,
            hostname:  &self.hostname,
            summary:   &self.summary,
            findings:  nevelio_findings,
        };

        serde_json::to_string_pretty(&report).unwrap_or_default()
    }
}
