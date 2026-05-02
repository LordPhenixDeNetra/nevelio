use chrono::{DateTime, Utc};
use nevelio_core::types::{Finding, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    #[default]
    Json,
    Html,
    Markdown,
    Junit,
    Sarif,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informative: usize,
    pub total: usize,
}

impl ReportSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self::default();
        for f in findings {
            s.total += 1;
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Informative => s.informative += 1,
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: Severity) -> Finding {
        Finding::new("T", severity, 1.0, "m", "u", "GET")
    }

    #[test]
    fn report_summary_counts_correctly() {
        let findings = vec![
            make_finding(Severity::Critical),
            make_finding(Severity::Critical),
            make_finding(Severity::High),
            make_finding(Severity::Medium),
            make_finding(Severity::Low),
            make_finding(Severity::Informative),
        ];
        let s = ReportSummary::from_findings(&findings);
        assert_eq!(s.critical, 2);
        assert_eq!(s.high, 1);
        assert_eq!(s.medium, 1);
        assert_eq!(s.low, 1);
        assert_eq!(s.informative, 1);
        assert_eq!(s.total, 6);
    }

    #[test]
    fn report_summary_empty() {
        let s = ReportSummary::from_findings(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.critical, 0);
    }

    #[test]
    fn json_reporter_round_trip() {
        use crate::json_reporter::JsonReporter;
        use nevelio_core::ScanSession;
        use nevelio_core::types::ScanConfig;
        use std::path::PathBuf;

        let config = ScanConfig {
            target: "https://example.com".to_string(),
            profile: nevelio_core::types::ScanProfile::Normal,
            concurrency: 20,
            rate_limit: 50,
            timeout_ms: 5000,
            auth_token: None,
            proxy: None,
            verbose: false,
            out_dir: PathBuf::from("."),
            modules: vec![],
            dry_run: false,
            locale: "en".to_string(),
        };
        let mut session = ScanSession::new(config);
        session.add_finding(make_finding(Severity::High));
        session.finish();

        let report = JsonReporter::generate(&session);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.high, 1);
        assert_eq!(report.target, "https://example.com");

        let json = serde_json::to_string(&report).expect("should serialize");
        assert!(json.contains("HIGH"));
        assert!(json.contains("example.com"));
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub duration_secs: f64,
    pub profile: String,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
    #[serde(default = "default_locale")]
    pub locale: String,
}

fn default_locale() -> String {
    "en".to_string()
}
