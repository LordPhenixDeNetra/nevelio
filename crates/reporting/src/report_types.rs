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
}
