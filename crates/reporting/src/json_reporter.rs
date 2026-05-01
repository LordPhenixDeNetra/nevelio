use anyhow::Result;
use nevelio_core::session::ScanSession;
use std::path::Path;

use crate::report_types::{ReportSummary, ScanReport};

pub struct JsonReporter;

impl JsonReporter {
    pub fn generate(session: &ScanSession) -> ScanReport {
        let duration = session
            .end_time
            .map(|end| (end - session.start_time).num_milliseconds() as f64 / 1000.0)
            .unwrap_or(0.0);

        ScanReport {
            scan_id: session.id.clone(),
            target: session.config.target.clone(),
            started_at: session.start_time,
            finished_at: session.end_time,
            duration_secs: duration,
            profile: format!("{:?}", session.config.profile).to_lowercase(),
            summary: ReportSummary::from_findings(&session.findings),
            findings: session.findings.clone(),
        }
    }

    pub fn write_to_file(report: &ScanReport, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
