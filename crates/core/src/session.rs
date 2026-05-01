use chrono::{DateTime, Utc};
use crate::types::{Finding, ScanConfig};

pub struct ScanSession {
    pub id: String,
    pub config: ScanConfig,
    pub findings: Vec<Finding>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
}

impl ScanSession {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            config,
            findings: Vec::new(),
            start_time: Utc::now(),
            end_time: None,
        }
    }

    pub fn finish(&mut self) {
        self.end_time = Some(Utc::now());
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
}
