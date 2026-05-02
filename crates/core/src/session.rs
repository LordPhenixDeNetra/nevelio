use chrono::{DateTime, Utc};
use std::collections::HashSet;
use crate::types::{Finding, ScanConfig};

pub struct ScanSession {
    pub id: String,
    pub config: ScanConfig,
    pub findings: Vec<Finding>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    seen: HashSet<String>,
}

impl ScanSession {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            config,
            findings: Vec::new(),
            start_time: Utc::now(),
            end_time: None,
            seen: HashSet::new(),
        }
    }

    pub fn finish(&mut self) {
        self.end_time = Some(Utc::now());
    }

    pub fn add_finding(&mut self, finding: Finding) {
        let key = format!("{}|{}|{}", finding.module, finding.title, finding.endpoint);
        if self.seen.insert(key) {
            self.findings.push(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanProfile, Severity};
    use std::path::PathBuf;

    fn make_session() -> ScanSession {
        ScanSession::new(ScanConfig {
            target: "https://example.com".to_string(),
            profile: ScanProfile::Normal,
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
        })
    }

    #[test]
    fn dedup_prevents_duplicate_findings() {
        let mut session = make_session();
        let f = Finding::new("SQLi", Severity::Critical, 9.8, "injection", "https://x.com/q", "GET");
        session.add_finding(f.clone());
        session.add_finding(f);
        assert_eq!(session.findings.len(), 1);
    }

    #[test]
    fn different_endpoints_not_deduped() {
        let mut session = make_session();
        let f1 = Finding::new("SQLi", Severity::Critical, 9.8, "injection", "https://x.com/a", "GET");
        let f2 = Finding::new("SQLi", Severity::Critical, 9.8, "injection", "https://x.com/b", "GET");
        session.add_finding(f1);
        session.add_finding(f2);
        assert_eq!(session.findings.len(), 2);
    }

    #[test]
    fn different_titles_not_deduped() {
        let mut session = make_session();
        let f1 = Finding::new("SQLi", Severity::Critical, 9.8, "injection", "https://x.com/q", "GET");
        let f2 = Finding::new("XSS", Severity::High, 7.5, "injection", "https://x.com/q", "GET");
        session.add_finding(f1);
        session.add_finding(f2);
        assert_eq!(session.findings.len(), 2);
    }

    #[test]
    fn session_finish_sets_end_time() {
        let mut session = make_session();
        assert!(session.end_time.is_none());
        session.finish();
        assert!(session.end_time.is_some());
    }
}
