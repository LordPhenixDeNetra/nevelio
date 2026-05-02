use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Informative,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Informative => write!(f, "INFORMATIVE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss_score: f64,
    /// CVSS v3.1 vector string, e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    pub cvss_vector: Option<String>,
    pub module: String,
    pub endpoint: String,
    pub method: String,
    pub description: String,
    pub proof: String,
    pub recommendation: String,
    pub cwe: Option<String>,
    pub references: Vec<String>,
    pub discovered_at: DateTime<Utc>,
}

impl Finding {
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        cvss_score: f64,
        module: impl Into<String>,
        endpoint: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.into(),
            severity,
            cvss_score,
            cvss_vector: None,
            module: module.into(),
            endpoint: endpoint.into(),
            method: method.into(),
            description: String::new(),
            proof: String::new(),
            recommendation: String::new(),
            cwe: None,
            references: Vec::new(),
            discovered_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    Stealth,
    #[default]
    Normal,
    Aggressive,
}

impl ScanProfile {
    pub fn concurrency(&self) -> usize {
        match self {
            Self::Stealth => 5,
            Self::Normal => 20,
            Self::Aggressive => 100,
        }
    }

    pub fn rate_limit_per_sec(&self) -> u64 {
        match self {
            Self::Stealth => 10,
            Self::Normal => 50,
            Self::Aggressive => 200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub full_url: String,
    pub parameters: Vec<Parameter>,
    pub auth_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Informative);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::Informative.to_string(), "INFORMATIVE");
    }

    #[test]
    fn finding_new_has_id_and_fields() {
        let f = Finding::new("XSS", Severity::High, 7.5, "injection", "https://x.com/q", "GET");
        assert!(!f.id.is_empty());
        assert_eq!(f.title, "XSS");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.cvss_score, 7.5);
        assert_eq!(f.module, "injection");
        assert_eq!(f.method, "GET");
        assert!(f.description.is_empty());
        assert!(f.cwe.is_none());
    }

    #[test]
    fn finding_ids_are_unique() {
        let a = Finding::new("A", Severity::Low, 1.0, "m", "u", "GET");
        let b = Finding::new("B", Severity::Low, 1.0, "m", "u", "GET");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn scan_profile_concurrency() {
        assert_eq!(ScanProfile::Stealth.concurrency(), 5);
        assert_eq!(ScanProfile::Normal.concurrency(), 20);
        assert_eq!(ScanProfile::Aggressive.concurrency(), 100);
    }

    #[test]
    fn scan_profile_rate_limit() {
        assert_eq!(ScanProfile::Stealth.rate_limit_per_sec(), 10);
        assert_eq!(ScanProfile::Normal.rate_limit_per_sec(), 50);
        assert_eq!(ScanProfile::Aggressive.rate_limit_per_sec(), 200);
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub profile: ScanProfile,
    pub concurrency: usize,
    pub rate_limit: u64,
    pub timeout_ms: u64,
    pub auth_token: Option<String>,
    pub proxy: Option<String>,
    pub verbose: bool,
    pub out_dir: PathBuf,
    pub modules: Vec<String>,
    pub dry_run: bool,
}
