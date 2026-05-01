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
