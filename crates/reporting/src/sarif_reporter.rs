use anyhow::Result;
use serde::Serialize;
use std::path::Path;

use nevelio_core::types::{Finding, Severity};
use crate::report_types::ScanReport;

// ---------------------------------------------------------------------------
// SARIF 2.1.0 structures
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'static str,
    version: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    properties: SarifRuleProps,
}

#[derive(Serialize)]
struct SarifRuleProps {
    #[serde(rename = "security-severity")]
    security_severity: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifText,
    locations: Vec<SarifLocation>,
    properties: SarifResultProps,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifResultProps {
    cvss_score: f64,
    module: String,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwe: Option<String>,
    proof: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_to_level(s: &Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Informative => "none",
    }
}

/// Derive a stable rule ID from the finding's CWE or title.
fn rule_id(f: &Finding) -> String {
    if let Some(ref cwe) = f.cwe {
        cwe.clone()
    } else {
        // slug: first segment of the title, letters/digits only
        let slug: String = f
            .title
            .chars()
            .take(40)
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .trim_matches('-')
            .to_string();
        format!("NEVELIO-{}", slug)
    }
}

fn build_rules(findings: &[Finding]) -> Vec<SarifRule> {
    let mut seen = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for f in findings {
        let id = rule_id(f);
        if seen.insert(id.clone()) {
            let help = f.references.first().cloned();
            rules.push(SarifRule {
                id,
                name: f
                    .title
                    .split_whitespace()
                    .next()
                    .unwrap_or("Finding")
                    .to_string(),
                short_description: SarifText { text: f.title.clone() },
                help_uri: help,
                properties: SarifRuleProps {
                    security_severity: format!("{:.1}", f.cvss_score),
                },
            });
        }
    }

    rules
}

fn build_result(f: &Finding) -> SarifResult {
    SarifResult {
        rule_id: rule_id(f),
        level: severity_to_level(&f.severity),
        message: SarifText {
            text: if f.description.is_empty() { f.title.clone() } else { f.description.clone() },
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation { uri: f.endpoint.clone() },
            },
        }],
        properties: SarifResultProps {
            cvss_score: f.cvss_score,
            module: f.module.clone(),
            method: f.method.clone(),
            cwe: f.cwe.clone(),
            proof: f.proof.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub struct SarifReporter;

impl SarifReporter {
    pub fn generate(report: &ScanReport) -> String {
        let rules = build_rules(&report.findings);
        let results: Vec<SarifResult> = report.findings.iter().map(build_result).collect();

        let log = SarifLog {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Nevelio",
                        version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/your-org/nevelio",
                        rules,
                    },
                },
                results,
            }],
        };

        serde_json::to_string_pretty(&log).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn write_to_file(report: &ScanReport, path: &Path) -> Result<()> {
        let sarif = Self::generate(report);
        std::fs::write(path, sarif)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_types::ReportSummary;
    use chrono::Utc;

    fn make_report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            scan_id: "test".to_string(),
            target: "https://example.com".to_string(),
            started_at: Utc::now(),
            finished_at: None,
            duration_secs: 0.0,
            profile: "normal".to_string(),
            summary: ReportSummary::from_findings(&findings),
            findings,
            locale: "en".to_string(),
        }
    }

    #[test]
    fn sarif_empty_findings() {
        let report = make_report(vec![]);
        let sarif = SarifReporter::generate(&report);
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("\"results\": []"));
    }

    #[test]
    fn sarif_severity_levels() {
        assert_eq!(severity_to_level(&Severity::Critical), "error");
        assert_eq!(severity_to_level(&Severity::High), "error");
        assert_eq!(severity_to_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_level(&Severity::Low), "note");
        assert_eq!(severity_to_level(&Severity::Informative), "none");
    }

    #[test]
    fn sarif_finding_produces_result_and_rule() {
        let mut f = Finding::new(
            "SQL Injection",
            Severity::Critical,
            9.8,
            "injection",
            "https://api.example.com/users",
            "GET",
        );
        f.cwe = Some("CWE-89".to_string());
        let report = make_report(vec![f]);
        let sarif = SarifReporter::generate(&report);
        assert!(sarif.contains("CWE-89"));
        assert!(sarif.contains("\"level\": \"error\""));
        assert!(sarif.contains("api.example.com"));
    }

    #[test]
    fn sarif_deduplicates_rules() {
        // Two findings with same CWE should produce one rule
        let mut f1 = Finding::new("SQLi boolean", Severity::Critical, 9.8, "injection", "https://x.com/a", "GET");
        f1.cwe = Some("CWE-89".to_string());
        let mut f2 = Finding::new("SQLi time", Severity::Critical, 9.8, "injection", "https://x.com/b", "GET");
        f2.cwe = Some("CWE-89".to_string());
        let report = make_report(vec![f1, f2]);
        let sarif = SarifReporter::generate(&report);
        // Exactly one rule entry for CWE-89
        assert_eq!(sarif.matches("\"id\": \"CWE-89\"").count(), 1);
        // Two results
        assert_eq!(sarif.matches("\"ruleId\"").count(), 2);
    }
}
