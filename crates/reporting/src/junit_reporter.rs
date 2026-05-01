use anyhow::Result;
use std::path::Path;

use crate::report_types::ScanReport;
use nevelio_core::types::Severity;

pub struct JunitReporter;

impl JunitReporter {
    pub fn generate(report: &ScanReport) -> String {
        let total = report.findings.len();
        let failures = report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .count();

        let mut xml = String::with_capacity(4096);
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<testsuites name=\"Nevelio Security Scan\" tests=\"{}\" failures=\"{}\" time=\"{:.3}\">\n",
            total, failures, report.duration_secs
        ));

        // Group findings by module → one <testsuite> per module
        let mut modules: Vec<String> = report
            .findings
            .iter()
            .map(|f| f.module.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        modules.sort();

        // Also add findings with no match (shouldn't happen, but safety net)
        if modules.is_empty() && total > 0 {
            modules.push("unknown".to_string());
        }

        for module in &modules {
            let group: Vec<_> = report
                .findings
                .iter()
                .filter(|f| &f.module == module)
                .collect();
            let mod_failures = group
                .iter()
                .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
                .count();

            xml.push_str(&format!(
                "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\">\n",
                escape_xml(module),
                group.len(),
                mod_failures
            ));

            for f in &group {
                let classname = format!("{}.{}", escape_xml(module), sanitize_name(&f.endpoint));
                xml.push_str(&format!(
                    "    <testcase name=\"{}\" classname=\"{}\" time=\"0\">\n",
                    escape_xml(&f.title),
                    classname
                ));

                match f.severity {
                    Severity::Critical | Severity::High => {
                        xml.push_str(&format!(
                            "      <failure message=\"{} | CVSS {} | {}\">{}</failure>\n",
                            escape_xml(&f.severity.to_string()),
                            f.cvss_score,
                            escape_xml(&f.endpoint),
                            escape_xml(&f.description)
                        ));
                    }
                    Severity::Medium | Severity::Low => {
                        xml.push_str(&format!(
                            "      <system-out>[{}] {} — {}</system-out>\n",
                            escape_xml(&f.severity.to_string()),
                            escape_xml(&f.title),
                            escape_xml(&f.endpoint)
                        ));
                    }
                    Severity::Informative => {
                        xml.push_str(&format!(
                            "      <skipped message=\"{}\"/>\n",
                            escape_xml(&f.title)
                        ));
                    }
                }

                xml.push_str("    </testcase>\n");
            }

            xml.push_str("  </testsuite>\n");
        }

        // Empty testsuite if no findings (so CI tools see the suite)
        if modules.is_empty() {
            xml.push_str("  <testsuite name=\"nevelio\" tests=\"0\" failures=\"0\"/>\n");
        }

        xml.push_str("</testsuites>\n");
        xml
    }

    pub fn write_to_file(report: &ScanReport, path: &Path) -> Result<()> {
        std::fs::write(path, Self::generate(report))?;
        Ok(())
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect()
}
