use anyhow::Result;
use chrono::Utc;
use std::path::Path;

use crate::report_types::ScanReport;
use nevelio_core::types::Severity;

pub struct MarkdownReporter;

impl MarkdownReporter {
    pub fn generate(report: &ScanReport) -> String {
        let mut md = String::with_capacity(4096);

        // Header
        md.push_str("# Nevelio — Rapport de Sécurité API\n\n");
        md.push_str(&format!(
            "_Généré le {} | Scan ID: {}_\n\n",
            Utc::now().format("%Y-%m-%d %H:%M UTC"),
            report.scan_id
        ));

        // Scan info table
        md.push_str("## Informations du scan\n\n");
        md.push_str("| Champ | Valeur |\n|---|---|\n");
        md.push_str(&format!("| Cible | `{}` |\n", report.target));
        md.push_str(&format!("| Profil | {} |\n", report.profile));
        md.push_str(&format!("| Démarré | {} |\n", report.started_at));
        md.push_str(&format!(
            "| Durée | {:.2}s |\n",
            report.duration_secs
        ));
        md.push('\n');

        // Summary
        md.push_str("## Résumé\n\n");
        md.push_str("| Sévérité | Nombre |\n|---|---|\n");
        md.push_str(&format!("| 🔴 Critical | {} |\n", report.summary.critical));
        md.push_str(&format!("| 🟠 High | {} |\n", report.summary.high));
        md.push_str(&format!("| 🟡 Medium | {} |\n", report.summary.medium));
        md.push_str(&format!("| 🔵 Low | {} |\n", report.summary.low));
        md.push_str(&format!(
            "| ⚪ Informative | {} |\n",
            report.summary.informative
        ));
        md.push_str(&format!("| **Total** | **{}** |\n\n", report.summary.total));

        if report.findings.is_empty() {
            md.push_str("✅ **Aucun finding détecté.**\n");
            return md;
        }

        // Findings grouped by severity
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Informative,
        ] {
            let group: Vec<_> = report
                .findings
                .iter()
                .filter(|f| f.severity == severity)
                .collect();

            if group.is_empty() {
                continue;
            }

            let (icon, label) = match severity {
                Severity::Critical => ("🔴", "CRITICAL"),
                Severity::High => ("🟠", "HIGH"),
                Severity::Medium => ("🟡", "MEDIUM"),
                Severity::Low => ("🔵", "LOW"),
                Severity::Informative => ("⚪", "INFORMATIVE"),
            };

            md.push_str(&format!("## {} {} Findings\n\n", icon, label));

            for (i, f) in group.iter().enumerate() {
                md.push_str(&format!("### {}.{} {}\n\n", label, i + 1, f.title));

                md.push_str("| Champ | Valeur |\n|---|---|\n");
                md.push_str(&format!("| Module | `{}` |\n", f.module));
                md.push_str(&format!(
                    "| Endpoint | `{} {}` |\n",
                    f.method, f.endpoint
                ));
                if f.cvss_score > 0.0 {
                    md.push_str(&format!("| CVSS | {} |\n", f.cvss_score));
                }
                if let Some(ref cwe) = f.cwe {
                    md.push_str(&format!("| CWE | {} |\n", cwe));
                }
                md.push_str(&format!("| Découvert | {} |\n\n", f.discovered_at));

                if !f.description.is_empty() {
                    md.push_str("**Description**\n\n");
                    md.push_str(&f.description);
                    md.push_str("\n\n");
                }

                if !f.recommendation.is_empty() {
                    md.push_str("**Recommandation**\n\n");
                    md.push_str(&f.recommendation);
                    md.push_str("\n\n");
                }

                if !f.proof.is_empty() {
                    md.push_str("**Preuve**\n\n```\n");
                    md.push_str(&f.proof);
                    md.push_str("\n```\n\n");
                }

                if !f.references.is_empty() {
                    md.push_str("**Références**\n\n");
                    for r in &f.references {
                        md.push_str(&format!("- <{}>\n", r));
                    }
                    md.push('\n');
                }

                md.push_str("---\n\n");
            }
        }

        md.push_str(
            "_Généré par Nevelio v0.1.0 — Usage autorisé uniquement sur systèmes avec autorisation explicite._\n",
        );
        md
    }

    pub fn write_to_file(report: &ScanReport, path: &Path) -> Result<()> {
        std::fs::write(path, Self::generate(report))?;
        Ok(())
    }
}
