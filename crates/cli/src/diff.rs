use anyhow::{Context, Result};
use colored::Colorize;
use nevelio_core::types::{Finding, Severity};
use nevelio_reporting::ScanReport;
use std::collections::HashMap;
use std::path::Path;

use crate::args::{DiffArgs, FailOnArg};

/// Compare two scan reports and report regressions.
///
/// Exit codes:
///   0 — no new findings
///   1 — new LOW/MEDIUM findings
///   2 — new HIGH/CRITICAL findings
pub async fn handle_diff(args: DiffArgs) -> Result<()> {
    let before = load_report(&args.before)?;
    let after = load_report(&args.after)?;

    type Key = (String, String, String); // (title, endpoint, method)

    let before_map: HashMap<Key, &Finding> = before
        .findings
        .iter()
        .map(|f| ((f.title.clone(), f.endpoint.clone(), f.method.clone()), f))
        .collect();

    let after_map: HashMap<Key, &Finding> = after
        .findings
        .iter()
        .map(|f| ((f.title.clone(), f.endpoint.clone(), f.method.clone()), f))
        .collect();

    // New findings: in `after` but not in `before`
    let mut new_findings: Vec<&Finding> = after
        .findings
        .iter()
        .filter(|f| {
            !before_map.contains_key(&(f.title.clone(), f.endpoint.clone(), f.method.clone()))
        })
        .collect();
    new_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Resolved findings: in `before` but not in `after`
    let mut resolved: Vec<&Finding> = before
        .findings
        .iter()
        .filter(|f| {
            !after_map.contains_key(&(f.title.clone(), f.endpoint.clone(), f.method.clone()))
        })
        .collect();
    resolved.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Severity changes: same finding key, different severity
    let mut changed: Vec<(&Finding, &Finding)> = after
        .findings
        .iter()
        .filter_map(|af| {
            let key = (af.title.clone(), af.endpoint.clone(), af.method.clone());
            before_map.get(&key).and_then(|bf| {
                if bf.severity != af.severity {
                    Some((*bf, af))
                } else {
                    None
                }
            })
        })
        .collect();
    changed.sort_by(|a, b| b.1.severity.cmp(&a.1.severity));

    // ── Print header ──────────────────────────────────────────────────────────

    println!("{}", "═".repeat(64).cyan());
    println!("  {}", "Nevelio — Rapport de diff".bold());
    println!(
        "  {} {} {}",
        args.before.display().to_string().dimmed(),
        "→".dimmed(),
        args.after.display().to_string().dimmed()
    );
    println!("{}", "═".repeat(64).cyan());
    println!();
    println!(
        "  Baseline : {} finding(s)  —  {}",
        before.findings.len().to_string().bold(),
        before.target.dimmed()
    );
    println!(
        "  Nouveau  : {} finding(s)  —  {}",
        after.findings.len().to_string().bold(),
        after.target.dimmed()
    );
    println!();

    // ── New findings ──────────────────────────────────────────────────────────

    if new_findings.is_empty() {
        println!("{}", "✓  Aucun nouveau finding".green().bold());
    } else {
        println!(
            "{}",
            format!("⚠  {} nouveau(x) finding(s)", new_findings.len())
                .red()
                .bold()
        );
        for f in &new_findings {
            let sev = severity_badge(&f.severity);
            println!(
                "   {} {} — {} {}",
                sev,
                f.title.bold(),
                f.method.dimmed(),
                f.endpoint
            );
        }
    }
    println!();

    // ── Resolved findings ─────────────────────────────────────────────────────

    if !resolved.is_empty() {
        println!(
            "{}",
            format!("✓  {} finding(s) résolu(s)", resolved.len()).green()
        );
        for f in &resolved {
            println!(
                "   {} {} — {} {}",
                severity_badge(&f.severity),
                f.title.dimmed(),
                f.method.dimmed(),
                f.endpoint.dimmed()
            );
        }
        println!();
    }

    // ── Severity changes ──────────────────────────────────────────────────────

    if !changed.is_empty() {
        println!(
            "{}",
            format!("⚡  {} changement(s) de sévérité", changed.len()).yellow()
        );
        for (bf, af) in &changed {
            println!(
                "   {} → {}  {} — {} {}",
                format!("{}", bf.severity).dimmed(),
                severity_badge(&af.severity),
                af.title.bold(),
                af.method.dimmed(),
                af.endpoint
            );
        }
        println!();
    }

    // ── Exit code ─────────────────────────────────────────────────────────────

    let exit_code = compute_exit_code(&new_findings, args.fail_on);

    if exit_code == 0 {
        println!("{}", "✅  Pas de régression détectée.".green().bold());
    } else {
        println!(
            "{}",
            format!("❌  Régression détectée — exit code {}", exit_code)
                .red()
                .bold()
        );
    }

    std::process::exit(exit_code);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_report(path: &Path) -> Result<ScanReport> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read '{}'", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("Invalid JSON in '{}'", path.display()))
}

fn severity_badge(s: &Severity) -> colored::ColoredString {
    let label = format!("[{s}]");
    match s {
        Severity::Critical => label.red().bold(),
        Severity::High => label.red(),
        Severity::Medium => label.yellow(),
        Severity::Low => label.blue(),
        Severity::Informative => label.dimmed(),
    }
}

fn compute_exit_code(new_findings: &[&Finding], fail_on: Option<FailOnArg>) -> i32 {
    match fail_on {
        // Explicit threshold
        Some(FailOnArg::None) => 0,
        Some(threshold) => {
            let min_sev = match threshold {
                FailOnArg::Low => Severity::Low,
                FailOnArg::Medium => Severity::Medium,
                FailOnArg::High => Severity::High,
                FailOnArg::Critical => Severity::Critical,
                FailOnArg::None => unreachable!(),
            };
            if new_findings.iter().any(|f| f.severity >= min_sev) {
                1
            } else {
                0
            }
        }
        // Default tiered exit code
        None => {
            if new_findings
                .iter()
                .any(|f| matches!(f.severity, Severity::Critical | Severity::High))
            {
                2
            } else if !new_findings.is_empty() {
                1
            } else {
                0
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_0_when_no_new_findings() {
        assert_eq!(compute_exit_code(&[], None), 0);
    }

    fn make_finding(sev: Severity) -> Finding {
        nevelio_core::types::Finding::new("Test", sev, 5.0, "module", "https://x.com/", "GET")
    }

    #[test]
    fn exit_code_1_for_medium_findings() {
        let f = make_finding(Severity::Medium);
        assert_eq!(compute_exit_code(&[&f], None), 1);
    }

    #[test]
    fn exit_code_2_for_critical_findings() {
        let f = make_finding(Severity::Critical);
        assert_eq!(compute_exit_code(&[&f], None), 2);
    }

    #[test]
    fn fail_on_overrides_default() {
        let f = make_finding(Severity::Low);
        // fail_on = High: Low finding → exit 0
        assert_eq!(compute_exit_code(&[&f], Some(FailOnArg::High)), 0);
        // fail_on = Low: Low finding → exit 1
        assert_eq!(compute_exit_code(&[&f], Some(FailOnArg::Low)), 1);
    }
}
