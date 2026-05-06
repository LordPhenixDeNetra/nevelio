use colored::Colorize;
use nevelio_core::types::{Finding, Severity};
use rust_i18n::t;

pub fn print_finding(finding: &Finding) {
    let badge = match finding.severity {
        Severity::Critical => " CRITICAL    ".on_red().white().bold(),
        Severity::High => " HIGH        ".on_bright_red().white().bold(),
        Severity::Medium => " MEDIUM      ".on_yellow().black().bold(),
        Severity::Low => " LOW         ".on_blue().white().bold(),
        Severity::Informative => " INFORMATIVE ".on_white().black(),
    };
    println!(
        "  {}  {}  {}",
        badge,
        finding.title.bold(),
        finding.endpoint.dimmed()
    );
}

pub fn print_summary(findings: &[Finding]) {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
    let informative = findings.iter().filter(|f| f.severity == Severity::Informative).count();

    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan());
    println!(
        "{}",
        t!(
            "scan.summary",
            c = critical,
            h = high,
            m = medium,
            l = low,
            i = informative
        )
    );
}
