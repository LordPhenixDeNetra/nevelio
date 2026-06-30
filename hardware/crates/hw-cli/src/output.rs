use colored::Colorize;
use hw_core::{HwReport, HwSeverity};
use rust_i18n::t;

pub fn render_text(report: &HwReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "\n  {} {}\n",
        "⚙".cyan(),
        t!("output.report_title")
    ));
    out.push_str(&format!(
        "  {} {:<13}: {}\n",
        "·".dimmed(), t!("output.host_label"), report.hostname
    ));
    out.push_str(&format!(
        "  {} {:<13}: {}\n",
        "·".dimmed(), t!("output.generated_label"), report.generated_at
    ));
    out.push_str(&format!(
        "  {} {:<13}: {} {}  [{} CRIT  {} HIGH  {} MED  {} LOW]\n\n",
        "·".dimmed(),
        t!("output.summary_label"),
        report.summary.total.to_string().bold(),
        t!("output.findings_word"),
        colorize_count(report.summary.critical, HwSeverity::Critical),
        colorize_count(report.summary.high,     HwSeverity::High),
        colorize_count(report.summary.medium,   HwSeverity::Medium),
        colorize_count(report.summary.low,      HwSeverity::Low),
    ));

    if report.findings.is_empty() {
        out.push_str(&format!(
            "  {}  {}\n\n",
            "✓".green(),
            t!("output.no_findings")
        ));
        return out;
    }

    out.push_str(&format!("  {} ─────────────────────────────────────────\n\n", "┌".dimmed()));

    for (i, f) in report.findings.iter().enumerate() {
        let sev_badge = severity_badge(&f.severity);
        let cwe_str  = f.cwe.map(|c| format!(" CWE-{}", c)).unwrap_or_default();
        let cvss_str = f.cvss.map(|v| format!(" CVSS {:.1}", v)).unwrap_or_default();

        out.push_str(&format!(
            "  [{:>3}] {}{}{}  {}\n",
            i + 1, sev_badge,
            cwe_str.dimmed(), cvss_str.dimmed(),
            f.title.bold()
        ));
        out.push_str(&format!(
            "        {:<13}: {}\n", t!("output.field_module"), f.module.cyan()
        ));
        out.push_str(&format!(
            "        {:<13}: {}\n", t!("output.field_detail"),
            wrap_text(&f.description, 66, 22)
        ));
        out.push_str(&format!(
            "        {:<13}: {}\n", t!("output.field_evidence"),
            wrap_text(&f.evidence, 66, 22).dimmed()
        ));
        out.push_str(&format!(
            "        {:<13}: {}\n\n", t!("output.field_remediation"),
            wrap_text(&f.remediation, 66, 22).yellow()
        ));
    }

    out.push_str(&format!("  {} ─────────────────────────────────────────\n\n", "└".dimmed()));
    out
}

fn severity_badge(sev: &HwSeverity) -> colored::ColoredString {
    match sev {
        HwSeverity::Critical    => "[CRITICAL]   ".red().bold(),
        HwSeverity::High        => "[HIGH]       ".red(),
        HwSeverity::Medium      => "[MEDIUM]     ".yellow(),
        HwSeverity::Low         => "[LOW]        ".blue(),
        HwSeverity::Informative => "[INFO]       ".dimmed(),
    }
}

fn colorize_count(count: usize, sev: HwSeverity) -> colored::ColoredString {
    let s = count.to_string();
    if count == 0 { return s.dimmed(); }
    match sev {
        HwSeverity::Critical => s.red().bold(),
        HwSeverity::High     => s.red(),
        HwSeverity::Medium   => s.yellow(),
        HwSeverity::Low      => s.blue(),
        _                    => s.dimmed(),
    }
}

fn wrap_text(text: &str, width: usize, indent: usize) -> String {
    if text.len() <= width { return text.to_string(); }
    let pad = " ".repeat(indent);
    let mut result = String::new();
    let mut line_len = 0;
    for word in text.split_whitespace() {
        if line_len + word.len() + 1 > width && line_len > 0 {
            result.push('\n');
            result.push_str(&pad);
            line_len = 0;
        } else if line_len > 0 {
            result.push(' ');
            line_len += 1;
        }
        result.push_str(word);
        line_len += word.len();
    }
    result
}
