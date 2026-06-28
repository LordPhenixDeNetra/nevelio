mod channels;
mod email;
mod pagerduty;
mod webhook;

use anyhow::{Context, Result};
use colored::Colorize;
use nevelio_core::types::{Finding, Severity};
use nevelio_reporting::ScanReport;
use std::time::Duration;

use crate::args::{FailOnArg, NotifyArgs};

pub async fn handle_notify(args: NotifyArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.findings)
        .with_context(|| format!("Fichier introuvable : {}", args.findings.display()))?;
    let report: ScanReport =
        serde_json::from_str(&content).context("Format findings.json invalide")?;

    let to_notify: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| severity_meets_threshold(&f.severity, &args.min_severity))
        .collect();

    if to_notify.is_empty() {
        println!("  Aucun finding au-dessus du seuil {:?}. Rien à notifier.", args.min_severity);
        return Ok(());
    }

    let summary = build_summary(&report, &to_notify);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let mut sent = 0u32;

    if let Some(ref url) = args.slack {
        channels::send_slack(&client, url, &report, &to_notify, &summary)
            .await.context("Erreur envoi Slack")?;
        println!("  {} Slack notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref url) = args.teams {
        channels::send_teams(&client, url, &report, &to_notify, &summary)
            .await.context("Erreur envoi Teams")?;
        println!("  {} Microsoft Teams notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref url) = args.webhook {
        webhook::send_generic(&client, url, &report)
            .await.context("Erreur envoi webhook")?;
        println!("  {} Webhook notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref key) = args.pagerduty {
        pagerduty::send_pagerduty(&client, key, &report, &to_notify)
            .await.context("Erreur envoi PagerDuty")?;
        println!("  {} PagerDuty notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref smtp_addr) = args.smtp {
        if let Some(ref to) = args.email_to {
            let smtp_user = args.smtp_user.clone().or_else(|| std::env::var("SMTP_USER").ok());
            let smtp_pass = args.smtp_pass.clone().or_else(|| std::env::var("SMTP_PASS").ok());
            email::send_email(
                smtp_addr, smtp_user.as_deref(), smtp_pass.as_deref(),
                &args.email_from, to, &report, &to_notify, &summary,
            ).await.context("Erreur envoi email")?;
            println!("  {} Email envoyé à {}.", "✓".green(), to);
            sent += 1;
        } else {
            println!("  ⚠ --smtp fourni mais --email-to manquant.");
        }
    }

    if sent == 0 {
        println!("  Aucune destination configurée. Utilisez --slack, --teams, --webhook, --pagerduty ou --smtp.");
    }

    Ok(())
}

pub(crate) fn severity_meets_threshold(sev: &Severity, threshold: &FailOnArg) -> bool {
    match threshold {
        FailOnArg::None     => false,
        FailOnArg::Low      => true,
        FailOnArg::Medium   => !matches!(sev, Severity::Low | Severity::Informative),
        FailOnArg::High     => matches!(sev, Severity::High | Severity::Critical),
        FailOnArg::Critical => matches!(sev, Severity::Critical),
    }
}

fn build_summary(report: &ScanReport, findings: &[&Finding]) -> String {
    let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high     = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
    let medium   = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
    format!(
        "Nevelio — {} finding(s) sur {} | CRITICAL: {} | HIGH: {} | MEDIUM: {}",
        findings.len(), report.target, critical, high, medium
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_none_rejects_all() {
        assert!(!severity_meets_threshold(&Severity::Critical, &FailOnArg::None));
        assert!(!severity_meets_threshold(&Severity::Low, &FailOnArg::None));
    }

    #[test]
    fn threshold_low_accepts_all() {
        assert!(severity_meets_threshold(&Severity::Informative, &FailOnArg::Low));
        assert!(severity_meets_threshold(&Severity::Critical, &FailOnArg::Low));
    }

    #[test]
    fn threshold_medium_rejects_low_info() {
        assert!(!severity_meets_threshold(&Severity::Low, &FailOnArg::Medium));
        assert!(!severity_meets_threshold(&Severity::Informative, &FailOnArg::Medium));
        assert!(severity_meets_threshold(&Severity::Medium, &FailOnArg::Medium));
        assert!(severity_meets_threshold(&Severity::Critical, &FailOnArg::Medium));
    }

    #[test]
    fn threshold_high_only_high_critical() {
        assert!(!severity_meets_threshold(&Severity::Medium, &FailOnArg::High));
        assert!(severity_meets_threshold(&Severity::High, &FailOnArg::High));
        assert!(severity_meets_threshold(&Severity::Critical, &FailOnArg::High));
    }

    #[test]
    fn threshold_critical_only_critical() {
        assert!(!severity_meets_threshold(&Severity::High, &FailOnArg::Critical));
        assert!(severity_meets_threshold(&Severity::Critical, &FailOnArg::Critical));
    }
}
