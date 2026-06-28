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
        send_slack(&client, url, &report, &to_notify, &summary)
            .await
            .context("Erreur envoi Slack")?;
        println!("  {} Slack notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref url) = args.teams {
        send_teams(&client, url, &report, &to_notify, &summary)
            .await
            .context("Erreur envoi Teams")?;
        println!("  {} Microsoft Teams notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref url) = args.webhook {
        send_generic(&client, url, &report)
            .await
            .context("Erreur envoi webhook")?;
        println!("  {} Webhook notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref key) = args.pagerduty {
        send_pagerduty(&client, key, &report, &to_notify)
            .await
            .context("Erreur envoi PagerDuty")?;
        println!("  {} PagerDuty notifié.", "✓".green());
        sent += 1;
    }

    if let Some(ref smtp_addr) = args.smtp {
        if let Some(ref to) = args.email_to {
            let smtp_user = args.smtp_user.clone()
                .or_else(|| std::env::var("SMTP_USER").ok());
            let smtp_pass = args.smtp_pass.clone()
                .or_else(|| std::env::var("SMTP_PASS").ok());
            send_email(
                smtp_addr,
                smtp_user.as_deref(),
                smtp_pass.as_deref(),
                &args.email_from,
                to,
                &report,
                &to_notify,
                &summary,
            )
            .await
            .context("Erreur envoi email")?;
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

// ── Severity filter ───────────────────────────────────────────────────────────

pub(crate) fn severity_meets_threshold(sev: &Severity, threshold: &FailOnArg) -> bool {
    match threshold {
        FailOnArg::None => false,
        FailOnArg::Low => true,
        FailOnArg::Medium => !matches!(sev, Severity::Low | Severity::Informative),
        FailOnArg::High => matches!(sev, Severity::High | Severity::Critical),
        FailOnArg::Critical => matches!(sev, Severity::Critical),
    }
}

// ── Summary builder ───────────────────────────────────────────────────────────

fn build_summary(report: &ScanReport, findings: &[&Finding]) -> String {
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium))
        .count();

    format!(
        "Nevelio — {} finding(s) sur {} | CRITICAL: {} | HIGH: {} | MEDIUM: {}",
        findings.len(),
        report.target,
        critical,
        high,
        medium
    )
}

// ── Slack ─────────────────────────────────────────────────────────────────────

async fn send_slack(
    client: &reqwest::Client,
    url: &str,
    report: &ScanReport,
    findings: &[&Finding],
    summary: &str,
) -> Result<()> {
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();
    let color = if critical > 0 {
        "danger"
    } else if high > 0 {
        "warning"
    } else {
        "good"
    };

    let payload = serde_json::json!({
        "text": summary,
        "attachments": [{
            "color": color,
            "fields": [
                { "title": "Cible", "value": &report.target, "short": true },
                { "title": "Durée", "value": format!("{:.0}s", report.duration_secs), "short": true },
                { "title": "Findings", "value": findings.len().to_string(), "short": true },
                { "title": "Profil", "value": &report.profile, "short": true },
            ],
            "footer": "Nevelio Security Scanner",
            "ts": chrono::Utc::now().timestamp(),
        }]
    });

    let resp = client.post(url).json(&payload).send().await?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Slack API error: {}", text);
    }
    Ok(())
}

// ── Microsoft Teams ───────────────────────────────────────────────────────────

async fn send_teams(
    client: &reqwest::Client,
    url: &str,
    report: &ScanReport,
    findings: &[&Finding],
    summary: &str,
) -> Result<()> {
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let color = if critical > 0 { "FF0000" } else { "FF8C00" };

    let payload = serde_json::json!({
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": summary,
        "sections": [{
            "activityTitle": "Nevelio Security Scan",
            "activitySubtitle": &report.target,
            "facts": [
                { "name": "Findings", "value": findings.len().to_string() },
                { "name": "Profil", "value": &report.profile },
                { "name": "Durée", "value": format!("{:.0}s", report.duration_secs) },
            ],
            "markdown": true
        }]
    });

    let resp = client.post(url).json(&payload).send().await?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Teams API error: {}", text);
    }
    Ok(())
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

async fn send_pagerduty(
    client: &reqwest::Client,
    integration_key: &str,
    report: &ScanReport,
    findings: &[&Finding],
) -> Result<()> {
    let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();

    let severity = if critical > 0 { "critical" } else if high > 0 { "error" } else { "warning" };
    let summary = format!(
        "Nevelio: {} security finding(s) on {} — CRITICAL: {}, HIGH: {}",
        findings.len(), report.target, critical, high
    );

    let body = serde_json::json!({
        "routing_key": integration_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": report.target,
            "component": "nevelio-security-scanner",
            "group": "security",
            "class": "vulnerability",
            "custom_details": {
                "findings_count": findings.len(),
                "critical": critical,
                "high": high,
                "profile": report.profile,
                "duration_secs": report.duration_secs,
            }
        },
        "links": [{
            "href": format!("file://{}/findings.json", std::env::current_dir().unwrap_or_default().display()),
            "text": "Nevelio findings.json"
        }]
    });

    let resp = client
        .post("https://events.pagerduty.com/v2/enqueue")
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("PagerDuty API error: {}", text);
    }
    Ok(())
}

// ── Email (SMTP) ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn send_email(
    smtp_addr: &str,
    smtp_user: Option<&str>,
    smtp_pass: Option<&str>,
    from: &str,
    to: &str,
    report: &ScanReport,
    findings: &[&Finding],
    summary: &str,
) -> Result<()> {
    // Build HTML email body
    let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();

    let rows: String = findings
        .iter()
        .take(20)
        .map(|f| {
            format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                f.severity, f.module, f.endpoint, f.title
            )
        })
        .collect();

    let html_body = format!(
        r#"<!DOCTYPE html><html><body>
<h2>Nevelio Security Report — {target}</h2>
<p><b>Summary:</b> {total} finding(s) | Critical: {crit} | High: {high}</p>
<p><b>Scan profile:</b> {profile} | Duration: {dur:.0}s</p>
<table border="1" cellpadding="4" style="border-collapse:collapse;font-family:monospace">
<tr><th>Severity</th><th>Module</th><th>Endpoint</th><th>Title</th></tr>
{rows}
</table>
{more}
<hr><small>Generated by Nevelio v{ver}</small>
</body></html>"#,
        target = report.target,
        total = findings.len(),
        crit = critical,
        high = high,
        profile = report.profile,
        dur = report.duration_secs,
        rows = rows,
        more = if findings.len() > 20 {
            format!("<p><i>...and {} more findings (see findings.json)</i></p>", findings.len() - 20)
        } else {
            String::new()
        },
        ver = env!("CARGO_PKG_VERSION"),
    );

    // Build raw MIME email
    let msg = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {summary}\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n{html_body}"
    );

    // Parse host:port
    let (host, port_str) = smtp_addr.rsplit_once(':').unwrap_or((smtp_addr, "587"));
    let port: u16 = port_str.parse().unwrap_or(587);

    // Use tokio TCP + manual SMTP (no external dep required)
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let stream = tokio::time::timeout(
        Duration::from_secs(15),
        TcpStream::connect((host, port)),
    )
    .await
    .context("SMTP connection timeout")?
    .context("SMTP connection failed")?;

    let (reader_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader_half);

    // Read greeting
    smtp_readline(&mut reader).await?;

    // EHLO
    writer.write_all(b"EHLO nevelio\r\n").await?;
    loop {
        let l = smtp_readline(&mut reader).await?;
        if l.len() < 4 || !l.starts_with("250-") {
            break;
        }
    }

    // AUTH LOGIN if credentials provided
    if let (Some(user), Some(pass)) = (smtp_user, smtp_pass) {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        writer.write_all(b"AUTH LOGIN\r\n").await?;
        smtp_readline(&mut reader).await?;

        let user_b64 = b64.encode(user);
        writer.write_all(format!("{}\r\n", user_b64).as_bytes()).await?;
        smtp_readline(&mut reader).await?;

        let pass_b64 = b64.encode(pass);
        writer.write_all(format!("{}\r\n", pass_b64).as_bytes()).await?;
        let auth_resp = smtp_readline(&mut reader).await?;
        if !auth_resp.starts_with("235") {
            anyhow::bail!("SMTP auth failed: {}", auth_resp.trim());
        }
    }

    // MAIL FROM
    writer.write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes()).await?;
    smtp_readline(&mut reader).await?;

    // RCPT TO
    writer.write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes()).await?;
    smtp_readline(&mut reader).await?;

    // DATA
    writer.write_all(b"DATA\r\n").await?;
    smtp_readline(&mut reader).await?;

    writer.write_all(msg.as_bytes()).await?;
    writer.write_all(b"\r\n.\r\n").await?;
    smtp_readline(&mut reader).await?;

    // QUIT
    writer.write_all(b"QUIT\r\n").await?;

    Ok(())
}

// ── SMTP helper ──────────────────────────────────────────────────────────────

async fn smtp_readline<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<String> {
    let mut line = String::new();
    tokio::io::AsyncBufReadExt::read_line(reader, &mut line).await?;
    Ok(line)
}

// ── Generic webhook ───────────────────────────────────────────────────────────

async fn send_generic(
    client: &reqwest::Client,
    url: &str,
    report: &ScanReport,
) -> Result<()> {
    let payload = serde_json::json!({
        "source": "nevelio",
        "target": &report.target,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "findings_count": report.findings.len(),
        "summary": report.summary,
        "findings": report.findings,
    });

    let resp = client.post(url).json(&payload).send().await?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Webhook error: {}", text);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
