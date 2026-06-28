use anyhow::Result;
use nevelio_core::types::{Finding, Severity};
use nevelio_reporting::ScanReport;

pub(super) async fn send_slack(
    client: &reqwest::Client,
    url: &str,
    report: &ScanReport,
    findings: &[&Finding],
    summary: &str,
) -> Result<()> {
    let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high     = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
    let color = if critical > 0 { "danger" } else if high > 0 { "warning" } else { "good" };

    let payload = serde_json::json!({
        "text": summary,
        "attachments": [{
            "color": color,
            "fields": [
                { "title": "Cible",     "value": &report.target,                                  "short": true },
                { "title": "Durée",     "value": format!("{:.0}s", report.duration_secs),          "short": true },
                { "title": "Findings",  "value": findings.len().to_string(),                       "short": true },
                { "title": "Profil",    "value": &report.profile,                                  "short": true },
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

pub(super) async fn send_teams(
    client: &reqwest::Client,
    url: &str,
    report: &ScanReport,
    findings: &[&Finding],
    summary: &str,
) -> Result<()> {
    let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
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
                { "name": "Profil",   "value": &report.profile },
                { "name": "Durée",    "value": format!("{:.0}s", report.duration_secs) },
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
