use anyhow::Result;
use nevelio_core::types::{Finding, Severity};
use nevelio_reporting::ScanReport;

pub(super) async fn send_pagerduty(
    client: &reqwest::Client,
    integration_key: &str,
    report: &ScanReport,
    findings: &[&Finding],
) -> Result<()> {
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();

    let severity = if critical > 0 {
        "critical"
    } else if high > 0 {
        "error"
    } else {
        "warning"
    };
    let summary = format!(
        "Nevelio: {} security finding(s) on {} — CRITICAL: {}, HIGH: {}",
        findings.len(),
        report.target,
        critical,
        high
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
            "href": format!("file://{}/findings.json",
                std::env::current_dir().unwrap_or_default().display()),
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
