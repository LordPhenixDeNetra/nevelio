use anyhow::Result;
use nevelio_reporting::ScanReport;

pub(super) async fn send_generic(
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
