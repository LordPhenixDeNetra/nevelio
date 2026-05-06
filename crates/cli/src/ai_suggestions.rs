use std::path::Path;

use anyhow::{bail, Context, Result};
use rust_i18n::t;
use chrono::Utc;
use nevelio_core::types::Finding;
use serde_json::json;

const ANTHROPIC_API: &str = "https://api.anthropic.com/v1/messages";
const MODEL: &str = "claude-haiku-4-5-20251001";

fn build_prompt(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return t!("ai.prompt_no_findings").to_string();
    }

    let mut lines = vec![t!("ai.prompt_header").to_string(), String::new()];

    for (i, f) in findings.iter().enumerate() {
        lines.push(format!(
            "{}. [{:?}] {} — {} ({})",
            i + 1,
            f.severity,
            f.title,
            f.endpoint,
            f.module,
        ));
        if !f.description.is_empty() {
            lines.push(t!("ai.prompt_desc", desc = f.description.as_str()).to_string());
        }
        if !f.recommendation.is_empty() {
            lines.push(t!("ai.prompt_rec", rec = f.recommendation.as_str()).to_string());
        }
        lines.push(String::new());
    }

    lines.push(t!("ai.prompt_footer").to_string());
    lines.join("\n")
}

pub async fn generate_and_save(findings: &[Finding], out_dir: &Path) -> Result<()> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .context(t!("ai.no_key").to_string())?;

    let prompt = build_prompt(findings);

    let client = reqwest::Client::new();
    let body = json!({
        "model": MODEL,
        "max_tokens": 4096,
        "messages": [
            { "role": "user", "content": prompt }
        ]
    });

    let resp = client
        .post(ANTHROPIC_API)
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .context(t!("ai.api_error").to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("{}", t!("ai.api_status", status = status.as_str(), body = text.as_str()));
    }

    let data: serde_json::Value = resp.json().await
        .context(t!("ai.invalid_response").to_string())?;

    let content = data["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|block| block["text"].as_str())
        .context(t!("ai.missing_field").to_string())?;

    let header = format!(
        "# Suggestions IA — Nevelio\n\n> Généré par Claude ({}) le {}\n\n---\n\n",
        MODEL,
        Utc::now().format("%Y-%m-%d %H:%M UTC")
    );
    let output = format!("{}{}", header, content);

    let path = out_dir.join("ai_suggestions.md");
    std::fs::write(&path, &output)
        .context(t!("ai.write_error").to_string())?;

    println!("{:<12}: {}", t!("scan.ia_label"), path.display());

    Ok(())
}
