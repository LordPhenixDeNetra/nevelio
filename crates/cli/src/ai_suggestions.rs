use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use nevelio_core::types::Finding;
use serde_json::json;

const ANTHROPIC_API: &str = "https://api.anthropic.com/v1/messages";
const MODEL: &str = "claude-haiku-4-5-20251001";

fn build_prompt(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "Aucun finding détecté lors du scan.".to_string();
    }

    let mut lines = vec![
        "Tu es un expert en sécurité des API. Voici les findings détectés lors d'un pentest automatisé :".to_string(),
        String::new(),
    ];

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
            lines.push(format!("   Description : {}", f.description));
        }
        if !f.recommendation.is_empty() {
            lines.push(format!("   Recommandation actuelle : {}", f.recommendation));
        }
        lines.push(String::new());
    }

    lines.push("Pour chaque finding, fournis :".to_string());
    lines.push("- Une explication claire du risque en 1-2 phrases".to_string());
    lines.push("- Des étapes concrètes de remédiation (code ou configuration si applicable)".to_string());
    lines.push("- La priorité de correction (Immédiate / Court terme / Long terme)".to_string());
    lines.push(String::new());
    lines.push("Réponds en français, format Markdown.".to_string());

    lines.join("\n")
}

pub async fn generate_and_save(findings: &[Finding], out_dir: &Path) -> Result<()> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .context("ANTHROPIC_API_KEY non défini — impossible de générer les suggestions IA")?;

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
        .context("Échec de l'appel à l'API Anthropic")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("API Anthropic erreur {} : {}", status, text);
    }

    let data: serde_json::Value = resp.json().await.context("Réponse API invalide")?;

    let content = data["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|block| block["text"].as_str())
        .context("Réponse API inattendue — champ 'content[0].text' manquant")?;

    let header = format!(
        "# Suggestions IA — Nevelio\n\n> Généré par Claude ({}) le {}\n\n---\n\n",
        MODEL,
        Utc::now().format("%Y-%m-%d %H:%M UTC")
    );
    let output = format!("{}{}", header, content);

    let path = out_dir.join("ai_suggestions.md");
    std::fs::write(&path, &output)
        .context("Impossible d'écrire ai_suggestions.md")?;

    println!("{:<12}: {}", "IA Rapport", path.display());

    Ok(())
}
