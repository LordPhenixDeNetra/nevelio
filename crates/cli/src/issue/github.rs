use anyhow::{Context, Result};
use colored::Colorize;
use nevelio_core::types::Finding;
use nevelio_reporting::ScanReport;
use std::collections::HashSet;
use std::time::Duration;

use crate::args::GithubIssueArgs;
use crate::notify::severity_meets_threshold;

pub(super) async fn handle_github(report: &ScanReport, args: GithubIssueArgs) -> Result<()> {
    let token = args.token
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .context("Token GitHub requis. Utilisez --token ou la variable GITHUB_TOKEN.")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("nevelio-security-scanner")
        .build()?;

    let to_create: Vec<&Finding> = report.findings.iter()
        .filter(|f| severity_meets_threshold(&f.severity, &args.min_severity))
        .collect();

    if to_create.is_empty() {
        println!("  Aucun finding au-dessus du seuil. Rien à créer.");
        return Ok(());
    }

    println!("  {} finding(s) à créer sur {}", to_create.len().to_string().bold(), args.repo.cyan());

    let existing = fetch_github_issue_titles(&client, &args.repo, &token).await?;

    let mut created = 0u32;
    let mut skipped = 0u32;

    for finding in to_create {
        let title = format!("[Nevelio] {} — {}", finding.severity, finding.title);
        if existing.contains(&title) {
            skipped += 1;
            continue;
        }
        create_github_issue(&client, &args.repo, &token, finding, &title, &args.labels).await?;
        created += 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    println!("  {} {} issue(s) créé(s), {} ignoré(s) (déjà existant).",
        "✓".green(), created, skipped);
    Ok(())
}

async fn fetch_github_issue_titles(
    client: &reqwest::Client,
    repo: &str,
    token: &str,
) -> Result<HashSet<String>> {
    let url = format!(
        "https://api.github.com/repos/{}/issues?state=open&labels=nevelio&per_page=100",
        repo
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("token {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .send().await.context("Erreur API GitHub")?;

    match resp.status().as_u16() {
        401 => anyhow::bail!("Token GitHub invalide ou permissions insuffisantes."),
        404 => anyhow::bail!("Dépôt '{}' introuvable ou accès refusé.", repo),
        _   => {}
    }

    let issues: Vec<serde_json::Value> = resp.json().await?;
    Ok(issues.iter()
        .filter_map(|i| i["title"].as_str().map(|s| s.to_string()))
        .collect())
}

async fn create_github_issue(
    client: &reqwest::Client,
    repo: &str,
    token: &str,
    finding: &Finding,
    title: &str,
    extra_labels: &[String],
) -> Result<()> {
    let url = format!("https://api.github.com/repos/{}/issues", repo);

    let mut labels = vec![
        "security".to_string(),
        "nevelio".to_string(),
        format!("severity:{}", finding.severity.to_string().to_lowercase()),
    ];
    labels.extend_from_slice(extra_labels);

    let body = format!(
        "## Détails\n\n\
        **Sévérité :** {severity}  \n**Module :** {module}  \n**Endpoint :** `{method} {endpoint}`  \n\n\
        ## Description\n\n{description}\n\n## Recommandation\n\n{recommendation}\n\n\
        ---\n*Détecté par [Nevelio](https://github.com/LordPhenixDeNetra/nevelio)*",
        severity      = finding.severity,
        module        = finding.module,
        method        = finding.method,
        endpoint      = finding.endpoint,
        description   = finding.description,
        recommendation= finding.recommendation,
    );

    let payload = serde_json::json!({ "title": title, "body": body, "labels": labels });

    let resp = client
        .post(&url)
        .header("Authorization", format!("token {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .json(&payload)
        .send().await.context("Erreur création issue GitHub")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("GitHub API error: {}", text);
    }

    let issue: serde_json::Value = resp.json().await?;
    println!("  {} #{} {}", "→".blue(), issue["number"].as_u64().unwrap_or(0), title);
    Ok(())
}
