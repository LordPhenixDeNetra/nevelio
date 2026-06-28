use anyhow::{Context, Result};
use colored::Colorize;
use nevelio_core::types::{Finding, Severity};
use nevelio_reporting::ScanReport;
use std::collections::HashSet;
use std::time::Duration;

use crate::args::JiraIssueArgs;
use crate::notify::severity_meets_threshold;

pub(super) async fn handle_jira(report: &ScanReport, args: JiraIssueArgs) -> Result<()> {
    let token = args.token
        .or_else(|| std::env::var("JIRA_API_TOKEN").ok())
        .context("Token Jira requis. Utilisez --token ou JIRA_API_TOKEN.")?;
    let email = args.email
        .or_else(|| std::env::var("JIRA_EMAIL").ok())
        .context("Email Jira requis. Utilisez --email ou JIRA_EMAIL.")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let to_create: Vec<&Finding> = report.findings.iter()
        .filter(|f| severity_meets_threshold(&f.severity, &args.min_severity))
        .collect();

    if to_create.is_empty() {
        println!("  Aucun finding au-dessus du seuil. Rien à créer.");
        return Ok(());
    }

    println!("  {} finding(s) à créer dans le projet {} sur Jira",
        to_create.len().to_string().bold(), args.project.cyan());

    let existing =
        fetch_jira_issue_summaries(&client, &args.jira_url, &args.project, &email, &token).await?;

    let mut created = 0u32;
    let mut skipped = 0u32;

    for finding in to_create {
        let summary = format!("[Nevelio] {} — {}", finding.severity, finding.title);
        if existing.contains(&summary) {
            skipped += 1;
            continue;
        }
        create_jira_issue(&client, &args.jira_url, &args.project, &email, &token, finding, &summary)
            .await?;
        created += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!("  {} {} ticket(s) créé(s), {} ignoré(s).", "✓".green(), created, skipped);
    Ok(())
}

async fn fetch_jira_issue_summaries(
    client: &reqwest::Client,
    base_url: &str,
    project: &str,
    email: &str,
    token: &str,
) -> Result<HashSet<String>> {
    let jql = format!("project = {} AND labels = nevelio ORDER BY created DESC", project);
    let encoded_jql = percent_encode(&jql);
    let url = format!(
        "{}/rest/api/3/search?jql={}&fields=summary&maxResults=100",
        base_url, encoded_jql
    );

    let resp = client
        .get(&url)
        .basic_auth(email, Some(token))
        .header("Accept", "application/json")
        .send().await.context("Erreur API Jira")?;

    match resp.status().as_u16() {
        401 => anyhow::bail!("Credentials Jira invalides (email/token)."),
        403 => anyhow::bail!("Accès refusé au projet Jira '{}'.", project),
        _   => {}
    }

    let data: serde_json::Value = resp.json().await?;
    let issues = data["issues"].as_array().cloned().unwrap_or_default();
    Ok(issues.iter()
        .filter_map(|i| i["fields"]["summary"].as_str().map(|s| s.to_string()))
        .collect())
}

async fn create_jira_issue(
    client: &reqwest::Client,
    base_url: &str,
    project: &str,
    email: &str,
    token: &str,
    finding: &Finding,
    summary: &str,
) -> Result<()> {
    let description_text = format!(
        "Sévérité: {severity}\nModule: {module}\nEndpoint: {method} {endpoint}\n\n{description}\n\nRecommandation:\n{recommendation}",
        severity      = finding.severity,
        module        = finding.module,
        method        = finding.method,
        endpoint      = finding.endpoint,
        description   = finding.description,
        recommendation= finding.recommendation,
    );

    let payload = serde_json::json!({
        "fields": {
            "project": { "key": project },
            "summary": summary,
            "description": {
                "type": "doc", "version": 1,
                "content": [{ "type": "paragraph", "content": [{ "type": "text", "text": description_text }] }]
            },
            "issuetype": { "name": "Bug" },
            "priority": { "name": jira_priority(finding) },
            "labels": ["nevelio", "security"],
        }
    });

    let resp = client
        .post(format!("{}/rest/api/3/issue", base_url))
        .basic_auth(email, Some(token))
        .header("Accept", "application/json")
        .json(&payload)
        .send().await.context("Erreur création ticket Jira")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Jira API error: {}", text);
    }

    let issue: serde_json::Value = resp.json().await?;
    println!("  {} {} {}",
        "→".blue(), issue["key"].as_str().unwrap_or("?").bold(), summary);
    Ok(())
}

fn percent_encode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || "-_.~".contains(c) {
                vec![c.to_string()]
            } else {
                c.to_string().as_bytes().iter().map(|b| format!("%{:02X}", b)).collect()
            }
        })
        .collect()
}

fn jira_priority(finding: &Finding) -> &'static str {
    match finding.severity {
        Severity::Critical    => "Highest",
        Severity::High        => "High",
        Severity::Medium      => "Medium",
        Severity::Low         => "Low",
        Severity::Informative => "Lowest",
    }
}
