use anyhow::{Context, Result};
use colored::Colorize;
use nevelio_core::types::{Finding, Severity};
use nevelio_reporting::ScanReport;
use std::collections::HashSet;
use std::time::Duration;

use crate::args::{GithubIssueArgs, IssueArgs, IssueProvider, JiraIssueArgs, LinearIssueArgs};
use crate::notify::severity_meets_threshold;

pub async fn handle_issue(args: IssueArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.findings)
        .with_context(|| format!("Fichier introuvable : {}", args.findings.display()))?;
    let report: ScanReport =
        serde_json::from_str(&content).context("Format findings.json invalide")?;

    match args.provider {
        IssueProvider::Github(gh) => handle_github(&report, gh).await,
        IssueProvider::Jira(jira) => handle_jira(&report, jira).await,
        IssueProvider::Linear(linear) => handle_linear(&report, linear).await,
    }
}

// ── GitHub issues ─────────────────────────────────────────────────────────────

async fn handle_github(report: &ScanReport, args: GithubIssueArgs) -> Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .context("Token GitHub requis. Utilisez --token ou la variable GITHUB_TOKEN.")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("nevelio-security-scanner")
        .build()?;

    let to_create: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| severity_meets_threshold(&f.severity, &args.min_severity))
        .collect();

    if to_create.is_empty() {
        println!("  Aucun finding au-dessus du seuil. Rien à créer.");
        return Ok(());
    }

    println!(
        "  {} finding(s) à créer sur {}",
        to_create.len().to_string().bold(),
        args.repo.cyan()
    );

    let existing =
        fetch_github_issue_titles(&client, &args.repo, &token).await?;

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

        // Respect GitHub secondary rate limit (1 req/s for creation)
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    println!(
        "  {} {} issue(s) créé(s), {} ignoré(s) (déjà existant).",
        "✓".green(),
        created,
        skipped
    );
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
        .send()
        .await
        .context("Erreur API GitHub")?;

    match resp.status().as_u16() {
        401 => anyhow::bail!("Token GitHub invalide ou permissions insuffisantes."),
        404 => anyhow::bail!("Dépôt '{}' introuvable ou accès refusé.", repo),
        _ => {}
    }

    let issues: Vec<serde_json::Value> = resp.json().await?;
    Ok(issues
        .iter()
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
        **Sévérité :** {severity}  \n\
        **Module :** {module}  \n\
        **Endpoint :** `{method} {endpoint}`  \n\n\
        ## Description\n\n\
        {description}\n\n\
        ## Recommandation\n\n\
        {recommendation}\n\n\
        ---\n\
        *Détecté par [Nevelio](https://github.com/LordPhenixDeNetra/nevelio)*",
        severity = finding.severity,
        module = finding.module,
        method = finding.method,
        endpoint = finding.endpoint,
        description = finding.description,
        recommendation = finding.recommendation,
    );

    let payload = serde_json::json!({
        "title": title,
        "body": body,
        "labels": labels,
    });

    let resp = client
        .post(&url)
        .header("Authorization", format!("token {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .json(&payload)
        .send()
        .await
        .context("Erreur création issue GitHub")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("GitHub API error: {}", text);
    }

    let issue: serde_json::Value = resp.json().await?;
    println!(
        "  {} #{} {}",
        "→".blue(),
        issue["number"].as_u64().unwrap_or(0),
        title
    );
    Ok(())
}

// ── Jira tickets ──────────────────────────────────────────────────────────────

async fn handle_jira(report: &ScanReport, args: JiraIssueArgs) -> Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var("JIRA_API_TOKEN").ok())
        .context("Token Jira requis. Utilisez --token ou JIRA_API_TOKEN.")?;
    let email = args
        .email
        .or_else(|| std::env::var("JIRA_EMAIL").ok())
        .context("Email Jira requis. Utilisez --email ou JIRA_EMAIL.")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let to_create: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| severity_meets_threshold(&f.severity, &args.min_severity))
        .collect();

    if to_create.is_empty() {
        println!("  Aucun finding au-dessus du seuil. Rien à créer.");
        return Ok(());
    }

    println!(
        "  {} finding(s) à créer dans le projet {} sur Jira",
        to_create.len().to_string().bold(),
        args.project.cyan()
    );

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

        create_jira_issue(
            &client,
            &args.jira_url,
            &args.project,
            &email,
            &token,
            finding,
            &summary,
        )
        .await?;
        created += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!(
        "  {} {} ticket(s) créé(s), {} ignoré(s).",
        "✓".green(),
        created,
        skipped
    );
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
        .send()
        .await
        .context("Erreur API Jira")?;

    match resp.status().as_u16() {
        401 => anyhow::bail!("Credentials Jira invalides (email/token)."),
        403 => anyhow::bail!("Accès refusé au projet Jira '{}'.", project),
        _ => {}
    }

    let data: serde_json::Value = resp.json().await?;
    let issues = data["issues"].as_array().cloned().unwrap_or_default();
    Ok(issues
        .iter()
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
        severity = finding.severity,
        module = finding.module,
        method = finding.method,
        endpoint = finding.endpoint,
        description = finding.description,
        recommendation = finding.recommendation,
    );

    // Atlassian Document Format (ADF)
    let payload = serde_json::json!({
        "fields": {
            "project": { "key": project },
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{ "type": "text", "text": description_text }]
                }]
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
        .send()
        .await
        .context("Erreur création ticket Jira")?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Jira API error: {}", text);
    }

    let issue: serde_json::Value = resp.json().await?;
    println!(
        "  {} {} {}",
        "→".blue(),
        issue["key"].as_str().unwrap_or("?").bold(),
        summary
    );
    Ok(())
}

fn percent_encode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || "-_.~".contains(c) {
                vec![c.to_string()]
            } else {
                c.to_string()
                    .as_bytes()
                    .iter()
                    .map(|b| format!("%{:02X}", b))
                    .collect()
            }
        })
        .collect()
}

fn jira_priority(finding: &Finding) -> &'static str {
    match finding.severity {
        Severity::Critical => "Highest",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Informative => "Lowest",
    }
}

// ── Linear issues ─────────────────────────────────────────────────────────────

async fn handle_linear(report: &ScanReport, args: LinearIssueArgs) -> Result<()> {
    let token = args
        .token
        .or_else(|| std::env::var("LINEAR_API_KEY").ok())
        .context("Clé API Linear requise. Utilisez --token ou la variable LINEAR_API_KEY.")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    let to_create: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| severity_meets_threshold(&f.severity, &args.min_severity))
        .collect();

    if to_create.is_empty() {
        println!("  Aucun finding au-dessus du seuil. Aucun ticket Linear créé.");
        return Ok(());
    }

    // Resolve label ID if a label name was provided
    let label_id = if let Some(ref label_name) = args.label {
        resolve_linear_label(&client, &token, label_name).await.ok().flatten()
    } else {
        None
    };

    let mut created = 0u32;
    let mut skipped = 0u32;

    // Check existing issues to avoid duplicates
    let existing_titles = fetch_linear_issue_titles(&client, &token, &args.team).await?;

    for finding in &to_create {
        let title = format!("[Nevelio] {} — {}", finding.title, finding.module);

        if existing_titles.contains(&title) {
            skipped += 1;
            continue;
        }

        let description = format!(
            "## Security Finding\n\n\
             **Module:** {module}\n\
             **Endpoint:** {ep}\n\
             **Method:** {method}\n\
             **Severity:** {sev:?}\n\
             **CVSS:** {cvss:.1}\n\n\
             ### Description\n{desc}\n\n\
             ### Recommendation\n{rec}\n\n\
             {cwe}\
             ---\n*Generated by Nevelio v{ver} | Target: {target}*",
            module = finding.module,
            ep = finding.endpoint,
            method = finding.method,
            sev = finding.severity,
            cvss = finding.cvss_score,
            desc = finding.description,
            rec = finding.recommendation,
            cwe = finding.cwe.as_deref().map(|c| format!("**CWE:** {}\n\n", c)).unwrap_or_default(),
            ver = env!("CARGO_PKG_VERSION"),
            target = report.target,
        );

        let priority = linear_priority_for_sev(&finding.severity);

        let mut variables = serde_json::json!({
            "teamId": args.team,
            "title": title,
            "description": description,
            "priority": priority,
        });

        if let Some(ref pid) = args.project {
            variables["projectId"] = serde_json::json!(pid);
        }
        if let Some(ref lid) = label_id {
            variables["labelIds"] = serde_json::json!([lid]);
        }

        let mutation = r#"
            mutation CreateIssue($teamId: String!, $title: String!, $description: String, $priority: Int, $projectId: String, $labelIds: [String!]) {
                issueCreate(input: {
                    teamId: $teamId,
                    title: $title,
                    description: $description,
                    priority: $priority,
                    projectId: $projectId,
                    labelIds: $labelIds
                }) {
                    success
                    issue { id url }
                }
            }
        "#;

        let resp = client
            .post("https://api.linear.app/graphql")
            .header("Authorization", &token)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "query": mutation, "variables": variables }))
            .send()
            .await
            .context("Erreur appel Linear API")?;

        let body: serde_json::Value = resp.json().await?;
        if body["data"]["issueCreate"]["success"].as_bool().unwrap_or(false) {
            let url = body["data"]["issueCreate"]["issue"]["url"]
                .as_str()
                .unwrap_or("");
            println!("  {} Linear issue créé : {}", "✓".green(), url);
            created += 1;
        } else if let Some(errors) = body["errors"].as_array() {
            let msg = errors.first().and_then(|e| e["message"].as_str()).unwrap_or("unknown");
            eprintln!("  ✗ Erreur Linear : {}", msg);
        }
    }

    println!(
        "\n  Bilan : {} issue(s) créé(s), {} ignoré(s) (déjà existants).",
        created, skipped
    );
    Ok(())
}

async fn fetch_linear_issue_titles(
    client: &reqwest::Client,
    token: &str,
    team_id: &str,
) -> Result<HashSet<String>> {
    let query = r#"
        query TeamIssues($teamId: String!) {
            team(id: $teamId) {
                issues(filter: { title: { startsWith: "[Nevelio]" } }) {
                    nodes { title }
                }
            }
        }
    "#;

    let resp = client
        .post("https://api.linear.app/graphql")
        .header("Authorization", token)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "query": query, "variables": { "teamId": team_id } }))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let titles = body["data"]["team"]["issues"]["nodes"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|n| n["title"].as_str().map(String::from))
        .collect();

    Ok(titles)
}

async fn resolve_linear_label(
    client: &reqwest::Client,
    token: &str,
    label_name: &str,
) -> Result<Option<String>> {
    let query = r#"query { issueLabels { nodes { id name } } }"#;
    let resp = client
        .post("https://api.linear.app/graphql")
        .header("Authorization", token)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "query": query }))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    let id = body["data"]["issueLabels"]["nodes"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .find(|n| n["name"].as_str().map(|s| s.eq_ignore_ascii_case(label_name)).unwrap_or(false))
        .and_then(|n| n["id"].as_str().map(String::from));

    Ok(id)
}

fn linear_priority_for_sev(sev: &Severity) -> u8 {
    // Linear priorities: 0=No priority, 1=Urgent, 2=High, 3=Medium, 4=Low
    match sev {
        Severity::Critical => 1,
        Severity::High => 2,
        Severity::Medium => 3,
        Severity::Low => 4,
        Severity::Informative => 4,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jira_priority_maps_severity() {
        use nevelio_core::types::Severity;
        assert_eq!(jira_priority_for_sev(Severity::Critical), "Highest");
        assert_eq!(jira_priority_for_sev(Severity::High), "High");
        assert_eq!(jira_priority_for_sev(Severity::Medium), "Medium");
        assert_eq!(jira_priority_for_sev(Severity::Low), "Low");
        assert_eq!(jira_priority_for_sev(Severity::Informative), "Lowest");
    }

    fn jira_priority_for_sev(sev: Severity) -> &'static str {
        match sev {
            Severity::Critical => "Highest",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Informative => "Lowest",
        }
    }
}
