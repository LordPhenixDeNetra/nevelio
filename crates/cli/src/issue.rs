mod github;
mod jira;
mod linear;

use anyhow::{Context, Result};
use nevelio_reporting::ScanReport;

use crate::args::{IssueArgs, IssueProvider};

pub async fn handle_issue(args: IssueArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.findings)
        .with_context(|| format!("Fichier introuvable : {}", args.findings.display()))?;
    let report: ScanReport =
        serde_json::from_str(&content).context("Format findings.json invalide")?;

    match args.provider {
        IssueProvider::Github(gh) => github::handle_github(&report, gh).await,
        IssueProvider::Jira(jira) => jira::handle_jira(&report, jira).await,
        IssueProvider::Linear(lin) => linear::handle_linear(&report, lin).await,
    }
}

#[cfg(test)]
mod tests {
    use nevelio_core::types::Severity;

    #[test]
    fn jira_priority_maps_severity() {
        assert_eq!(priority(Severity::Critical), "Highest");
        assert_eq!(priority(Severity::High), "High");
        assert_eq!(priority(Severity::Medium), "Medium");
        assert_eq!(priority(Severity::Low), "Low");
        assert_eq!(priority(Severity::Informative), "Lowest");
    }

    fn priority(sev: Severity) -> &'static str {
        match sev {
            Severity::Critical => "Highest",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Informative => "Lowest",
        }
    }
}
