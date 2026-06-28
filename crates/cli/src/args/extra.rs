use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

use super::{FailOnArg, ProfileArg};

// ── Diff ──────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(after_help = "\
EXIT CODES :
  0  Aucun nouveau finding
  1  Nouveaux findings LOW ou MEDIUM
  2  Nouveaux findings HIGH ou CRITICAL")]
pub struct DiffArgs {
    pub before: PathBuf,
    pub after: PathBuf,

    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<FailOnArg>,
}

// ── Watch ─────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct WatchArgs {
    #[arg(long, value_name = "URL")]
    pub url: String,

    #[arg(long, default_value = "6h")]
    pub interval: String,

    #[arg(long, value_name = "SPEC")]
    pub spec: Option<String>,

    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<ProfileArg>,

    #[arg(long, value_name = "URL")]
    pub notify_webhook: Option<String>,

    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,

    #[arg(long)]
    pub daemon: bool,
}

// ── Shell ─────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct ShellArgs {
    #[arg(long, value_name = "URL")]
    pub url: Option<String>,

    #[arg(long, value_name = "SPEC")]
    pub spec: Option<String>,

    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,
}

// ── Serve ─────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(after_help = "\
EXEMPLES :
  nevelio serve
  nevelio serve --dir ./results --port 8080
  nevelio serve --findings ./scan/findings.json --no-open")]
pub struct ServeArgs {
    #[arg(long, value_name = "PATH")]
    pub dir: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    pub findings: Option<PathBuf>,

    #[arg(long, default_value = "4000")]
    pub port: u16,

    #[arg(long)]
    pub no_open: bool,
}

// ── Notify ────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(after_help = "\
EXEMPLES :
  nevelio notify --findings findings.json --slack https://hooks.slack.com/services/...
  nevelio notify --teams https://... --min-severity high")]
pub struct NotifyArgs {
    #[arg(long, value_name = "FILE", default_value = "./nevelio-results/findings.json")]
    pub findings: PathBuf,

    #[arg(long, value_name = "URL")]
    pub slack: Option<String>,

    #[arg(long, value_name = "URL")]
    pub teams: Option<String>,

    #[arg(long, value_name = "URL")]
    pub webhook: Option<String>,

    #[arg(long, value_name = "KEY")]
    pub pagerduty: Option<String>,

    #[arg(long, value_name = "HOST:PORT")]
    pub smtp: Option<String>,

    #[arg(long, value_name = "USER")]
    pub smtp_user: Option<String>,

    #[arg(long, value_name = "PASS")]
    pub smtp_pass: Option<String>,

    #[arg(long, value_name = "EMAIL")]
    pub email_to: Option<String>,

    #[arg(long, value_name = "EMAIL", default_value = "nevelio@localhost")]
    pub email_from: String,

    #[arg(long, value_name = "SEVERITY", default_value = "medium")]
    pub min_severity: FailOnArg,
}

// ── Issue ─────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(after_help = "\
EXEMPLES :
  nevelio issue github --repo owner/repo --token ghp_...
  nevelio issue jira --jira-url https://myco.atlassian.net --project SEC --email me@myco.com")]
pub struct IssueArgs {
    #[arg(long, value_name = "FILE", default_value = "./nevelio-results/findings.json")]
    pub findings: PathBuf,

    #[command(subcommand)]
    pub provider: IssueProvider,
}

#[derive(Debug, Subcommand)]
pub enum IssueProvider {
    Github(GithubIssueArgs),
    Jira(JiraIssueArgs),
    Linear(LinearIssueArgs),
}

#[derive(Debug, clap::Args)]
pub struct GithubIssueArgs {
    #[arg(long, value_name = "OWNER/REPO")]
    pub repo: String,

    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    #[arg(long, value_name = "LABEL")]
    pub labels: Vec<String>,

    #[arg(long, value_name = "SEVERITY", default_value = "medium")]
    pub min_severity: FailOnArg,
}

#[derive(Debug, clap::Args)]
pub struct JiraIssueArgs {
    #[arg(long, value_name = "URL")]
    pub jira_url: String,

    #[arg(long, value_name = "KEY")]
    pub project: String,

    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    #[arg(long, value_name = "EMAIL")]
    pub email: Option<String>,

    #[arg(long, value_name = "SEVERITY", default_value = "medium")]
    pub min_severity: FailOnArg,
}

#[derive(Debug, clap::Args)]
pub struct LinearIssueArgs {
    #[arg(long, value_name = "KEY")]
    pub token: Option<String>,

    #[arg(long, value_name = "TEAM_ID")]
    pub team: String,

    #[arg(long, value_name = "LABEL")]
    pub label: Option<String>,

    #[arg(long, value_name = "PROJECT_ID")]
    pub project: Option<String>,

    #[arg(long, value_name = "SEVERITY", default_value = "medium")]
    pub min_severity: FailOnArg,
}
