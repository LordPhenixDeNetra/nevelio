use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "nevelio",
    after_help = "COMPLETION : nevelio --generate-completion bash > ~/.bash_completion.d/nevelio",
    version = env!("CARGO_PKG_VERSION"),
    about = "Nevelio — API Penetration Testing Tool",
    after_help = "\
EXEMPLES :
  Scanner avec un spec OpenAPI :
    nevelio scan --target https://api.example.com --spec openapi.yaml

  Scanner sans spec (découverte automatique) :
    nevelio scan --target https://api.example.com

  Importer une collection Postman ou un fichier HAR :
    nevelio scan --target https://api.example.com --spec collection.postman.json
    nevelio scan --target https://api.example.com --spec traffic.har

  Scanner et générer un rapport HTML :
    nevelio scan --target https://api.example.com --output html --out-dir ./results

  Comparer deux scans (diff CI/CD) :
    nevelio diff before.json after.json

  Surveiller une API toutes les 6h :
    nevelio watch --url https://api.example.com --interval 6h

  Shell interactif :
    nevelio shell --url https://api.example.com

  Convertir un JSON existant en rapport HTML :
    nevelio report --input findings.json --format html

  Lister les modules disponibles :
    nevelio modules list"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Skip the legal disclaimer prompt
    #[arg(long, global = true)]
    pub accept_legal: bool,

    /// Disable coloured output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Interface language: fr | en | es (auto-detected from $LANG if absent)
    #[arg(long, value_name = "LANG", global = true)]
    pub lang: Option<String>,

    /// Generate shell completion script and print to stdout
    #[arg(long, value_name = "SHELL")]
    pub generate_completion: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan an API for vulnerabilities
    Scan(ScanArgs),
    /// Générer un rapport depuis les résultats JSON d'un scan précédent
    #[command(alias = "convert")]
    Report(ReportArgs),
    /// List or inspect available attack modules
    Modules(ModulesArgs),
    /// Créer un fichier .nevelio.toml commenté dans le répertoire courant
    Init,
    /// Compare two scan reports and detect regressions (CI/CD diff)
    Diff(DiffArgs),
    /// Monitor an API continuously and alert on new findings
    Watch(WatchArgs),
    /// Interactive shell for manual exploration and testing
    Shell(ShellArgs),
    /// Serve the HTML report on a local web dashboard
    Serve(ServeArgs),
    /// Send findings to Slack, Teams or a webhook
    Notify(NotifyArgs),
    /// Create GitHub issues or Jira tickets from findings
    Issue(IssueArgs),
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
VARIABLES D'ENVIRONNEMENT :
  ANTHROPIC_API_KEY    Clé API Claude (requis pour --ai-suggestions)")]
pub struct ScanArgs {
    /// Path or URL to an OpenAPI/Swagger spec (JSON or YAML)
    #[arg(long, value_name = "SPEC")]
    pub spec: Option<String>,

    /// Base URL of the target API
    #[arg(long, value_name = "URL")]
    pub target: Option<String>,

    /// Base URL of the target API (alias for --target)
    #[arg(long, value_name = "URL", conflicts_with = "target")]
    pub url: Option<String>,

    /// Scan profile controlling concurrency and rate limits
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<ProfileArg>,

    /// Attack modules to run (default: all)
    #[arg(long = "module", value_name = "MODULE", num_args = 1..)]
    pub modules: Vec<String>,

    /// Maximum concurrent requests (overrides profile default)
    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,

    /// Maximum requests per second (overrides profile default)
    #[arg(long, value_name = "N")]
    pub rate_limit: Option<u64>,

    /// Request timeout in seconds
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    /// Authentication token (e.g. "Bearer eyJ..." or "Basic dXNlcjpwYXNz")
    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    /// HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Output format for findings
    #[arg(long, value_name = "FORMAT")]
    pub output: Option<OutputFormat>,

    /// Directory to write output files
    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,

    /// Exit with code 1 when any finding meets or exceeds this severity
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<FailOnArg>,

    /// Resume a previous scan: load findings + skip completed modules from <out-dir>
    #[arg(long)]
    pub resume: bool,

    /// Simulate the scan without sending real HTTP requests
    #[arg(long)]
    pub dry_run: bool,

    /// Disable the ratatui TUI dashboard (use plain stdout)
    #[arg(long)]
    pub no_tui: bool,

    /// Generate AI-powered remediation suggestions via Claude API (requires ANTHROPIC_API_KEY)
    #[arg(long)]
    pub ai_suggestions: bool,

    /// Rhai scripts to run after scan — return false to suppress a finding
    #[arg(long, value_name = "SCRIPT")]
    pub scripts: Vec<String>,

        /// WASM plugin paths to load as additional attack modules
    #[arg(long, value_name = "FILE")]
    pub plugin: Vec<PathBuf>,

    /// Protobuf (.proto) file for gRPC service discovery
    #[arg(long, value_name = "FILE")]
    pub proto: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Path to the JSON findings file produced by a previous scan
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,

    /// Output format for the report
    #[arg(long, value_name = "FORMAT", default_value = "html")]
    pub format: OutputFormat,

    /// Directory to write the report
    #[arg(long, value_name = "PATH", default_value = ".")]
    pub out_dir: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct ModulesArgs {
    #[command(subcommand)]
    pub action: ModulesAction,
}

#[derive(Debug, Subcommand)]
pub enum ModulesAction {
    /// List all available modules
    List,
    /// Show details of a specific module
    Show {
        /// Module name (e.g. auth, injection, infra)
        name: String,
    },
}

#[derive(Debug, Clone, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum ProfileArg {
    Stealth,
    Normal,
    Aggressive,
}

impl From<ProfileArg> for nevelio_core::types::ScanProfile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Stealth => Self::Stealth,
            ProfileArg::Normal => Self::Normal,
            ProfileArg::Aggressive => Self::Aggressive,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum OutputFormat {
    Json,
    Html,
    Markdown,
    Junit,
    Sarif,
}

impl From<OutputFormat> for nevelio_reporting::ReportFormat {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Json => Self::Json,
            OutputFormat::Html => Self::Html,
            OutputFormat::Markdown => Self::Markdown,
            OutputFormat::Junit => Self::Junit,
            OutputFormat::Sarif => Self::Sarif,
        }
    }
}

/// Severity threshold for CI/CD exit code 1.
#[derive(Debug, Clone, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum FailOnArg {
    /// Never exit with failure based on severity
    None,
    Low,
    Medium,
    High,
    Critical,
}

// ── Diff ──────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(after_help = "\
EXIT CODES :
  0  Aucun nouveau finding
  1  Nouveaux findings LOW ou MEDIUM
  2  Nouveaux findings HIGH ou CRITICAL")]
pub struct DiffArgs {
    /// Scan report before (baseline) — findings.json from a previous scan
    pub before: PathBuf,
    /// Scan report after (new scan) — findings.json to compare
    pub after: PathBuf,
    /// Exit with failure only when new findings meet or exceed this severity
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<FailOnArg>,
}

// ── Watch ─────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct WatchArgs {
    /// Target API URL to monitor
    #[arg(long, value_name = "URL")]
    pub url: String,

    /// Scan interval (e.g. 30s, 5m, 6h, 1d)
    #[arg(long, default_value = "6h")]
    pub interval: String,

    /// Path to spec file (OpenAPI / Postman / HAR — auto-detected)
    #[arg(long, value_name = "SPEC")]
    pub spec: Option<String>,

    /// Authentication token
    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    /// HTTP proxy URL
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Scan profile
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<ProfileArg>,

    /// Webhook URL to notify on new findings (POST JSON)
    #[arg(long, value_name = "URL")]
    pub notify_webhook: Option<String>,

    /// Directory to store watch state and reports
    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,

    /// Run as a background daemon (writes PID to <out-dir>/nevelio-watch.pid)
    #[arg(long)]
    pub daemon: bool,
}

// ── Shell ─────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct ShellArgs {
    /// Initial target API URL (can also be set inside the shell with `target <url>`)
    #[arg(long, value_name = "URL")]
    pub url: Option<String>,

    /// Path to spec file (OpenAPI / Postman / HAR — auto-detected)
    #[arg(long, value_name = "SPEC")]
    pub spec: Option<String>,

    /// Authentication token
    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    /// HTTP proxy URL
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Directory to write exported reports
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
    /// Directory containing findings.json or report.html
    #[arg(long, value_name = "PATH")]
    pub dir: Option<PathBuf>,

    /// Explicit path to findings.json (overrides --dir lookup)
    #[arg(long, value_name = "FILE")]
    pub findings: Option<PathBuf>,

    /// Port for the local web server
    #[arg(long, default_value = "4000")]
    pub port: u16,

    /// Do not open the browser automatically
    #[arg(long)]
    pub no_open: bool,
}

// ── Notify ────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(after_help = "\
VARIABLES D'ENVIRONNEMENT :
  (aucune — fournir les URLs directement)

EXEMPLES :
  nevelio notify --findings findings.json --slack https://hooks.slack.com/services/...
  nevelio notify --teams https://... --min-severity high")]
pub struct NotifyArgs {
    /// Path to findings.json produced by a scan
    #[arg(long, value_name = "FILE", default_value = "./nevelio-results/findings.json")]
    pub findings: PathBuf,

    /// Slack Incoming Webhook URL
    #[arg(long, value_name = "URL")]
    pub slack: Option<String>,

    /// Microsoft Teams Incoming Webhook URL
    #[arg(long, value_name = "URL")]
    pub teams: Option<String>,

    /// Generic webhook URL (POST JSON payload)
    #[arg(long, value_name = "URL")]
    pub webhook: Option<String>,

    /// PagerDuty Events API v2 integration key
    #[arg(long, value_name = "KEY")]
    pub pagerduty: Option<String>,

    /// SMTP server for email notifications (e.g. smtp.gmail.com:587)
    #[arg(long, value_name = "HOST:PORT")]
    pub smtp: Option<String>,

    /// SMTP username (or set SMTP_USER env var)
    #[arg(long, value_name = "USER")]
    pub smtp_user: Option<String>,

    /// SMTP password (or set SMTP_PASS env var)
    #[arg(long, value_name = "PASS")]
    pub smtp_pass: Option<String>,

    /// Email recipient address
    #[arg(long, value_name = "EMAIL")]
    pub email_to: Option<String>,

    /// Email sender address (default: nevelio@localhost)
    #[arg(long, value_name = "EMAIL", default_value = "nevelio@localhost")]
    pub email_from: String,

    /// Minimum severity to include in the notification
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
    /// Path to findings.json produced by a scan
    #[arg(long, value_name = "FILE", default_value = "./nevelio-results/findings.json")]
    pub findings: PathBuf,

    #[command(subcommand)]
    pub provider: IssueProvider,
}

#[derive(Debug, Subcommand)]
pub enum IssueProvider {
    /// Create GitHub issues for each finding
    Github(GithubIssueArgs),
    /// Create Jira Cloud tickets for each finding
    Jira(JiraIssueArgs),
    /// Create Linear issues for each finding
    Linear(LinearIssueArgs),
}

#[derive(Debug, clap::Args)]
pub struct GithubIssueArgs {
    /// GitHub repository in owner/repo format
    #[arg(long, value_name = "OWNER/REPO")]
    pub repo: String,

    /// GitHub API token (or set GITHUB_TOKEN env var)
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Additional labels to add to each issue
    #[arg(long, value_name = "LABEL")]
    pub labels: Vec<String>,

    /// Minimum severity to create issues for
    #[arg(long, value_name = "SEVERITY", default_value = "medium")]
    pub min_severity: FailOnArg,
}

#[derive(Debug, clap::Args)]
pub struct JiraIssueArgs {
    /// Jira Cloud base URL (e.g. https://mycompany.atlassian.net)
    #[arg(long, value_name = "URL")]
    pub jira_url: String,

    /// Jira project key (e.g. SEC)
    #[arg(long, value_name = "KEY")]
    pub project: String,

    /// Jira API token (or set JIRA_API_TOKEN env var)
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Jira user email (or set JIRA_EMAIL env var)
    #[arg(long, value_name = "EMAIL")]
    pub email: Option<String>,

    /// Minimum severity to create tickets for
    #[arg(long, value_name = "SEVERITY", default_value = "medium")]
    pub min_severity: FailOnArg,
}

#[derive(Debug, clap::Args)]
pub struct LinearIssueArgs {
    /// Linear API key (or set LINEAR_API_KEY env var)
    #[arg(long, value_name = "KEY")]
    pub token: Option<String>,

    /// Linear team ID to create issues in
    #[arg(long, value_name = "TEAM_ID")]
    pub team: String,

    /// Linear label to add (e.g. "security")
    #[arg(long, value_name = "LABEL")]
    pub label: Option<String>,

    /// Linear project ID to associate issues with
    #[arg(long, value_name = "PROJECT_ID")]
    pub project: Option<String>,

    /// Minimum severity to create issues for
    #[arg(long, value_name = "SEVERITY", default_value = "medium")]
    pub min_severity: FailOnArg,
}
