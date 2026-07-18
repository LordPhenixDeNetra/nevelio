mod extra;
pub use extra::*;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "nevelio",
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

    #[arg(long, global = true)]
    pub verbose: bool,

    #[arg(long, global = true)]
    pub accept_legal: bool,

    #[arg(long, global = true)]
    pub no_color: bool,

    #[arg(long, value_name = "LANG", global = true)]
    pub lang: Option<String>,

    #[arg(long, value_name = "SHELL")]
    pub generate_completion: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Scan(ScanArgs),
    #[command(alias = "convert")]
    Report(ReportArgs),
    Modules(ModulesArgs),
    Init,
    Diff(DiffArgs),
    Watch(WatchArgs),
    Shell(ShellArgs),
    Serve(ServeArgs),
    Notify(NotifyArgs),
    Issue(IssueArgs),
    Config(crate::config_cmd::ConfigArgs),
    #[command(about = "Run the autonomous AI security agent")]
    Agent(crate::agent_cmd::AgentArgs),
    #[command(about = "Start an MCP server exposing Nevelio tools to AI orchestrators")]
    Mcp(crate::mcp::McpArgs),
}

#[derive(Debug, clap::Args)]
#[command(after_help = "\
VARIABLES D'ENVIRONNEMENT :
  ANTHROPIC_API_KEY    Clé API Claude (requis pour --ai-suggestions)")]
pub struct ScanArgs {
    #[arg(long, value_name = "SPEC")]
    pub spec: Option<String>,

    #[arg(long, value_name = "URL")]
    pub target: Option<String>,

    #[arg(long, value_name = "URL", conflicts_with = "target")]
    pub url: Option<String>,

    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<ProfileArg>,

    #[arg(long = "module", value_name = "MODULE", num_args = 1..)]
    pub modules: Vec<String>,

    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,

    #[arg(long, value_name = "N")]
    pub rate_limit: Option<u64>,

    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    #[arg(long, value_name = "FORMAT")]
    pub output: Option<OutputFormat>,

    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,

    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<FailOnArg>,

    #[arg(long)]
    pub resume: bool,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub no_tui: bool,

    #[arg(long)]
    pub ai_suggestions: bool,

    #[arg(long)]
    pub ai_triage: bool,

    #[arg(long)]
    pub ai_remediation: bool,

    #[arg(long)]
    pub ai_report: bool,

    #[arg(long)]
    pub ai_payloads: bool,

    #[arg(long, value_name = "SCRIPT")]
    pub scripts: Vec<String>,

    #[arg(long, value_name = "FILE")]
    pub plugin: Vec<PathBuf>,

    #[arg(long, value_name = "FILE")]
    pub proto: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,

    #[arg(long, value_name = "FORMAT", default_value = "html")]
    pub format: OutputFormat,

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
    List,
    Show { name: String },
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

#[derive(Debug, Clone, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum FailOnArg {
    None,
    Low,
    Medium,
    High,
    Critical,
}
