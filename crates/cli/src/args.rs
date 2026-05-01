use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "nevelio",
    version = env!("CARGO_PKG_VERSION"),
    about = "Nevelio — API Penetration Testing Tool",
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
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan an API for vulnerabilities
    Scan(ScanArgs),
    /// Generate a report from a previous scan's JSON results
    Report(ReportArgs),
    /// List or inspect available attack modules
    Modules(ModulesArgs),
}

#[derive(Debug, clap::Args)]
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
    #[arg(long, value_name = "PROFILE", default_value = "normal")]
    pub profile: ProfileArg,

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
    #[arg(long, value_name = "SECONDS", default_value = "5")]
    pub timeout: u64,

    /// Authentication token (e.g. "Bearer eyJ..." or "Basic dXNlcjpwYXNz")
    #[arg(long, value_name = "TOKEN")]
    pub auth_token: Option<String>,

    /// HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Output format for findings
    #[arg(long, value_name = "FORMAT", default_value = "json")]
    pub output: OutputFormat,

    /// Directory to write output files
    #[arg(long, value_name = "PATH", default_value = ".")]
    pub out_dir: PathBuf,

    /// Simulate the scan without sending real HTTP requests
    #[arg(long)]
    pub dry_run: bool,
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
}

impl From<OutputFormat> for nevelio_reporting::ReportFormat {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Json => Self::Json,
            OutputFormat::Html => Self::Html,
            OutputFormat::Markdown => Self::Markdown,
        }
    }
}
