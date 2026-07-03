use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use rust_i18n::t;
use std::path::{Path, PathBuf};
use tracing_subscriber::{fmt, EnvFilter};

use nevelio_core::types::{Finding, Severity};
use nevelio_reporting::{
    HtmlReporter, JsonReporter, JunitReporter, MarkdownReporter, ReportFormat, SarifReporter,
    ScanReport,
};

use crate::args::{Cli, Commands, FailOnArg, ModulesAction};
use crate::legal;
use crate::output;

pub async fn run() -> Result<()> {
    {
        use clap::Parser as _;
        let cli = crate::args::Cli::parse();
        if let Some(ref shell) = cli.generate_completion {
            generate_completion(shell);
            return Ok(());
        }
    }
    let cli = Cli::parse();

    let locale = crate::locale::detect(cli.lang.as_deref());
    rust_i18n::set_locale(&locale);

    let filter = if cli.verbose { EnvFilter::new("debug") } else { EnvFilter::new("warn") };
    fmt().with_env_filter(filter).without_time().init();

    if cli.no_color {
        colored::control::set_override(false);
    }

    if !cli.accept_legal {
        legal::display_and_confirm()?;
    } else {
        legal::persist_acceptance_if_needed();
        legal::display_banner();
    }

    // First-run: if no global config exists and this isn't already `config init`, auto-launch it
    if !nevelio_config::global_config_exists()
        && !matches!(cli.command, Commands::Config(_))
    {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            println!("{}", t!("config.first_run.msg").yellow());
            println!();
            crate::config_cmd::handle_config(crate::config_cmd::ConfigArgs {
                action: crate::config_cmd::ConfigAction::Init,
            })?;
            println!();
        } else {
            eprintln!("{}", t!("config.first_run.hint").yellow());
        }
    }

    match cli.command {
        Commands::Scan(args)    => crate::scan::handle_scan(args, cli.verbose).await,
        Commands::Report(args)  => handle_report(args).await,
        Commands::Modules(args) => handle_modules(args),
        Commands::Init          => handle_init(),
        Commands::Diff(args)    => crate::diff::handle_diff(args).await,
        Commands::Watch(args)   => crate::watch::handle_watch(args, cli.verbose).await,
        Commands::Shell(args)   => crate::shell::handle_shell(args, cli.verbose).await,
        Commands::Serve(args)   => crate::serve::handle_serve(args).await,
        Commands::Notify(args)  => crate::notify::handle_notify(args).await,
        Commands::Issue(args)   => crate::issue::handle_issue(args).await,
        Commands::Config(args)  => crate::config_cmd::handle_config(args),
        Commands::Agent(args)   => crate::agent_cmd::handle_agent(args).await,
    }
}

pub(crate) fn write_report(report: &ScanReport, format: &ReportFormat, out_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;

    let (path, label) = match format {
        ReportFormat::Json => {
            let p = out_dir.join("findings.json");
            JsonReporter::write_to_file(report, &p)?;
            (p, "JSON")
        }
        ReportFormat::Html => {
            let p = out_dir.join("report.html");
            HtmlReporter::write_to_file(report, &p)?;
            (p, "HTML")
        }
        ReportFormat::Markdown => {
            let p = out_dir.join("report.md");
            MarkdownReporter::write_to_file(report, &p)?;
            (p, "Markdown")
        }
        ReportFormat::Junit => {
            let p = out_dir.join("security-report.xml");
            JunitReporter::write_to_file(report, &p)?;
            (p, "JUnit XML")
        }
        ReportFormat::Sarif => {
            let p = out_dir.join("security-report.sarif");
            SarifReporter::write_to_file(report, &p)?;
            (p, "SARIF")
        }
    };

    tracing::info!("{} report written to {}", label, path.display());
    Ok(path)
}

const NEVELIO_TOML_TEMPLATE: &str = r#"# .nevelio.toml — Configuration Nevelio
# Toutes les clés sont optionnelles. Les arguments CLI ont la priorité.

# URL de base de l'API cible
# target = "https://api.example.com"

# Profil de scan : stealth | normal | aggressive
# profile = "normal"

# Format de sortie : html | json | markdown | junit | sarif
# output = "html"

# Répertoire des fichiers de sortie
# out_dir = "./nevelio-results"

# Timeout des requêtes en secondes
# timeout = 5

# Modules à activer (vide = tous)
# modules = ["auth", "injection", "access-control", "business-logic", "graphql", "infra"]

# Concurrence maximale (requêtes simultanées)
# concurrency = 10

# Limite de débit (requêtes par seconde)
# rate_limit = 20

# Token d'authentification — préférer auth_token_env pour ne pas exposer le token
# auth_token = "Bearer eyJ..."

# Variable d'environnement contenant le token (recommandé)
# auth_token_env = "API_TOKEN"

# Proxy HTTP (ex. Burp Suite)
# proxy = "http://127.0.0.1:8080"
"#;

fn handle_init() -> Result<()> {
    let path = std::path::Path::new(".nevelio.toml");
    if path.exists() {
        eprintln!("{}", t!("error.toml_exists").yellow());
        std::process::exit(1);
    }
    std::fs::write(path, NEVELIO_TOML_TEMPLATE)
        .context(t!("error.toml_create").to_string())?;
    println!("{}", t!("init.created").green());
    Ok(())
}

async fn handle_report(args: crate::args::ReportArgs) -> Result<()> {
    let json = std::fs::read_to_string(&args.input)
        .context(t!("error.json_read").to_string())?;
    let report: ScanReport = serde_json::from_str(&json)
        .context(t!("error.json_invalid").to_string())?;

    println!("{}", t!(
        "scan.report_line",
        count = report.findings.len(),
        target = report.target.as_str(),
        secs = format!("{:.2}", report.duration_secs).as_str()
    ));
    output::print_summary(&report.findings);
    println!();

    let format: ReportFormat = args.format.into();
    let path = write_report(&report, &format, &args.out_dir)?;
    println!("{}", t!("scan.finding_arrow", title = path.display().to_string().as_str()).cyan());

    Ok(())
}

fn handle_modules(args: crate::args::ModulesArgs) -> Result<()> {
    let modules = crate::modules::build_all_modules();

    match args.action {
        ModulesAction::List => {
            println!("{:<20} {}", t!("modules.header.name").bold(), t!("modules.header.desc").bold());
            println!("{}", "─".repeat(70));
            for m in &modules {
                println!("{:<20} {}", m.name(), m.description());
            }
        }
        ModulesAction::Show { name } => {
            if let Some(m) = modules.iter().find(|m| m.name() == name) {
                println!("{}", t!("modules.show.name", name = m.name().bold().cyan().to_string().as_str()));
                println!("{}", t!("modules.show.desc", desc = m.description()));
            } else {
                eprintln!("{}", t!("error.unknown_module", name = name.as_str()));
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn ci_exit_code(findings: &[Finding]) -> i32 {
    if findings.iter().any(|f| f.severity == Severity::Critical) { return 3; }
    if findings.iter().any(|f| f.severity == Severity::High) { return 2; }
    if findings.iter().any(|f| f.severity == Severity::Medium || f.severity == Severity::Low) {
        return 1;
    }
    0
}

fn fail_on_exit_code(findings: &[Finding], fail_on: FailOnArg) -> i32 {
    let threshold = match fail_on {
        FailOnArg::None     => return 0,
        FailOnArg::Low      => Severity::Low,
        FailOnArg::Medium   => Severity::Medium,
        FailOnArg::High     => Severity::High,
        FailOnArg::Critical => Severity::Critical,
    };
    if findings.iter().any(|f| f.severity >= threshold) { 1 } else { 0 }
}

pub(crate) fn resolve_exit_code(findings: &[Finding], fail_on: Option<FailOnArg>) -> i32 {
    match fail_on {
        Some(level) => fail_on_exit_code(findings, level),
        None        => ci_exit_code(findings),
    }
}

pub fn generate_completion(shell: &str) {
    use clap::CommandFactory;
    use std::io;

    let mut cmd = crate::args::Cli::command();
    let shell_enum = match shell.to_lowercase().as_str() {
        "bash"       => clap_complete::Shell::Bash,
        "zsh"        => clap_complete::Shell::Zsh,
        "fish"       => clap_complete::Shell::Fish,
        "powershell" => clap_complete::Shell::PowerShell,
        "elvish"     => clap_complete::Shell::Elvish,
        other => {
            eprintln!("Shell non supporté : '{}'. Shells disponibles : bash, zsh, fish, powershell, elvish", other);
            return;
        }
    };

    clap_complete::generate(shell_enum, &mut cmd, "nevelio", &mut io::stdout());
}
