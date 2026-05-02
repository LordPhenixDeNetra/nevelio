use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;
use tracing_subscriber::{fmt, EnvFilter};

use nevelio_core::types::{Finding, ScanConfig, ScanProfile, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_module_access_control::AccessControlModule;
use nevelio_module_auth::AuthModule;
use nevelio_module_business_logic::BusinessLogicModule;
use nevelio_module_graphql::GraphqlModule;
use nevelio_module_infra::InfraModule;
use nevelio_module_injection::InjectionModule;
use nevelio_reporting::{
    HtmlReporter, JsonReporter, JunitReporter, MarkdownReporter, ReportFormat, SarifReporter,
    ScanReport,
};

use crate::ai_suggestions;
use crate::args::{Cli, Commands, FailOnArg, ModulesAction, OutputFormat};
use crate::config::NevelioConfig;
use crate::legal;
use crate::output;
use crate::tui::{self, ScanEvent};

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Detect and apply locale before any user-facing output
    let locale = crate::locale::detect(cli.lang.as_deref());
    rust_i18n::set_locale(&locale);

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
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

    match cli.command {
        Commands::Scan(args) => handle_scan(args, cli.verbose).await,
        Commands::Report(args) => handle_report(args).await,
        Commands::Modules(args) => handle_modules(args),
        Commands::Init => handle_init(),
    }
}

// ---------------------------------------------------------------------------
// Report writing helper
// ---------------------------------------------------------------------------

fn write_report(report: &ScanReport, format: &ReportFormat, out_dir: &Path) -> Result<PathBuf> {
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

// ---------------------------------------------------------------------------
// Scan command
// ---------------------------------------------------------------------------

async fn handle_scan(args: crate::args::ScanArgs, verbose: bool) -> Result<()> {
    // Load .nevelio.toml from working directory — extract all fields upfront
    let file_cfg = NevelioConfig::load();
    // Call method first (before any field moves that invalidate the borrow)
    let cfg_auth_token  = file_cfg.resolved_auth_token();
    let cfg_target      = file_cfg.target;
    let cfg_profile     = file_cfg.profile;
    let cfg_output      = file_cfg.output;
    let cfg_out_dir     = file_cfg.out_dir;
    let cfg_timeout     = file_cfg.timeout;
    let cfg_modules     = file_cfg.modules;
    let cfg_concurrency = file_cfg.concurrency;
    let cfg_rate_limit  = file_cfg.rate_limit;
    let cfg_proxy       = file_cfg.proxy;

    // Merge: CLI arg wins over config file; config file wins over hardcoded default.
    let target = args
        .target
        .or(args.url)
        .or(cfg_target)
        .context(t!("error.no_target").to_string())?;

    if !target.starts_with("http://") && !target.starts_with("https://") {
        anyhow::bail!("{}", t!("error.invalid_url", url = target.as_str()));
    }

    let profile: ScanProfile = args
        .profile
        .map(ScanProfile::from)
        .or_else(|| parse_profile(cfg_profile.as_deref()))
        .unwrap_or(ScanProfile::Normal);

    let output_format: OutputFormat = args
        .output
        .or_else(|| parse_output_format(cfg_output.as_deref()))
        .unwrap_or(OutputFormat::Html);

    let out_dir: PathBuf = args
        .out_dir
        .or(cfg_out_dir)
        .unwrap_or_else(|| PathBuf::from("."));

    let timeout: u64 = args.timeout.or(cfg_timeout).unwrap_or(5);

    let modules: Vec<String> = if !args.modules.is_empty() {
        args.modules
    } else {
        cfg_modules.unwrap_or_default()
    };

    let auth_token = args.auth_token.or(cfg_auth_token);
    let proxy = args.proxy.or(cfg_proxy);

    let concurrency = args
        .concurrency
        .or(cfg_concurrency)
        .unwrap_or_else(|| profile.concurrency());
    let rate_limit = args
        .rate_limit
        .or(cfg_rate_limit)
        .unwrap_or_else(|| profile.rate_limit_per_sec());

    let config = ScanConfig {
        target: target.clone(),
        profile,
        concurrency,
        rate_limit,
        timeout_ms: timeout * 1000,
        auth_token,
        proxy,
        verbose,
        out_dir: out_dir.clone(),
        modules,
        dry_run: args.dry_run,
        locale: rust_i18n::locale().to_string(),
    };

    use std::io::IsTerminal;
    let use_tui = !args.no_tui && !args.dry_run && std::io::stdout().is_terminal();
    let ai_suggestions = args.ai_suggestions;

    if ai_suggestions && std::env::var("ANTHROPIC_API_KEY").is_err() {
        eprintln!("{}", t!("scan.ai_warning").yellow());
    }

    if !use_tui {
        println!("{:<12}: {}", t!("scan.label.target"), target.cyan().bold());
        if let Some(ref spec) = args.spec {
            println!("{:<12}: {}", t!("scan.label.spec"), spec);
        }
        println!("{:<12}: {:?}", t!("scan.label.profile"), config.profile);
        println!("{:<12}: {}", t!("scan.label.output"), out_dir.display().to_string().dimmed());
        if config.dry_run {
            println!("{}", t!("scan.dry_run").yellow());
        }
        println!();
    }

    if !use_tui && !config.dry_run {
        let names: Vec<&str> = if config.modules.is_empty() {
            vec!["auth", "injection", "access-control", "business-logic", "graphql", "infra"]
        } else {
            config.modules.iter().map(String::as_str).collect()
        };
        println!("{:<12}: {}", t!("scan.label.modules"), names.join(", ").dimmed());
        println!();
    }

    let http_client = HttpClient::new(&config).context(t!("error.http_client").to_string())?;
    let raw_client = http_client.inner().clone();

    // --- Recon ---
    let endpoints = if !config.dry_run {
        if let Some(ref spec_path) = args.spec {
            nevelio_recon::openapi::parse_spec(spec_path, &target, &raw_client)
                .await
                .context(t!("error.spec_read").to_string())?
        } else {
            nevelio_recon::discover_endpoints(&target, &raw_client)
                .await
                .context(t!("error.discovery").to_string())?
        }
    } else {
        vec![nevelio_core::types::Endpoint {
            method: "GET".to_string(),
            path: "/".to_string(),
            full_url: target.clone(),
            parameters: vec![],
            auth_required: false,
        }]
    };

    if !use_tui {
        println!("{}", t!("scan.endpoints_found", count = endpoints.len()));
    }

    let mut session = ScanSession::new(config);

    let all_modules: Vec<Box<dyn AttackModule>> = vec![
        Box::new(AuthModule),
        Box::new(InjectionModule),
        Box::new(AccessControlModule),
        Box::new(BusinessLogicModule),
        Box::new(GraphqlModule),
        Box::new(InfraModule),
    ];

    let module_names: Vec<String> = all_modules.iter().map(|m| m.name().to_string()).collect();

    // Resume: load previous findings and completed modules from <out_dir>
    let mut completed_modules: Vec<String> = Vec::new();
    if args.resume {
        if let Some(prev) = load_progress(&out_dir) {
            if !use_tui {
                println!("{}", t!(
                    "scan.resume",
                    count = prev.completed_modules.len(),
                    modules = prev.completed_modules.join(", ").as_str()
                ).yellow());
            }
            completed_modules = prev.completed_modules.clone();
            if let Ok(prev_report) = load_findings_json(&out_dir) {
                for f in prev_report.findings {
                    session.add_finding(f);
                }
            }
        } else if !use_tui {
            println!("{}", t!("scan.no_progress").yellow());
        }
    }

    let active_modules: Vec<&Box<dyn AttackModule>> = all_modules
        .iter()
        .filter(|m| {
            let in_scope = session.config.modules.is_empty()
                || session.config.modules.iter().any(|n| n == m.name());
            let already_done = completed_modules.iter().any(|c| c == m.name());
            in_scope && !already_done
        })
        .collect();

    // --- TUI setup ---
    let tui_tx: Option<std_mpsc::Sender<ScanEvent>> = if use_tui {
        let (tx, rx) = std_mpsc::channel();
        let names = module_names.clone();
        std::thread::spawn(move || {
            if let Err(e) = tui::run_tui_blocking(rx, names) {
                eprintln!("{}", t!("error.tui", msg = e.to_string().as_str()));
            }
        });
        let _ = tx.send(ScanEvent::EndpointScanned {
            total: endpoints.len(),
            done: 0,
        });
        Some(tx)
    } else {
        None
    };

    // --- Plain mode progress bar ---
    let pb = if !use_tui {
        let bar = ProgressBar::new(endpoints.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "[{bar:40.cyan/blue}] {pos}/{len} endpoints — {elapsed_precise} · ETA {eta}",
            )?
            .progress_chars("█▓░"),
        );
        Some(bar)
    } else {
        None
    };

    if !session.config.dry_run {
        for module in &active_modules {
            tracing::info!("Running module: {}", module.name());
            if let Some(ref tx) = tui_tx {
                let _ = tx.send(ScanEvent::ModuleStarted { name: module.name().to_string() });
            }
            let findings = module.run(&session, &http_client, &endpoints).await;
            for f in findings {
                if let Some(ref tx) = tui_tx {
                    let _ = tx.send(ScanEvent::FindingFound(Box::new(f.clone())));
                } else {
                    output::print_finding(&f);
                }
                session.add_finding(f);
            }
            completed_modules.push(module.name().to_string());
            if let Some(ref tx) = tui_tx {
                let _ = tx.send(ScanEvent::ModuleFinished { name: module.name().to_string() });
            }
            save_progress(&out_dir, &completed_modules, &session.config.target);
            let checkpoint = JsonReporter::generate(&session);
            let _ = JsonReporter::write_to_file(&checkpoint, &out_dir.join("findings.json"));
        }
    }

    for (i, _) in endpoints.iter().enumerate() {
        if let Some(ref tx) = tui_tx {
            let _ = tx.send(ScanEvent::EndpointScanned {
                total: endpoints.len(),
                done: i + 1,
            });
        }
        if let Some(ref bar) = pb {
            bar.inc(1);
        }
        if session.config.dry_run {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    if let Some(ref tx) = tui_tx {
        let _ = tx.send(ScanEvent::ScanComplete);
    }
    if let Some(bar) = pb {
        bar.finish_with_message(t!("scan.finished").to_string());
    }

    session.finish();

    let report = JsonReporter::generate(&session);
    let out_dir = session.config.out_dir.clone();

    let json_path = out_dir.join("findings.json");
    JsonReporter::write_to_file(&report, &json_path)
        .context(t!("error.json_write").to_string())?;

    let report_format: ReportFormat = output_format.into();
    let report_path = if matches!(report_format, ReportFormat::Json) {
        json_path
    } else {
        write_report(&report, &report_format, &out_dir)?
    };

    // Wait a moment for TUI thread to receive ScanComplete before we print to stdout
    if use_tui {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    println!();
    output::print_summary(&session.findings);
    println!(
        "{:<12}: {}",
        t!("scan.report_label"),
        report_path.display().to_string().cyan()
    );

    if ai_suggestions {
        println!();
        println!("{}", t!("scan.ai_generating").cyan());
        match ai_suggestions::generate_and_save(&session.findings, &out_dir).await {
            Ok(()) => {}
            Err(e) => eprintln!("{}", t!("scan.ai_saved", path = e.to_string().as_str()).yellow()),
        }
    }

    let exit_code = resolve_exit_code(&session.findings, args.fail_on);
    std::process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// Init command
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Report command
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Modules command
// ---------------------------------------------------------------------------

fn handle_modules(args: crate::args::ModulesArgs) -> Result<()> {
    let modules: Vec<Box<dyn AttackModule>> = vec![
        Box::new(AuthModule),
        Box::new(InjectionModule),
        Box::new(AccessControlModule),
        Box::new(BusinessLogicModule),
        Box::new(GraphqlModule),
        Box::new(InfraModule),
    ];

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

// ---------------------------------------------------------------------------
// Exit code helpers
// ---------------------------------------------------------------------------

/// Default tiered exit codes: 0=clean, 1=low/medium, 2=high, 3=critical.
fn ci_exit_code(findings: &[Finding]) -> i32 {
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return 3;
    }
    if findings.iter().any(|f| f.severity == Severity::High) {
        return 2;
    }
    if findings
        .iter()
        .any(|f| f.severity == Severity::Medium || f.severity == Severity::Low)
    {
        return 1;
    }
    0
}

/// When `--fail-on` is set: exit 1 if any finding meets or exceeds the threshold, else 0.
fn fail_on_exit_code(findings: &[Finding], fail_on: FailOnArg) -> i32 {
    let threshold = match fail_on {
        FailOnArg::None => return 0,
        FailOnArg::Low => Severity::Low,
        FailOnArg::Medium => Severity::Medium,
        FailOnArg::High => Severity::High,
        FailOnArg::Critical => Severity::Critical,
    };
    if findings.iter().any(|f| f.severity >= threshold) {
        1
    } else {
        0
    }
}

fn resolve_exit_code(findings: &[Finding], fail_on: Option<FailOnArg>) -> i32 {
    match fail_on {
        Some(level) => fail_on_exit_code(findings, level),
        None => ci_exit_code(findings),
    }
}

// ---------------------------------------------------------------------------
// Config file merge helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Resume / progress helpers
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ScanProgress {
    target: String,
    completed_modules: Vec<String>,
}

fn save_progress(out_dir: &Path, completed: &[String], target: &str) {
    let progress = ScanProgress {
        target: target.to_string(),
        completed_modules: completed.to_vec(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&progress) {
        let _ = std::fs::write(out_dir.join("scan_progress.json"), json);
    }
}

fn load_progress(out_dir: &Path) -> Option<ScanProgress> {
    let path = out_dir.join("scan_progress.json");
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn load_findings_json(out_dir: &Path) -> Result<ScanReport> {
    let path = out_dir.join("findings.json");
    let content = std::fs::read_to_string(path).context(t!("error.findings_missing").to_string())?;
    serde_json::from_str(&content).context(t!("error.findings_invalid").to_string())
}

fn parse_profile(s: Option<&str>) -> Option<ScanProfile> {
    match s? {
        "stealth" => Some(ScanProfile::Stealth),
        "normal" => Some(ScanProfile::Normal),
        "aggressive" => Some(ScanProfile::Aggressive),
        _ => None,
    }
}

fn parse_output_format(s: Option<&str>) -> Option<OutputFormat> {
    match s? {
        "json" => Some(OutputFormat::Json),
        "html" => Some(OutputFormat::Html),
        "markdown" => Some(OutputFormat::Markdown),
        "junit" => Some(OutputFormat::Junit),
        "sarif" => Some(OutputFormat::Sarif),
        _ => None,
    }
}
