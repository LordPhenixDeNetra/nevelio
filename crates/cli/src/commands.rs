use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing_subscriber::{fmt, EnvFilter};

use nevelio_core::types::{Finding, ScanConfig, ScanProfile, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_module_access_control::AccessControlModule;
use nevelio_module_auth::AuthModule;
use nevelio_module_business_logic::BusinessLogicModule;
use nevelio_module_infra::InfraModule;
use nevelio_module_injection::InjectionModule;
use nevelio_reporting::{
    HtmlReporter, JsonReporter, JunitReporter, MarkdownReporter, ReportFormat, SarifReporter,
    ScanReport,
};

use crate::args::{Cli, Commands, FailOnArg, ModulesAction, OutputFormat};
use crate::config::NevelioConfig;
use crate::legal;
use crate::output;

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    fmt().with_env_filter(filter).without_time().init();

    if !cli.accept_legal {
        legal::display_and_confirm()?;
    } else {
        legal::display_banner();
    }

    match cli.command {
        Commands::Scan(args) => handle_scan(args, cli.verbose).await,
        Commands::Report(args) => handle_report(args).await,
        Commands::Modules(args) => handle_modules(args),
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
        .context("--target / --url requis (ou défini dans .nevelio.toml)")?;

    let profile: ScanProfile = args
        .profile
        .map(ScanProfile::from)
        .or_else(|| parse_profile(cfg_profile.as_deref()))
        .unwrap_or(ScanProfile::Normal);

    let output_format: OutputFormat = args
        .output
        .or_else(|| parse_output_format(cfg_output.as_deref()))
        .unwrap_or(OutputFormat::Json);

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
    };

    println!("{:<12}: {}", "Cible", target.cyan().bold());
    if let Some(ref spec) = args.spec {
        println!("{:<12}: {}", "Spec", spec);
    }
    println!("{:<12}: {:?}", "Profil", config.profile);
    if config.dry_run {
        println!("{}", "  [mode dry-run — aucune requête réelle envoyée]".yellow());
    }
    println!();

    let http_client = HttpClient::new(&config).context("Impossible de créer le client HTTP")?;
    let raw_client = http_client.inner().clone();

    // --- Recon ---
    let endpoints = if !config.dry_run {
        if let Some(ref spec_path) = args.spec {
            nevelio_recon::openapi::parse_spec(spec_path, &target, &raw_client)
                .await
                .context("Échec de la lecture du spec OpenAPI")?
        } else {
            nevelio_recon::discover_endpoints(&target, &raw_client)
                .await
                .context("Échec de la découverte des endpoints")?
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

    println!("{} endpoint(s) découvert(s)", endpoints.len());

    let mut session = ScanSession::new(config);

    let pb = ProgressBar::new(endpoints.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "[{bar:40.cyan/blue}] {pos}/{len} endpoints — {elapsed_precise}",
        )?
        .progress_chars("█▓░"),
    );

    let all_modules: Vec<Box<dyn AttackModule>> = vec![
        Box::new(AuthModule),
        Box::new(InjectionModule),
        Box::new(AccessControlModule),
        Box::new(BusinessLogicModule),
        Box::new(InfraModule),
    ];

    let active_modules: Vec<&Box<dyn AttackModule>> = if session.config.modules.is_empty() {
        all_modules.iter().collect()
    } else {
        all_modules
            .iter()
            .filter(|m| session.config.modules.iter().any(|n| n == m.name()))
            .collect()
    };

    if !session.config.dry_run {
        for module in &active_modules {
            tracing::info!("Running module: {}", module.name());
            let findings = module.run(&session, &http_client, &endpoints).await;
            for f in findings {
                output::print_finding(&f);
                session.add_finding(f);
            }
        }
    }

    for _ in &endpoints {
        pb.inc(1);
        if session.config.dry_run {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    pb.finish_with_message("Scan terminé");

    session.finish();

    let report = JsonReporter::generate(&session);
    let out_dir = session.config.out_dir.clone();

    // Always write JSON (canonical result)
    let json_path = out_dir.join("findings.json");
    JsonReporter::write_to_file(&report, &json_path)
        .context("Échec de l'écriture de findings.json")?;

    let report_format: ReportFormat = output_format.into();

    // Also write in the requested format if different from JSON
    let report_path = if matches!(report_format, ReportFormat::Json) {
        json_path
    } else {
        write_report(&report, &report_format, &out_dir)?
    };

    println!();
    output::print_summary(&session.findings);
    println!(
        "{:<12}: {}",
        "Rapport",
        report_path.display().to_string().cyan()
    );

    let exit_code = resolve_exit_code(&session.findings, args.fail_on);
    std::process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// Report command
// ---------------------------------------------------------------------------

async fn handle_report(args: crate::args::ReportArgs) -> Result<()> {
    let json =
        std::fs::read_to_string(&args.input).context("Impossible de lire le fichier JSON")?;
    let report: ScanReport = serde_json::from_str(&json).context("Fichier JSON invalide")?;

    println!(
        "Rapport : {} finding(s) — Cible: {} — Durée: {:.2}s",
        report.findings.len(),
        report.target,
        report.duration_secs
    );
    println!(
        "Résumé  : {} Critical  {} High  {} Medium  {} Low  {} Informative",
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low,
        report.summary.informative
    );
    println!();

    let format: ReportFormat = args.format.into();
    let path = write_report(&report, &format, &args.out_dir)?;
    println!("{}", format!("→ {}", path.display()).cyan());

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
        Box::new(InfraModule),
    ];

    match args.action {
        ModulesAction::List => {
            println!("{:<20} {}", "NOM".bold(), "DESCRIPTION".bold());
            println!("{}", "─".repeat(70));
            for m in &modules {
                println!("{:<20} {}", m.name(), m.description());
            }
        }
        ModulesAction::Show { name } => {
            if let Some(m) = modules.iter().find(|m| m.name() == name) {
                println!("Module      : {}", m.name().bold().cyan());
                println!("Description : {}", m.description());
            } else {
                eprintln!("Module inconnu : {}", name);
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
