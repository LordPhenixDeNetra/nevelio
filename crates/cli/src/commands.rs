use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing_subscriber::{fmt, EnvFilter};

use nevelio_core::types::{ScanConfig, ScanProfile};
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_module_access_control::AccessControlModule;
use nevelio_module_auth::AuthModule;
use nevelio_module_business_logic::BusinessLogicModule;
use nevelio_module_infra::InfraModule;
use nevelio_module_injection::InjectionModule;
use nevelio_reporting::{
    HtmlReporter, JsonReporter, JunitReporter, MarkdownReporter, ReportFormat, ScanReport,
};

use crate::args::{Cli, Commands, ModulesAction};
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
    };

    tracing::info!("{} report written to {}", label, path.display());
    Ok(path)
}

// ---------------------------------------------------------------------------
// Scan command
// ---------------------------------------------------------------------------

async fn handle_scan(args: crate::args::ScanArgs, verbose: bool) -> Result<()> {
    let target = args
        .target
        .or(args.url)
        .context("--target ou --url est requis")?;

    let base_profile: ScanProfile = args.profile.into();
    let concurrency = args.concurrency.unwrap_or(base_profile.concurrency());
    let rate_limit = args.rate_limit.unwrap_or(base_profile.rate_limit_per_sec());
    let output_format: ReportFormat = args.output.into();

    let config = ScanConfig {
        target: target.clone(),
        profile: base_profile,
        concurrency,
        rate_limit,
        timeout_ms: args.timeout * 1000,
        auth_token: args.auth_token,
        proxy: args.proxy,
        verbose,
        out_dir: args.out_dir.clone(),
        modules: args.modules,
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

    // Also write in the requested format if different from JSON
    let report_path = if matches!(output_format, ReportFormat::Json) {
        json_path
    } else {
        write_report(&report, &output_format, &out_dir)?
    };

    println!();
    output::print_summary(&session.findings);
    println!(
        "{:<12}: {}",
        "Rapport",
        report_path.display().to_string().cyan()
    );

    std::process::exit(ci_exit_code(&session.findings));
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
// CI/CD exit codes (CdC section 7.1)
// ---------------------------------------------------------------------------

fn ci_exit_code(findings: &[nevelio_core::types::Finding]) -> i32 {
    use nevelio_core::types::Severity;
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
