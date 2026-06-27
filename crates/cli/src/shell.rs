use anyhow::Result;
use colored::Colorize;
use nevelio_core::types::{Endpoint, Finding, ScanConfig, ScanProfile};
use nevelio_core::{HttpClient, ScanSession};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use crate::args::ShellArgs;
use crate::commands::{detect_spec_format, SpecFormat};
use nevelio_reporting::JsonReporter;

/// Shell state shared between commands.
struct ShellCtx {
    target: Option<String>,
    spec: Option<String>,
    auth_token: Option<String>,
    proxy: Option<String>,
    out_dir: PathBuf,
    endpoints: Vec<Endpoint>,
    findings: Vec<Finding>,
}

/// Interactive shell for manual exploration and testing.
pub async fn handle_shell(args: ShellArgs, verbose: bool) -> Result<()> {
    print_banner();

    let mut ctx = ShellCtx {
        target: args.url,
        spec: args.spec,
        auth_token: args.auth_token,
        proxy: args.proxy,
        out_dir: args.out_dir.unwrap_or_else(|| PathBuf::from("./nevelio-results")),
        endpoints: vec![],
        findings: vec![],
    };

    let stdin = io::stdin();

    loop {
        print!("{}", "nevelio> ".cyan().bold());
        io::stdout().flush()?;

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF (Ctrl+D)
            Ok(_) => {}
            Err(_) => break,
        }

        let input = line.trim();
        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        let cmd = parts[0];
        let rest = &parts[1..];

        let result: Result<()> = match cmd {
            "target" | "url" => {
                if let Some(url) = rest.first() {
                    ctx.target = Some(url.to_string());
                    println!("  Cible : {}", url.cyan());
                } else {
                    match &ctx.target {
                        Some(t) => println!("  Cible actuelle : {}", t.cyan()),
                        None => println!("  {}", "Aucune cible définie. Usage: target <url>".yellow()),
                    }
                }
                Ok(())
            }
            "spec" => {
                if let Some(s) = rest.first() {
                    ctx.spec = Some(s.to_string());
                    println!("  Spec  : {}", s.cyan());
                } else {
                    match &ctx.spec {
                        Some(s) => println!("  Spec actuelle : {}", s.cyan()),
                        None => println!("  Aucune spec définie."),
                    }
                }
                Ok(())
            }
            "token" => {
                if let Some(t) = rest.first() {
                    ctx.auth_token = Some(t.to_string());
                    println!("  Token défini.");
                } else {
                    println!(
                        "  Token : {}",
                        if ctx.auth_token.is_some() { "défini" } else { "absent" }
                    );
                }
                Ok(())
            }
            "scan" => run_shell_scan(&mut ctx, verbose).await,
            "list" | "endpoints" => {
                list_endpoints(&ctx);
                Ok(())
            }
            "show" => {
                show_endpoint(&ctx, rest);
                Ok(())
            }
            "findings" | "results" => {
                list_findings(&ctx);
                Ok(())
            }
            "replay" => replay_request(&ctx, rest).await,
            "export" => export_findings(&ctx),
            "clear" => {
                ctx.endpoints.clear();
                ctx.findings.clear();
                println!("  Session effacée.");
                Ok(())
            }
            "status" => {
                print_status(&ctx);
                Ok(())
            }
            "help" | "?" => {
                print_help();
                Ok(())
            }
            "quit" | "exit" | "q" | ":q" => break,
            other => {
                eprintln!(
                    "  {}: '{}'. Tapez {} pour l'aide.",
                    "Commande inconnue".red(),
                    other,
                    "help".bold()
                );
                Ok(())
            }
        };

        if let Err(e) = result {
            eprintln!("  {}: {}", "Erreur".red().bold(), e);
        }
    }

    println!("\n{}", "Au revoir !".cyan());
    Ok(())
}

// ── Scan ──────────────────────────────────────────────────────────────────────

async fn run_shell_scan(ctx: &mut ShellCtx, verbose: bool) -> Result<()> {
    let target = ctx
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Aucune cible. Utilisez: target <url>"))?
        .to_string();

    let config = ScanConfig {
        target: target.clone(),
        profile: ScanProfile::Normal,
        concurrency: 10,
        rate_limit: 30,
        timeout_ms: 5000,
        auth_token: ctx.auth_token.clone(),
        proxy: ctx.proxy.clone(),
        verbose,
        out_dir: ctx.out_dir.clone(),
        modules: vec![],
        dry_run: false,
        locale: rust_i18n::locale().to_string(),
    };

    println!("  Scan de {}…", target.cyan());

    let http_client = HttpClient::new(&config)?;
    let raw_client = http_client.inner().clone();

    // Discover endpoints
    ctx.endpoints = if let Some(ref spec) = ctx.spec {
        match detect_spec_format(spec) {
            SpecFormat::Har => nevelio_recon::parse_har(spec)?,
            SpecFormat::Postman => nevelio_recon::parse_postman(spec)?,
            SpecFormat::OpenApi => {
                nevelio_recon::openapi::parse_spec(spec, &target, &raw_client).await?
            }
        }
    } else {
        nevelio_recon::discover_endpoints(&target, &raw_client, false).await?
    };

    println!(
        "  {} endpoint(s) découvert(s).",
        ctx.endpoints.len().to_string().bold()
    );

    // Run all modules
    let mut session = ScanSession::new(config);
    let modules = crate::modules::build_all_modules();
    let total = modules.len();

    for (i, module) in modules.iter().enumerate() {
        print!(
            "  [{}/{}] {}…\r",
            i + 1,
            total,
            module.name()
        );
        io::stdout().flush().ok();
        let findings = module.run(&session, &http_client, &ctx.endpoints).await;
        for f in findings {
            session.add_finding(f);
        }
    }
    println!(); // clear the \r line

    ctx.findings = session.findings.clone();

    let critical = ctx.findings.iter().filter(|f| matches!(f.severity, nevelio_core::types::Severity::Critical)).count();
    let high     = ctx.findings.iter().filter(|f| matches!(f.severity, nevelio_core::types::Severity::High)).count();

    println!(
        "  {} Scan terminé — {} finding(s)  [{} critical, {} high]",
        "✓".green(),
        ctx.findings.len().to_string().bold(),
        if critical > 0 { critical.to_string().red().bold().to_string() } else { critical.to_string() },
        if high > 0 { high.to_string().red().to_string() } else { high.to_string() },
    );

    Ok(())
}

// ── List endpoints ────────────────────────────────────────────────────────────

fn list_endpoints(ctx: &ShellCtx) {
    if ctx.endpoints.is_empty() {
        println!("  Aucun endpoint. Lancez {} d'abord.", "scan".bold());
        return;
    }
    println!("  {} endpoint(s) :", ctx.endpoints.len().to_string().bold());
    for (i, ep) in ctx.endpoints.iter().enumerate() {
        println!(
            "  [{:>3}] {} {}",
            i,
            ep.method.bold(),
            ep.full_url.dimmed()
        );
    }
}

// ── Show endpoint ─────────────────────────────────────────────────────────────

fn show_endpoint(ctx: &ShellCtx, args: &[&str]) {
    let Some(idx_str) = args.first() else {
        println!("  Usage: show <N>");
        return;
    };
    let Ok(idx) = idx_str.parse::<usize>() else {
        println!("  {} doit être un entier.", "N".bold());
        return;
    };
    let Some(ep) = ctx.endpoints.get(idx) else {
        println!("  Index {} hors limite (0–{}).", idx, ctx.endpoints.len().saturating_sub(1));
        return;
    };

    println!("  {} {}  {}", ep.method.bold(), ep.full_url.cyan(), if ep.auth_required { "[auth]".yellow().to_string() } else { String::new() });
    if ep.parameters.is_empty() {
        println!("  Paramètres : aucun");
    } else {
        println!("  Paramètres :");
        for p in &ep.parameters {
            println!("    • {} ({:?}){}", p.name.bold(), p.location, if p.required { " *requis*" } else { "" });
        }
    }
}

// ── List findings ─────────────────────────────────────────────────────────────

fn list_findings(ctx: &ShellCtx) {
    if ctx.findings.is_empty() {
        println!("  Aucun finding. Lancez {} d'abord.", "scan".bold());
        return;
    }
    println!("  {} finding(s) :", ctx.findings.len().to_string().bold());
    let mut sorted = ctx.findings.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
    for f in sorted {
        let sev = format!("[{}]", f.severity);
        let sev_colored = match f.severity {
            nevelio_core::types::Severity::Critical => sev.red().bold(),
            nevelio_core::types::Severity::High => sev.red(),
            nevelio_core::types::Severity::Medium => sev.yellow(),
            nevelio_core::types::Severity::Low => sev.blue(),
            nevelio_core::types::Severity::Informative => sev.dimmed(),
        };
        println!(
            "  {} {} — {} {}",
            sev_colored,
            f.title.bold(),
            f.method.dimmed(),
            f.endpoint
        );
    }
}

// ── Replay request ────────────────────────────────────────────────────────────

async fn replay_request(ctx: &ShellCtx, args: &[&str]) -> Result<()> {
    let Some(idx_str) = args.first() else {
        println!("  Usage: replay <N>");
        return Ok(());
    };
    let Ok(idx) = idx_str.parse::<usize>() else {
        println!("  {} doit être un entier.", "N".bold());
        return Ok(());
    };
    let Some(ep) = ctx.endpoints.get(idx) else {
        println!("  Index {} hors limite.", idx);
        return Ok(());
    };

    let config = ScanConfig {
        target: ep.full_url.clone(),
        profile: ScanProfile::Normal,
        concurrency: 1,
        rate_limit: 10,
        timeout_ms: 10_000,
        auth_token: ctx.auth_token.clone(),
        proxy: ctx.proxy.clone(),
        verbose: false,
        out_dir: ctx.out_dir.clone(),
        modules: vec![],
        dry_run: false,
        locale: rust_i18n::locale().to_string(),
    };
    let http_client = HttpClient::new(&config)?;
    let client = http_client.inner();

    println!("  {} {}", ep.method.bold(), ep.full_url.cyan());

    let req = match ep.method.as_str() {
        "POST" | "PUT" | "PATCH" => client.post(&ep.full_url),
        "DELETE" => client.delete(&ep.full_url),
        _ => client.get(&ep.full_url),
    }
    .timeout(std::time::Duration::from_secs(10))
    .build()?;

    let resp = client.execute(req).await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    println!(
        "  {} {}",
        "Status:".bold(),
        if status.is_success() {
            status.to_string().green()
        } else {
            status.to_string().red()
        }
    );

    for (name, value) in headers.iter().take(10) {
        println!(
            "  {}: {}",
            name.as_str().dimmed(),
            value.to_str().unwrap_or("?")
        );
    }

    let preview = if body.len() > 800 { &body[..800] } else { &body };
    println!("\n{}", preview.dimmed());
    if body.len() > 800 {
        println!("  … ({} bytes total)", body.len());
    }

    Ok(())
}

// ── Export findings ───────────────────────────────────────────────────────────

fn export_findings(ctx: &ShellCtx) -> Result<()> {
    if ctx.findings.is_empty() {
        println!("  Aucun finding à exporter.");
        return Ok(());
    }

    std::fs::create_dir_all(&ctx.out_dir)?;

    // Build a minimal ScanReport manually
    let target = ctx.target.as_deref().unwrap_or("unknown").to_string();
    let config = ScanConfig {
        target: target.clone(),
        profile: ScanProfile::Normal,
        concurrency: 1,
        rate_limit: 10,
        timeout_ms: 5000,
        auth_token: None,
        proxy: None,
        verbose: false,
        out_dir: ctx.out_dir.clone(),
        modules: vec![],
        dry_run: false,
        locale: "fr".to_string(),
    };
    let mut session = ScanSession::new(config);
    for f in &ctx.findings {
        session.add_finding(f.clone());
    }
    session.finish();
    let report = JsonReporter::generate(&session);

    let path = ctx.out_dir.join("findings.json");
    JsonReporter::write_to_file(&report, &path)?;

    println!(
        "  {} Rapport exporté → {}",
        "✓".green(),
        path.display().to_string().cyan()
    );
    Ok(())
}

// ── UI helpers ────────────────────────────────────────────────────────────────

fn print_banner() {
    println!();
    println!("{}", "  ╔══════════════════════════════════════════════╗".cyan());
    println!("{}", "  ║        Nevelio — Shell Interactif             ║".cyan());
    println!("{}", "  ╚══════════════════════════════════════════════╝".cyan());
    println!("  Tapez {} pour les commandes, {} pour quitter.\n", "help".bold(), "quit".bold());
}

fn print_help() {
    println!();
    println!("  {}", "Commandes disponibles :".bold());
    println!();
    let cmds = [
        ("target <url>",           "Définir la cible (ou afficher la cible actuelle)"),
        ("spec <path>",            "Définir le fichier spec (OpenAPI/Postman/HAR)"),
        ("token <token>",          "Définir le token d'authentification"),
        ("scan",                   "Lancer un scan complet sur la cible"),
        ("list",                   "Lister les endpoints découverts"),
        ("show <N>",               "Détails de l'endpoint numéro N"),
        ("findings",               "Afficher les findings du dernier scan"),
        ("replay <N>",             "Rejouer la requête vers l'endpoint N"),
        ("export",                 "Exporter les findings en JSON"),
        ("clear",                  "Effacer la session (endpoints + findings)"),
        ("status",                 "Afficher l'état de la session"),
        ("help",                   "Afficher cette aide"),
        ("quit",                   "Quitter le shell"),
    ];
    for (cmd, desc) in cmds {
        println!("  {:<20} {}", cmd.bold(), desc.dimmed());
    }
    println!();
}

fn print_status(ctx: &ShellCtx) {
    println!("  Cible    : {}", ctx.target.as_deref().unwrap_or("(non définie)").cyan());
    println!("  Spec     : {}", ctx.spec.as_deref().unwrap_or("(aucune)").dimmed());
    println!("  Token    : {}", if ctx.auth_token.is_some() { "défini" } else { "(aucun)" });
    println!("  Endpoints: {}", ctx.endpoints.len());
    println!("  Findings : {}", ctx.findings.len());
    println!("  Out dir  : {}", ctx.out_dir.display().to_string().dimmed());
}
