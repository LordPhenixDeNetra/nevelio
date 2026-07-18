mod cmds;
mod ui;

use anyhow::Result;
use colored::Colorize;
use nevelio_core::types::{Endpoint, Finding, ScanConfig, ScanProfile};
use nevelio_core::{HttpClient, ScanSession};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use crate::args::ShellArgs;
use crate::scan::{detect_spec_format, SpecFormat};

pub(crate) struct ShellCtx {
    pub target: Option<String>,
    pub spec: Option<String>,
    pub auth_token: Option<String>,
    pub proxy: Option<String>,
    pub out_dir: PathBuf,
    pub endpoints: Vec<Endpoint>,
    pub findings: Vec<Finding>,
}

pub async fn handle_shell(args: ShellArgs, verbose: bool) -> Result<()> {
    ui::print_banner();

    let mut ctx = ShellCtx {
        target: args.url,
        spec: args.spec,
        auth_token: args.auth_token,
        proxy: args.proxy,
        out_dir: args
            .out_dir
            .unwrap_or_else(|| PathBuf::from("./nevelio-results")),
        endpoints: vec![],
        findings: vec![],
    };

    let stdin = io::stdin();

    loop {
        print!("{}", "nevelio> ".cyan().bold());
        io::stdout().flush()?;

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,
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
                        None => {
                            println!("  {}", "Aucune cible définie. Usage: target <url>".yellow())
                        }
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
                        if ctx.auth_token.is_some() {
                            "défini"
                        } else {
                            "absent"
                        }
                    );
                }
                Ok(())
            }
            "scan" => run_shell_scan(&mut ctx, verbose).await,
            "list" | "endpoints" => {
                cmds::list_endpoints(&ctx);
                Ok(())
            }
            "show" => {
                cmds::show_endpoint(&ctx, rest);
                Ok(())
            }
            "findings" | "results" => {
                cmds::list_findings(&ctx);
                Ok(())
            }
            "replay" => cmds::replay_request(&ctx, rest).await,
            "export" => cmds::export_findings(&ctx),
            "clear" => {
                ctx.endpoints.clear();
                ctx.findings.clear();
                println!("  Session effacée.");
                Ok(())
            }
            "status" => {
                ui::print_status(&ctx);
                Ok(())
            }
            "help" | "?" => {
                ui::print_help();
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

    let mut session = ScanSession::new(config);
    let modules = crate::modules::build_all_modules();
    let total = modules.len();

    for (i, module) in modules.iter().enumerate() {
        print!("  [{}/{}] {}…\r", i + 1, total, module.name());
        io::stdout().flush().ok();
        let findings = module.run(&session, &http_client, &ctx.endpoints).await;
        for f in findings {
            session.add_finding(f);
        }
    }
    println!();

    ctx.findings = session.findings.clone();

    let critical = ctx
        .findings
        .iter()
        .filter(|f| matches!(f.severity, nevelio_core::types::Severity::Critical))
        .count();
    let high = ctx
        .findings
        .iter()
        .filter(|f| matches!(f.severity, nevelio_core::types::Severity::High))
        .count();

    println!(
        "  {} Scan terminé — {} finding(s)  [{} critical, {} high]",
        "✓".green(),
        ctx.findings.len().to_string().bold(),
        if critical > 0 {
            critical.to_string().red().bold().to_string()
        } else {
            critical.to_string()
        },
        if high > 0 {
            high.to_string().red().to_string()
        } else {
            high.to_string()
        },
    );

    Ok(())
}
