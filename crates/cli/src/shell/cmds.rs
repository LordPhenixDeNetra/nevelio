use anyhow::Result;
use colored::Colorize;
use nevelio_core::types::{ScanConfig, ScanProfile};
use nevelio_core::HttpClient;
use nevelio_reporting::JsonReporter;
use std::io;

use super::ShellCtx;

pub(super) fn list_endpoints(ctx: &ShellCtx) {
    if ctx.endpoints.is_empty() {
        println!("  Aucun endpoint. Lancez {} d'abord.", "scan".bold());
        return;
    }
    println!("  {} endpoint(s) :", ctx.endpoints.len().to_string().bold());
    for (i, ep) in ctx.endpoints.iter().enumerate() {
        println!("  [{:>3}] {} {}", i, ep.method.bold(), ep.full_url.dimmed());
    }
}

pub(super) fn show_endpoint(ctx: &ShellCtx, args: &[&str]) {
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

    println!(
        "  {} {}  {}",
        ep.method.bold(), ep.full_url.cyan(),
        if ep.auth_required { "[auth]".yellow().to_string() } else { String::new() }
    );
    if ep.parameters.is_empty() {
        println!("  Paramètres : aucun");
    } else {
        println!("  Paramètres :");
        for p in &ep.parameters {
            println!("    • {} ({:?}){}", p.name.bold(), p.location,
                if p.required { " *requis*" } else { "" });
        }
    }
}

pub(super) fn list_findings(ctx: &ShellCtx) {
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
            nevelio_core::types::Severity::Critical    => sev.red().bold(),
            nevelio_core::types::Severity::High        => sev.red(),
            nevelio_core::types::Severity::Medium      => sev.yellow(),
            nevelio_core::types::Severity::Low         => sev.blue(),
            nevelio_core::types::Severity::Informative => sev.dimmed(),
        };
        println!("  {} {} — {} {}", sev_colored, f.title.bold(), f.method.dimmed(), f.endpoint);
    }
}

pub(super) async fn replay_request(ctx: &ShellCtx, args: &[&str]) -> Result<()> {
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
        _        => client.get(&ep.full_url),
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
        if status.is_success() { status.to_string().green() } else { status.to_string().red() }
    );

    for (name, value) in headers.iter().take(10) {
        println!("  {}: {}", name.as_str().dimmed(), value.to_str().unwrap_or("?"));
    }

    let preview = if body.len() > 800 { &body[..800] } else { &body };
    println!("\n{}", preview.dimmed());
    if body.len() > 800 {
        println!("  … ({} bytes total)", body.len());
    }

    Ok(())
}

pub(super) fn export_findings(ctx: &ShellCtx) -> Result<()> {
    if ctx.findings.is_empty() {
        println!("  Aucun finding à exporter.");
        return Ok(());
    }

    std::fs::create_dir_all(&ctx.out_dir)?;

    let target = ctx.target.as_deref().unwrap_or("unknown").to_string();
    let config = ScanConfig {
        target: target.clone(),
        profile: ScanProfile::Normal,
        concurrency: 1, rate_limit: 10, timeout_ms: 5000,
        auth_token: None, proxy: None, verbose: false,
        out_dir: ctx.out_dir.clone(), modules: vec![],
        dry_run: false, locale: "fr".to_string(),
    };

    let mut session = nevelio_core::ScanSession::new(config);
    for f in &ctx.findings { session.add_finding(f.clone()); }
    session.finish();
    let report = JsonReporter::generate(&session);

    let path = ctx.out_dir.join("findings.json");
    JsonReporter::write_to_file(&report, &path)?;

    println!("  {} Rapport exporté → {}", "✓".green(), path.display().to_string().cyan());
    Ok(())
}
