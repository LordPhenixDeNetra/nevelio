use anyhow::{Context, Result};
use colored::Colorize;
use nevelio_core::types::{Finding, ScanConfig, ScanProfile};
use nevelio_core::{HttpClient, ScanSession};
use nevelio_reporting::{JsonReporter, ScanReport};
use std::path::PathBuf;
use std::time::Duration;

use crate::args::WatchArgs;
use crate::commands::{detect_spec_format, SpecFormat};

/// Monitor an API at regular intervals and alert when new findings appear.
pub async fn handle_watch(args: WatchArgs, verbose: bool) -> Result<()> {
    let interval_secs =
        parse_interval(&args.interval).context(format!("Intervalle invalide: '{}'", args.interval))?;

    let out_dir = args
        .out_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./nevelio-watch"));
    std::fs::create_dir_all(&out_dir)?;

    let target = args.url.clone();
    let profile = args
        .profile
        .map(nevelio_core::types::ScanProfile::from)
        .unwrap_or(ScanProfile::Normal);
    let stealth = matches!(profile, ScanProfile::Stealth);

    let config = ScanConfig {
        target: target.clone(),
        profile: profile.clone(),
        concurrency: profile.concurrency(),
        rate_limit: profile.rate_limit_per_sec(),
        timeout_ms: 5000,
        auth_token: args.auth_token.clone(),
        proxy: args.proxy.clone(),
        verbose,
        out_dir: out_dir.clone(),
        modules: vec![],
        dry_run: false,
        locale: rust_i18n::locale().to_string(),
    };

    let http_client = HttpClient::new(&config).context("Impossible de créer le client HTTP")?;
    let raw_client = http_client.inner().clone();

    let state_path = out_dir.join("watch_state.json");
    let mut scan_count: u64 = 0;

    // ── Banner ────────────────────────────────────────────────────────────────

    println!();
    println!(
        "{}",
        format!(
            "  👁  Nevelio Watch — {} (intervalle: {})",
            target, args.interval
        )
        .cyan()
        .bold()
    );
    println!("  État  : {}", state_path.display().to_string().dimmed());
    println!("  Profil: {:?}", config.profile);
    if let Some(ref wh) = args.notify_webhook {
        println!("  Webhook: {}", wh.dimmed());
    }
    println!("  Ctrl+C pour arrêter.\n");

    loop {
        scan_count += 1;
        let now = chrono::Utc::now();
        println!(
            "{}",
            format!(
                "[Scan #{} — {}]",
                scan_count,
                now.format("%Y-%m-%d %H:%M:%S UTC")
            )
            .bold()
        );

        // ── Discover endpoints ────────────────────────────────────────────────
        let endpoints = if let Some(ref spec) = args.spec {
            match detect_spec_format(spec) {
                SpecFormat::Har => nevelio_recon::parse_har(spec)
                    .unwrap_or_else(|e| { tracing::warn!("HAR error: {}", e); vec![] }),
                SpecFormat::Postman => nevelio_recon::parse_postman(spec)
                    .unwrap_or_else(|e| { tracing::warn!("Postman error: {}", e); vec![] }),
                SpecFormat::OpenApi => {
                    nevelio_recon::openapi::parse_spec(spec, &target, &raw_client)
                        .await
                        .unwrap_or_else(|e| { tracing::warn!("OpenAPI error: {}", e); vec![] })
                }
            }
        } else {
            nevelio_recon::discover_endpoints(&target, &raw_client, stealth)
                .await
                .unwrap_or_default()
        };

        println!(
            "  {} endpoint(s) découvert(s).",
            endpoints.len().to_string().bold()
        );

        // ── Run modules ───────────────────────────────────────────────────────
        let mut session = ScanSession::new(config.clone());
        for module in crate::modules::build_all_modules() {
            let findings = module.run(&session, &http_client, &endpoints).await;
            for f in findings {
                session.add_finding(f);
            }
        }
        let new_report = JsonReporter::generate(&session);

        // ── Compare with previous state ───────────────────────────────────────
        let prev_report: Option<ScanReport> = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());

        let novel = diff_findings(prev_report.as_ref(), &new_report);

        if novel.is_empty() {
            println!(
                "  {} {} finding(s) — aucun nouveau finding.",
                "✓".green(),
                new_report.findings.len()
            );
        } else {
            println!(
                "  {} {} NOUVEAU(X) finding(s) !",
                "⚠".red().bold(),
                novel.len().to_string().red().bold()
            );
            for f in &novel {
                println!(
                    "    [{}] {} — {} {}",
                    format!("{}", f.severity).bold(),
                    f.title,
                    f.method.dimmed(),
                    f.endpoint
                );
            }
            if let Some(ref webhook_url) = args.notify_webhook {
                match send_webhook(&raw_client, webhook_url, &target, &novel).await {
                    Ok(()) => println!("  {} Webhook notifié.", "→".blue()),
                    Err(e) => eprintln!("  Webhook error: {}", e),
                }
            }
        }

        // ── Persist state ─────────────────────────────────────────────────────
        let _ = JsonReporter::write_to_file(&new_report, &state_path);

        let next_time = now + chrono::Duration::seconds(interval_secs as i64);
        println!(
            "  Prochain scan dans {} ({})\n",
            args.interval,
            next_time.format("%H:%M:%S UTC").to_string().dimmed()
        );

        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse interval strings like "30s", "5m", "6h", "1d" into seconds.
pub(crate) fn parse_interval(s: &str) -> Result<u64> {
    if let Some(n) = s.strip_suffix('s') {
        return n.parse::<u64>().context("Invalid number in interval");
    }
    if let Some(n) = s.strip_suffix('m') {
        return n.parse::<u64>().map(|v| v * 60).context("Invalid number in interval");
    }
    if let Some(n) = s.strip_suffix('h') {
        return n.parse::<u64>().map(|v| v * 3600).context("Invalid number in interval");
    }
    if let Some(n) = s.strip_suffix('d') {
        return n.parse::<u64>().map(|v| v * 86_400).context("Invalid number in interval");
    }
    // Plain number → seconds
    s.parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Format d'intervalle invalide '{}'. Exemples : 30s, 5m, 6h, 1d", s))
}

/// Return findings that appear in `after` but not in `before`.
fn diff_findings<'a>(before: Option<&ScanReport>, after: &'a ScanReport) -> Vec<&'a Finding> {
    let Some(prev) = before else {
        return after.findings.iter().collect();
    };

    use std::collections::HashSet;
    let known: HashSet<(String, String, String)> = prev
        .findings
        .iter()
        .map(|f| (f.title.clone(), f.endpoint.clone(), f.method.clone()))
        .collect();

    after
        .findings
        .iter()
        .filter(|f| !known.contains(&(f.title.clone(), f.endpoint.clone(), f.method.clone())))
        .collect()
}

async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    target: &str,
    findings: &[&Finding],
) -> Result<()> {
    let payload = serde_json::json!({
        "source": "nevelio-watch",
        "target": target,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "new_findings_count": findings.len(),
        "findings": findings,
    });
    client
        .post(url)
        .json(&payload)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .context("Webhook POST failed")?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interval_seconds() {
        assert_eq!(parse_interval("30s").unwrap(), 30);
    }

    #[test]
    fn parse_interval_minutes() {
        assert_eq!(parse_interval("5m").unwrap(), 300);
    }

    #[test]
    fn parse_interval_hours() {
        assert_eq!(parse_interval("6h").unwrap(), 21_600);
    }

    #[test]
    fn parse_interval_days() {
        assert_eq!(parse_interval("1d").unwrap(), 86_400);
    }

    #[test]
    fn parse_interval_plain_number() {
        assert_eq!(parse_interval("120").unwrap(), 120);
    }

    #[test]
    fn parse_interval_invalid_returns_err() {
        assert!(parse_interval("invalid").is_err());
    }
}
