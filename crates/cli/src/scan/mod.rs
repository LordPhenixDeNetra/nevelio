mod exec;

use anyhow::{Context, Result};
use colored::Colorize;
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use nevelio_core::types::{Endpoint, ScanConfig, ScanProfile};
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_reporting::ScanReport;

use crate::args::{OutputFormat, ScanArgs};
use crate::config::NevelioConfig;

// ---------------------------------------------------------------------------
// Spec format detection (also used by shell.rs)
// ---------------------------------------------------------------------------

pub(crate) enum SpecFormat {
    OpenApi,
    Postman,
    Har,
}

pub(crate) fn detect_spec_format(path: &str) -> SpecFormat {
    if path.starts_with("http://") || path.starts_with("https://") {
        return SpecFormat::OpenApi;
    }
    if path.ends_with(".har") {
        return SpecFormat::Har;
    }
    if let Ok(content) = std::fs::read_to_string(path) {
        let head = &content[..content.len().min(512)];
        if head.contains("_postman_schema") || head.contains("__export_format") {
            return SpecFormat::Postman;
        }
        if head.contains("\"log\"") && head.contains("\"entries\"") {
            return SpecFormat::Har;
        }
    }
    SpecFormat::OpenApi
}

// ---------------------------------------------------------------------------
// Resume / progress helpers
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub(crate) struct ScanProgress {
    pub target: String,
    pub completed_modules: Vec<String>,
}

pub(crate) fn save_progress(out_dir: &Path, completed: &[String], target: &str) {
    let progress = ScanProgress {
        target: target.to_string(),
        completed_modules: completed.to_vec(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&progress) {
        let _ = std::fs::write(out_dir.join("scan_progress.json"), json);
    }
}

pub(crate) fn load_progress(out_dir: &Path) -> Option<ScanProgress> {
    let path = out_dir.join("scan_progress.json");
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub(crate) fn load_findings_json(out_dir: &Path) -> Result<ScanReport> {
    let path = out_dir.join("findings.json");
    let content =
        std::fs::read_to_string(path).context(t!("error.findings_missing").to_string())?;
    serde_json::from_str(&content).context(t!("error.findings_invalid").to_string())
}

// ---------------------------------------------------------------------------
// Config merge helpers
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

// ---------------------------------------------------------------------------
// Plugin registry loader
// ---------------------------------------------------------------------------

pub(crate) fn load_plugin_registry() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let candidates: Vec<PathBuf> = [
        dirs_home().map(|h| h.join(".config").join("nevelio").join("plugins.toml")),
        Some(PathBuf::from("./nevelio-plugins.toml")),
    ]
    .into_iter()
    .flatten()
    .filter(|p| p.exists())
    .collect();

    for registry_path in candidates {
        let Ok(content) = std::fs::read_to_string(&registry_path) else {
            continue;
        };
        let Ok(table) = content.parse::<toml::Value>() else {
            continue;
        };

        if let Some(plugins) = table.get("plugins").and_then(|p| p.as_array()) {
            for plugin in plugins {
                let enabled = plugin
                    .get("enabled")
                    .and_then(|e| e.as_bool())
                    .unwrap_or(true);
                if !enabled {
                    continue;
                }
                if let Some(path_str) = plugin.get("path").and_then(|p| p.as_str()) {
                    let p = PathBuf::from(path_str);
                    if p.exists() {
                        paths.push(p);
                    } else {
                        tracing::warn!("Registry plugin path not found: {}", path_str);
                    }
                }
            }
        }
    }
    paths
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}

// ---------------------------------------------------------------------------
// Scan command entry point
// ---------------------------------------------------------------------------

pub async fn handle_scan(args: ScanArgs, verbose: bool) -> Result<()> {
    let file_cfg = NevelioConfig::load();
    let cfg_auth_token = file_cfg.resolved_auth_token();
    let cfg_suppress = file_cfg.suppress;
    let cfg_target = file_cfg.target;
    let cfg_profile = file_cfg.profile;
    let cfg_output = file_cfg.output;
    let cfg_out_dir = file_cfg.out_dir;
    let cfg_timeout = file_cfg.timeout;
    let cfg_modules = file_cfg.modules;
    let cfg_concurrency = file_cfg.concurrency;
    let cfg_rate_limit = file_cfg.rate_limit;
    let cfg_proxy = file_cfg.proxy;

    let fail_on = args.fail_on;

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
        .unwrap_or_else(|| PathBuf::from("./nevelio-results"));
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
    let ai_triage = args.ai_triage;
    let ai_remediation = args.ai_remediation;
    let ai_report = args.ai_report;
    let ai_payloads = args.ai_payloads;
    let script_paths = args.scripts.clone();

    if ai_suggestions && std::env::var("ANTHROPIC_API_KEY").is_err() {
        eprintln!("{}", t!("scan.ai_warning").yellow());
    }

    if !use_tui {
        println!("{:<12}: {}", t!("scan.label.target"), target.cyan().bold());
        if let Some(ref spec) = args.spec {
            println!("{:<12}: {}", t!("scan.label.spec"), spec);
        }
        println!("{:<12}: {:?}", t!("scan.label.profile"), config.profile);
        println!(
            "{:<12}: {}",
            t!("scan.label.output"),
            out_dir.display().to_string().dimmed()
        );
        if config.dry_run {
            println!("{}", t!("scan.dry_run").yellow());
        }
        println!();
    }

    if !use_tui && !config.dry_run {
        let names: Vec<&str> = if config.modules.is_empty() {
            vec![
                "auth",
                "injection",
                "access-control",
                "business-logic",
                "graphql",
                "infra",
                "ssrf",
                "oauth2",
            ]
        } else {
            config.modules.iter().map(String::as_str).collect()
        };
        println!(
            "{:<12}: {}",
            t!("scan.label.modules"),
            names.join(", ").dimmed()
        );
        println!();
    }

    let http_client = HttpClient::new(&config).context(t!("error.http_client").to_string())?;
    let raw_client = http_client.inner().clone();

    let endpoints = if !config.dry_run {
        if let Some(ref spec_path) = args.spec {
            match detect_spec_format(spec_path) {
                SpecFormat::Har => {
                    nevelio_recon::parse_har(spec_path).context("Erreur lecture fichier HAR")?
                }
                SpecFormat::Postman => nevelio_recon::parse_postman(spec_path)
                    .context("Erreur lecture collection Postman/Insomnia")?,
                SpecFormat::OpenApi => {
                    nevelio_recon::openapi::parse_spec(spec_path, &target, &raw_client)
                        .await
                        .context(t!("error.spec_read").to_string())?
                }
            }
        } else {
            let stealth = matches!(config.profile, ScanProfile::Stealth);
            nevelio_recon::discover_endpoints(&target, &raw_client, stealth)
                .await
                .context(t!("error.discovery").to_string())?
        }
    } else {
        vec![Endpoint {
            method: "GET".to_string(),
            path: "/".to_string(),
            full_url: target.clone(),
            parameters: vec![],
            auth_required: false,
        }]
    };

    let mut endpoints = endpoints;
    if let Some(ref proto_path) = args.proto {
        let proto_str = proto_path.to_string_lossy();
        match nevelio_recon::parse_proto(&proto_str) {
            Ok(services) => {
                let grpc_eps = nevelio_recon::services_to_endpoints(&target, &services);
                let grpc_count = grpc_eps.len();
                endpoints.extend(grpc_eps);
                if !use_tui {
                    println!(
                        "  {} Proto: {} service(s) → {} endpoint(s) gRPC ajoutés",
                        "✓".green(),
                        services.len(),
                        grpc_count
                    );
                }
            }
            Err(e) => eprintln!("  ⚠ Erreur lecture .proto : {}", e),
        }
    }

    if !use_tui {
        println!("{}", t!("scan.endpoints_found", count = endpoints.len()));
    }

    let mut session = ScanSession::new(config);
    let mut all_modules = crate::modules::build_all_modules();

    for plugin_path in &args.plugin {
        let path_str = plugin_path.to_string_lossy();
        match nevelio_core::WasmAttackModule::load(&path_str) {
            Ok(wasm_mod) => {
                if !use_tui {
                    println!(
                        "  {} Plugin WASM chargé : {}",
                        "✓".green(),
                        wasm_mod.name().cyan()
                    );
                }
                all_modules.push(Box::new(wasm_mod));
            }
            Err(e) => eprintln!(
                "  {} Impossible de charger le plugin WASM '{}' : {}",
                "✗".red(),
                path_str,
                e
            ),
        }
    }

    for plugin_path in load_plugin_registry() {
        let path_str = plugin_path.to_string_lossy();
        match nevelio_core::WasmAttackModule::load(&path_str) {
            Ok(wasm_mod) => {
                if !use_tui {
                    println!(
                        "  {} Plugin registry WASM : {}",
                        "✓".green(),
                        wasm_mod.name().cyan()
                    );
                }
                all_modules.push(Box::new(wasm_mod));
            }
            Err(e) => tracing::debug!("Registry plugin '{}' failed: {}", path_str, e),
        }
    }

    let module_names: Vec<String> = all_modules.iter().map(|m| m.name().to_string()).collect();

    let mut completed_modules: Vec<String> = Vec::new();
    if args.resume {
        if let Some(prev) = load_progress(&out_dir) {
            if !use_tui {
                println!(
                    "{}",
                    t!(
                        "scan.resume",
                        count = prev.completed_modules.len(),
                        modules = prev.completed_modules.join(", ").as_str()
                    )
                    .yellow()
                );
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

    let active_modules: Vec<&dyn AttackModule> = all_modules
        .iter()
        .filter(|m| {
            let in_scope = session.config.modules.is_empty()
                || session.config.modules.iter().any(|n| n == m.name());
            let already_done = completed_modules.iter().any(|c| c == m.name());
            in_scope && !already_done
        })
        .map(|m| m.as_ref())
        .collect();

    exec::run_and_report(
        &mut session,
        &http_client,
        &active_modules,
        &endpoints,
        module_names,
        &mut completed_modules,
        cfg_suppress,
        script_paths,
        output_format,
        use_tui,
        ai_suggestions,
        ai_triage,
        ai_remediation,
        ai_report,
        ai_payloads,
        fail_on,
    )
    .await
}
