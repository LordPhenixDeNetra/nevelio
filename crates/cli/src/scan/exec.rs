use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rust_i18n::t;

use nevelio_core::types::Endpoint;
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_reporting::{JsonReporter, ReportFormat};

use crate::args::{FailOnArg, OutputFormat};
use crate::config::SuppressRule;
use crate::tui::{self, ScanEvent};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_and_report(
    session: &mut ScanSession,
    http_client: &HttpClient,
    active_modules: &[&Box<dyn AttackModule>],
    endpoints: &[Endpoint],
    module_names: Vec<String>,
    completed_modules: &mut Vec<String>,
    cfg_suppress: Vec<SuppressRule>,
    script_paths: Vec<String>,
    output_format: OutputFormat,
    use_tui: bool,
    ai_suggestions: bool,
    fail_on: Option<FailOnArg>,
) -> Result<()> {
    let out_dir = session.config.out_dir.clone();

    let tui_tx: Option<mpsc::Sender<ScanEvent>> = if use_tui {
        let (tx, rx) = mpsc::channel();
        let names = module_names;
        std::thread::spawn(move || {
            if let Err(e) = tui::run_tui_blocking(rx, names) {
                eprintln!("{}", t!("error.tui", msg = e.to_string().as_str()));
            }
        });
        let _ = tx.send(ScanEvent::EndpointScanned { total: endpoints.len(), done: 0 });
        Some(tx)
    } else {
        None
    };

    let pb: Option<ProgressBar> = if !use_tui {
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
        if tui_tx.is_some() {
            for module in active_modules {
                tracing::info!("Running module: {}", module.name());
                if let Some(ref tx) = tui_tx {
                    let _ = tx.send(ScanEvent::ModuleStarted { name: module.name().to_string() });
                }
                let findings = module.run(session, http_client, endpoints).await;
                for f in findings {
                    if let Some(ref tx) = tui_tx {
                        let _ = tx.send(ScanEvent::FindingFound(Box::new(f.clone())));
                    }
                    session.add_finding(f);
                }
                completed_modules.push(module.name().to_string());
                if let Some(ref tx) = tui_tx {
                    let _ = tx.send(ScanEvent::ModuleFinished { name: module.name().to_string() });
                }
                super::save_progress(&out_dir, completed_modules, &session.config.target);
                let checkpoint = JsonReporter::generate(session);
                let _ = JsonReporter::write_to_file(&checkpoint, &out_dir.join("findings.json"));
            }
        } else {
            tracing::info!("Running {} modules in parallel", active_modules.len());
            let futures: Vec<_> = active_modules
                .iter()
                .map(|m| m.run(session, http_client, endpoints))
                .collect();

            let all_results = futures_util::future::join_all(futures).await;

            for (module, findings) in active_modules.iter().zip(all_results) {
                for f in findings {
                    crate::output::print_finding(&f);
                    session.add_finding(f);
                }
                completed_modules.push(module.name().to_string());
            }
            super::save_progress(&out_dir, completed_modules, &session.config.target);
            let checkpoint = JsonReporter::generate(session);
            let _ = JsonReporter::write_to_file(&checkpoint, &out_dir.join("findings.json"));
        }
    }

    for (i, _) in endpoints.iter().enumerate() {
        if let Some(ref tx) = tui_tx {
            let _ = tx.send(ScanEvent::EndpointScanned { total: endpoints.len(), done: i + 1 });
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
    if let Some(ref bar) = pb {
        bar.finish_with_message(t!("scan.finished").to_string());
    }

    let before_count = session.findings.len();
    if !cfg_suppress.is_empty() {
        session.findings.retain(|f| !cfg_suppress.iter().any(|r| r.matches(f)));
    }
    if !script_paths.is_empty() {
        match crate::script::ScriptRunner::load(&script_paths) {
            Ok(runner) => { session.findings = runner.filter_findings(&session.findings); }
            Err(e) => eprintln!("  {}: {}", "Erreur chargement scripts".red(), e),
        }
    }
    let suppressed = before_count.saturating_sub(session.findings.len());
    if suppressed > 0 {
        println!("  {} {} finding(s) supprimé(s) (règles + scripts).", "↩".yellow(), suppressed);
    }

    session.finish();

    let report = JsonReporter::generate(session);
    let json_path = out_dir.join("findings.json");
    JsonReporter::write_to_file(&report, &json_path)
        .context(t!("error.json_write").to_string())?;

    let report_format: ReportFormat = output_format.into();
    let report_path = if matches!(report_format, ReportFormat::Json) {
        json_path
    } else {
        crate::commands::write_report(&report, &report_format, &out_dir)?
    };

    if use_tui {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    println!();
    crate::output::print_summary(&session.findings);
    println!("{:<12}: {}", t!("scan.report_label"), report_path.display().to_string().cyan());

    if ai_suggestions {
        println!();
        println!("{}", t!("scan.ai_generating").cyan());
        match crate::ai_suggestions::generate_and_save(&session.findings, &out_dir).await {
            Ok(()) => {}
            Err(e) => eprintln!("{}", t!("scan.ai_saved", path = e.to_string().as_str()).yellow()),
        }
    }

    let exit_code = crate::commands::resolve_exit_code(&session.findings, fail_on);
    std::process::exit(exit_code);
}
