use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rust_i18n::t;
use std::path::Path;

use nevelio_core::types::{Endpoint, Finding};
use nevelio_core::{AttackModule, HttpClient, ScanSession};
use nevelio_reporting::{JsonReporter, ReportFormat};

use crate::args::{FailOnArg, OutputFormat};
use crate::config::SuppressRule;
use crate::tui::{self, ScanEvent};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_and_report(
    session:        &mut ScanSession,
    http_client:    &HttpClient,
    active_modules: &[&Box<dyn AttackModule>],
    endpoints:      &[Endpoint],
    module_names:   Vec<String>,
    completed_modules: &mut Vec<String>,
    cfg_suppress:   Vec<SuppressRule>,
    script_paths:   Vec<String>,
    output_format:  OutputFormat,
    use_tui:        bool,
    ai_suggestions: bool,
    ai_triage:      bool,
    ai_remediation: bool,
    ai_report:      bool,
    fail_on:        Option<FailOnArg>,
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

    // ── Phase 3 AI features ─────────────────────────────────────────────────
    #[cfg(feature = "ai")]
    if (ai_triage || ai_remediation || ai_report) && !session.findings.is_empty() {
        run_ai_features(
            &session.findings,
            &session.config.target,
            &session.config.locale,
            &out_dir,
            ai_triage,
            ai_remediation,
            ai_report,
        ).await;
    }
    // suppress unused-variable warnings when feature = "ai" is off
    let _ = (ai_triage, ai_remediation, ai_report);

    let exit_code = crate::commands::resolve_exit_code(&session.findings, fail_on);
    std::process::exit(exit_code);
}

// ── AI Phase 3 helper (compiled only when feature = "ai") ────────────────────

#[cfg(feature = "ai")]
async fn run_ai_features(
    findings:      &[Finding],
    target:        &str,
    lang:          &str,
    out_dir:       &Path,
    ai_triage:     bool,
    ai_remediation: bool,
    ai_report:     bool,
) {
    use colored::Colorize;
    use nevelio_ai::{build_provider, CompletionOpts, FindingContext};

    // Convert CLI findings to nevelio-ai FindingContext
    let contexts: Vec<FindingContext> = findings.iter().map(|f| FindingContext {
        id:             f.id.clone(),
        title:          f.title.clone(),
        severity:       f.severity.to_string(),
        module:         f.module.clone(),
        endpoint:       f.endpoint.clone(),
        method:         f.method.clone(),
        description:    f.description.clone(),
        recommendation: f.recommendation.clone(),
        proof:          f.proof.clone(),
    }).collect();

    // Load provider from global config
    let global_cfg = match nevelio_config::load_global() {
        Ok(c)  => c,
        Err(e) => { eprintln!("  {} Config IA : {}", "✗".red(), e); return; }
    };

    if !global_cfg.ai.enabled || global_cfg.ai.providers.is_empty() {
        eprintln!("  {} IA désactivée. Lancez : nevelio config init", "⚠".yellow());
        return;
    }

    let provider = match build_provider(&global_cfg.ai) {
        Ok(p)  => p,
        Err(e) => { eprintln!("  {} Provider IA : {}", "✗".red(), e); return; }
    };

    let opts = CompletionOpts::default();

    // ── Triage ────────────────────────────────────────────────────────────────
    if ai_triage {
        println!();
        println!("{}", "  IA · Triage des findings...".cyan());
        match nevelio_ai::triage::classify_findings(&contexts, lang, provider.as_ref(), &opts).await {
            Err(e) => eprintln!("  {} Triage : {}", "✗".red(), e),
            Ok(results) => {
                // Print triage table
                println!("  {:<8} {:<20} {:>4}  {}", "Verdict", "Titre", "Conf", "Raison");
                println!("  {}", "─".repeat(72));
                for r in &results {
                    let f = findings.iter().find(|f| f.id == r.id);
                    let title = f.map(|f| f.title.as_str()).unwrap_or("?");
                    let title_trunc = if title.len() > 20 { &title[..18] } else { title };
                    let verdict_label = r.verdict.label(lang);
                    let verdict_colored = match r.verdict {
                        nevelio_ai::triage::Verdict::TruePositive  => verdict_label.red().to_string(),
                        nevelio_ai::triage::Verdict::FalsePositive => verdict_label.green().to_string(),
                        nevelio_ai::triage::Verdict::Uncertain      => verdict_label.yellow().to_string(),
                    };
                    let reason_trunc = if r.reason.len() > 38 {
                        format!("{}...", &r.reason[..35])
                    } else {
                        r.reason.clone()
                    };
                    println!("  {:<8} {:<20} {:>3}%  {}", verdict_colored, title_trunc, r.confidence, reason_trunc);
                }
                // Save JSON
                let path = out_dir.join("ai_triage.json");
                if let Ok(json) = serde_json::to_string_pretty(&results) {
                    let _ = std::fs::write(&path, json);
                    println!("  {} ai_triage.json", "→".cyan());
                }
            }
        }
    }

    // ── Remediation ───────────────────────────────────────────────────────────
    if ai_remediation {
        println!();
        println!("{}", "  IA · Génération des remédiations...".cyan());
        match nevelio_ai::remediation::suggest(&contexts, lang, provider.as_ref(), &opts).await {
            Err(e) => eprintln!("  {} Remédiation : {}", "✗".red(), e),
            Ok(results) => {
                let path = out_dir.join("ai_remediation.md");
                let mut md = format!(
                    "# Remédiations IA — Nevelio\n\n> Provider : {} · Modèle : {}\n\n---\n\n",
                    provider.name(), provider.model()
                );
                for r in &results {
                    let f = findings.iter().find(|f| f.id == r.id);
                    let title = f.map(|f| f.title.as_str()).unwrap_or(&r.id);
                    let priority_label = r.priority.label(lang);
                    md.push_str(&format!("## {}\n\n", title));
                    md.push_str(&format!("**Priorité** : {}  \n\n", priority_label));
                    md.push_str(&format!("{}\n\n", r.explanation));
                    md.push_str("**Étapes** :\n\n");
                    for (i, step) in r.steps.iter().enumerate() {
                        md.push_str(&format!("{}. {}\n", i + 1, step));
                    }
                    if let Some(ref code) = r.code_example {
                        md.push_str(&format!("\n```\n{}\n```\n", code));
                    }
                    md.push_str("\n---\n\n");
                }
                let _ = std::fs::write(&path, &md);
                println!("  {} ai_remediation.md", "→".cyan());
            }
        }
    }

    // ── Narrative report ──────────────────────────────────────────────────────
    if ai_report {
        println!();
        println!("{}", "  IA · Génération du rapport narratif...".cyan());
        let mut report_opts = opts.clone();
        report_opts.max_tokens = 8192;
        match nevelio_ai::report::narrative(&contexts, target, lang, provider.as_ref(), &report_opts).await {
            Err(e) => eprintln!("  {} Rapport narratif : {}", "✗".red(), e),
            Ok(content) => {
                use chrono::Utc;
                let header = format!(
                    "# Rapport Narratif — Nevelio\n\n> Cible : {}  \n> Généré le {}  \n> Provider : {} · Modèle : {}\n\n---\n\n",
                    target,
                    Utc::now().format("%Y-%m-%d %H:%M UTC"),
                    provider.name(),
                    provider.model()
                );
                let path = out_dir.join("ai_narrative_report.md");
                let _ = std::fs::write(&path, format!("{}{}", header, content));
                println!("  {} ai_narrative_report.md", "→".cyan());
            }
        }
    }
}
