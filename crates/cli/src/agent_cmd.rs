use anyhow::Result;
use std::path::PathBuf;

// ── Args ──────────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(about = "Run the autonomous AI security agent on a target API")]
pub struct AgentArgs {
    /// Target API base URL (must start with http:// or https://)
    #[arg(long, value_name = "URL")]
    pub target: String,

    /// Maximum number of LLM reasoning iterations
    #[arg(long, value_name = "N", default_value = "20")]
    pub max_iterations: u32,

    /// Maximum number of outgoing HTTP requests (guardrail G.6)
    #[arg(long, value_name = "N", default_value = "100")]
    pub max_requests: u32,

    /// Token budget ceiling — agent stops cleanly when reached (guardrail G.9)
    #[arg(long, value_name = "TOKENS")]
    pub ai_budget: Option<u32>,

    /// Plan and report without sending real HTTP requests (guardrail G.8)
    #[arg(long)]
    pub dry_run: bool,

    /// Directory where agent findings are saved
    #[arg(long, value_name = "PATH")]
    pub out_dir: Option<PathBuf>,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// Run the autonomous AI agent (requires feature "ai").
#[cfg(feature = "ai")]
pub async fn handle_agent(args: AgentArgs) -> Result<()> {
    use colored::Colorize;
    use nevelio_ai::{build_provider, AgentConfig, CompletionOpts};

    // Validate target URL (G.5 scope only makes sense for http/https)
    if !args.target.starts_with("http://") && !args.target.starts_with("https://") {
        anyhow::bail!("Target must start with http:// or https://");
    }

    // Load global AI config (G.7 — legal was already checked before dispatch)
    let global_cfg = nevelio_config::load_global()
        .map_err(|e| anyhow::anyhow!("Cannot load config: {}. Run: nevelio config init", e))?;

    if !global_cfg.ai.enabled || global_cfg.ai.providers.is_empty() {
        anyhow::bail!("AI is disabled. Run: nevelio config init");
    }

    let provider = build_provider(&global_cfg.ai)?;

    let out_dir = args.out_dir.clone()
        .unwrap_or_else(|| PathBuf::from("./nevelio-results"));
    std::fs::create_dir_all(&out_dir)?;

    let lang = rust_i18n::locale().to_string();

    println!();
    println!("  {} {} — Agent autonome", "◆".cyan(), args.target.bold());
    if args.dry_run {
        println!("  {} dry-run activé (aucune requête HTTP réelle)", "⚠".yellow());
    }
    println!(
        "  {} max {} itérations · {} requêtes",
        "→".dimmed(),
        args.max_iterations,
        args.max_requests
    );
    if let Some(budget) = args.ai_budget {
        println!("  {} budget tokens : {}", "→".dimmed(), budget);
    }
    println!();

    // Endpoint discovery
    println!("{}", "  Découverte des endpoints...".dimmed());
    let endpoints: Vec<String> = if args.dry_run {
        // Minimal mock surface for dry-run
        vec![
            format!("{}/api/users", args.target),
            format!("{}/api/auth/login", args.target),
            format!("{}/api/health", args.target),
        ]
    } else {
        let raw_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Nevelio/0.1")
            .build()?;
        match nevelio_recon::discover_endpoints(&args.target, &raw_client, false).await {
            Ok(eps) => eps.into_iter().map(|e| e.full_url).collect(),
            Err(_)  => {
                println!(
                    "  {} Découverte échouée — l'agent démarre avec la cible uniquement",
                    "⚠".yellow()
                );
                vec![args.target.clone()]
            }
        }
    };
    println!(
        "  {} {} endpoint(s) découvert(s)",
        "✓".green(),
        endpoints.len()
    );
    println!();

    let config = AgentConfig {
        target:         args.target.clone(),
        max_iterations: args.max_iterations,
        max_requests:   args.max_requests,
        ai_budget:      args.ai_budget,
        dry_run:        args.dry_run,
        lang:           lang.clone(),
    };

    let opts = CompletionOpts::default();

    println!("{}", "  Démarrage de l'agent autonome...".cyan());
    println!("{}", "─".repeat(60).dimmed());

    let result = nevelio_ai::run_agent(&config, &endpoints, provider.as_ref(), &opts).await?;

    println!("{}", "─".repeat(60).dimmed());
    println!();
    println!(
        "  {} Agent terminé — {} itération(s) · {} requête(s)",
        "✓".green(),
        result.iterations,
        result.requests_made
    );

    if result.tokens_spent > 0 {
        println!("  {} ~{} tokens consommés", "→".dimmed(), result.tokens_spent);
    }
    println!();

    // Print findings summary
    if result.findings.is_empty() {
        println!("  {} Aucun finding confirmé", "◆".dimmed());
    } else {
        println!(
            "  {} {} finding(s) confirmé(s) :",
            "◆".cyan(),
            result.findings.len()
        );
        println!();
        for f in &result.findings {
            let sev = match f.severity.to_uppercase().as_str() {
                "CRITICAL" => f.severity.red().bold().to_string(),
                "HIGH"     => f.severity.red().to_string(),
                "MEDIUM"   => f.severity.yellow().to_string(),
                "LOW"      => f.severity.blue().to_string(),
                _          => f.severity.dimmed().to_string(),
            };
            println!(
                "  [{}] {} — {} {}",
                sev,
                f.title.bold(),
                f.method,
                f.endpoint
            );
        }

        // Save findings to JSON
        let findings_path = out_dir.join("agent_findings.json");
        let json = serde_json::to_string_pretty(&result.findings)?;
        std::fs::write(&findings_path, &json)?;
        println!();
        println!("  {} {}", "→".cyan(), findings_path.display());
    }

    // Print agent summary
    if !result.summary.is_empty() {
        println!();
        println!("  {}", "Résumé :".bold());
        for line in result.summary.lines() {
            println!("  {}", line.dimmed());
        }
    }

    Ok(())
}

/// Stub when the crate is built without the `ai` feature flag.
#[cfg(not(feature = "ai"))]
pub async fn handle_agent(_args: AgentArgs) -> Result<()> {
    anyhow::bail!(
        "`nevelio agent` requires the `ai` feature. \
         Recompile with: cargo build --features ai"
    )
}
