use anyhow::Result;
use colored::Colorize;
use rust_i18n::t;

use nevelio_config::{
    global_config_exists, global_config_path, load_global, save_global, GlobalConfig,
};

// ── Subcommand args ───────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Debug, clap::Subcommand)]
pub enum ConfigAction {
    /// Assistant interactif de configuration initiale
    Init,
    /// Affiche la configuration résolue
    Show,
    /// Lit une valeur de configuration
    Get { key: String },
    /// Modifie une valeur de configuration
    Set { key: String, value: String },
    /// Ouvre la config dans $EDITOR
    Edit,
    /// Remet la configuration aux valeurs par défaut
    Reset,
    /// Teste les providers IA configurés
    #[command(name = "ai")]
    Ai {
        #[command(subcommand)]
        action: AiAction,
    },
}

#[derive(Debug, clap::Subcommand)]
pub enum AiAction {
    /// Teste la connexion à tous les providers configurés
    Ping {
        /// Tester un provider spécifique
        provider: Option<String>,
    },
    /// Liste tous les providers disponibles et leur statut de configuration
    Providers,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn handle_config(args: ConfigArgs) -> Result<()> {
    match args.action {
        ConfigAction::Init          => cmd_init(),
        ConfigAction::Show          => cmd_show(),
        ConfigAction::Get { key }   => cmd_get(&key),
        ConfigAction::Set { key, value } => cmd_set(&key, &value),
        ConfigAction::Edit          => cmd_edit(),
        ConfigAction::Reset         => cmd_reset(),
        ConfigAction::Ai { action } => match action {
            AiAction::Ping { provider } => cmd_ai_ping(provider.as_deref()),
            AiAction::Providers         => cmd_ai_providers(),
        },
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

fn cmd_init() -> Result<()> {
    println!("{}", t!("config.init.welcome").bold());
    println!("{}", t!("config.init.separator"));

    if global_config_exists() {
        let path = global_config_path().unwrap_or_default();
        println!(
            "{}",
            t!("config.init.already_exists", path = path.display().to_string())
        );
        print!("{} ", t!("config.init.overwrite"));
        if !confirm_yes() {
            println!("{}", t!("config.init.skipped"));
            return Ok(());
        }
    }

    let mut cfg = GlobalConfig::default();

    // Name
    print!("{}: ", t!("config.init.name"));
    cfg.user.name = read_line_optional();

    // Language
    print!("{} [fr]: ", t!("config.init.lang"));
    let lang = read_line_optional().unwrap_or_else(|| "fr".to_string());
    cfg.scan.lang = if ["fr", "en", "es"].contains(&lang.as_str()) {
        lang
    } else {
        "fr".to_string()
    };

    // AI
    print!("{} ", t!("config.init.ai_enable"));
    cfg.ai.enabled = confirm_yes();

    if cfg.ai.enabled {
        println!("  {} : {}", t!("config.init.provider"), t!("config.init.providers_list"));
        print!("  [anthropic]: ");
        let prov = read_line_optional().unwrap_or_else(|| "anthropic".to_string());
        cfg.ai.provider = Some(prov.clone());

        // Key env var
        let default_env = default_key_env(&prov);
        print!("  {} [{}]: ", t!("config.init.key_env"), default_env);
        let env_var = read_line_optional().unwrap_or_else(|| default_env.to_string());

        if std::env::var(&env_var).is_ok() {
            println!("  {}", t!("config.init.key_found").green());
        } else {
            println!("  {}", t!("config.init.key_miss").yellow());
        }

        // Store provider config
        let provider_cfg = nevelio_config::ProviderConfig {
            model:       default_model(&prov).to_string(),
            api_key_env: Some(env_var),
            ..Default::default()
        };
        cfg.ai.providers.insert(prov, provider_cfg);
    }

    // Scan profile
    print!("{} [standard]: ", t!("config.init.profile"));
    let profile = read_line_optional().unwrap_or_else(|| "standard".to_string());
    cfg.scan.profile = Some(profile);

    // Write
    save_global(&cfg)?;

    let path = global_config_path().unwrap_or_default();
    println!(
        "\n{}",
        t!("config.init.done", path = path.display().to_string()).green()
    );

    Ok(())
}

// ── show ─────────────────────────────────────────────────────────────────────

fn cmd_show() -> Result<()> {
    let cfg = load_global()?;

    println!("{}", t!("config.cmd.show_title").bold().underline());
    println!();

    if let Some(path) = global_config_path() {
        let label = t!("config.cmd.show_global", path = path.display().to_string());
        println!("{}", label.dimmed());
    }

    println!();
    println!("[user]");
    println!("  name  = {:?}", cfg.user.name.as_deref().unwrap_or(""));
    println!("  email = {:?}", cfg.user.email.as_deref().unwrap_or(""));

    println!();
    println!("[ai]");
    println!("  enabled  = {}", cfg.ai.enabled);
    println!("  provider = {:?}", cfg.ai.active_provider_name());
    for (name, prov) in &cfg.ai.providers {
        println!("  [ai.providers.{}]", name);
        println!("    model       = {:?}", prov.model);
        println!("    api_key_env = {:?}", prov.api_key_env.as_deref().unwrap_or(""));
    }

    println!();
    println!("[scan]");
    println!("  lang         = {:?}", cfg.scan.lang);
    println!("  profile      = {:?}", cfg.scan.profile.as_deref().unwrap_or("standard"));
    println!("  dry_run      = {}", cfg.scan.dry_run);
    println!("  timeout_secs = {}", cfg.scan.timeout_secs);
    println!("  concurrency  = {}", cfg.scan.concurrency);

    Ok(())
}

// ── get ──────────────────────────────────────────────────────────────────────

fn cmd_get(key: &str) -> Result<()> {
    let cfg = load_global()?;

    let value = match key {
        "ai.enabled"      => Some(cfg.ai.enabled.to_string()),
        "ai.provider"     => cfg.ai.provider.clone(),
        "scan.lang"       => Some(cfg.scan.lang.clone()),
        "scan.profile"    => cfg.scan.profile.clone(),
        "scan.dry_run"    => Some(cfg.scan.dry_run.to_string()),
        "scan.timeout_secs" => Some(cfg.scan.timeout_secs.to_string()),
        "scan.concurrency"  => Some(cfg.scan.concurrency.to_string()),
        "user.name"       => cfg.user.name.clone(),
        "user.email"      => cfg.user.email.clone(),
        "output.format"   => Some(cfg.output.format.clone()),
        "output.colorize" => Some(cfg.output.colorize.to_string()),
        _ => None,
    };

    match value {
        Some(v) => println!("{}", v),
        None    => {
            eprintln!("{}", t!("config.cmd.get_miss", key = key).red());
            std::process::exit(1);
        }
    }
    Ok(())
}

// ── set ──────────────────────────────────────────────────────────────────────

fn cmd_set(key: &str, value: &str) -> Result<()> {
    let mut cfg = load_global()?;

    let ok = match key {
        "ai.enabled"       => { cfg.ai.enabled = value == "true" || value == "oui" || value == "yes"; true }
        "ai.provider"      => { cfg.ai.provider = Some(value.to_string()); true }
        "scan.lang"        => { cfg.scan.lang = value.to_string(); true }
        "scan.profile"     => { cfg.scan.profile = Some(value.to_string()); true }
        "scan.dry_run"     => { cfg.scan.dry_run = value == "true"; true }
        "scan.timeout_secs"=> { cfg.scan.timeout_secs = value.parse().unwrap_or(30); true }
        "scan.concurrency" => { cfg.scan.concurrency  = value.parse().unwrap_or(10); true }
        "user.name"        => { cfg.user.name = Some(value.to_string()); true }
        "user.email"       => { cfg.user.email = Some(value.to_string()); true }
        "output.format"    => { cfg.output.format   = value.to_string(); true }
        "output.colorize"  => { cfg.output.colorize = value == "true"; true }
        _ => false,
    };

    if !ok {
        eprintln!("{}", t!("config.cmd.get_miss", key = key).red());
        std::process::exit(1);
    }

    save_global(&cfg)?;
    println!("{}", t!("config.cmd.set_ok", key = key, value = value).green());
    Ok(())
}

// ── edit ─────────────────────────────────────────────────────────────────────

fn cmd_edit() -> Result<()> {
    let path = global_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    // Ensure the file exists
    if !global_config_exists() {
        save_global(&GlobalConfig::default())?;
    }

    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "nano".to_string());

    println!("{}", t!("config.cmd.edit_open", path = &path, editor = &editor));

    std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .ok();

    Ok(())
}

// ── reset ─────────────────────────────────────────────────────────────────────

fn cmd_reset() -> Result<()> {
    print!("{} ", t!("config.cmd.reset_confirm"));
    if !confirm_yes() {
        println!("{}", t!("config.cmd.reset_skip"));
        return Ok(());
    }
    save_global(&GlobalConfig::default())?;
    println!("{}", t!("config.cmd.reset_ok").green());
    Ok(())
}

// ── ai ping ──────────────────────────────────────────────────────────────────

fn cmd_ai_ping(provider_filter: Option<&str>) -> Result<()> {
    let cfg = load_global()?;

    if cfg.ai.providers.is_empty() {
        println!("{}", t!("config.ai.no_providers").yellow());
        return Ok(());
    }

    println!("{}", t!("config.ai.ping_title").bold());
    println!();

    for (name, prov) in &cfg.ai.providers {
        if let Some(filter) = provider_filter {
            if name != filter {
                continue;
            }
        }

        // Check API key
        let has_key = prov.api_key_env
            .as_deref()
            .map(|env| std::env::var(env).is_ok())
            .unwrap_or(true); // Ollama / local providers have no key

        if !has_key {
            let env = prov.api_key_env.as_deref().unwrap_or("");
            println!("{}", t!("config.ai.ping_no_key", provider = name, env = env).yellow());
            continue;
        }

        // Minimal HTTP connectivity check
        let start = std::time::Instant::now();
        let reachable = ping_provider(name, prov);
        let ms = start.elapsed().as_millis();

        if reachable {
            let key = if name == "ollama" || prov.base_url.is_some() {
                "config.ai.ping_local"
            } else {
                "config.ai.ping_ok"
            };
            println!("{}", t!(key, provider = name, ms = ms.to_string(), model = &prov.model).green());
        } else {
            println!("{}", t!("config.ai.ping_fail", provider = name, error = "connexion refusée").red());
        }
    }

    Ok(())
}

// ── ai providers (A.14) ──────────────────────────────────────────────────────

fn cmd_ai_providers() -> Result<()> {
    const KNOWN: &[(&str, &str, &str)] = &[
        ("anthropic", "ANTHROPIC_API_KEY", "https://api.anthropic.com"),
        ("openai",    "OPENAI_API_KEY",    "https://api.openai.com"),
        ("mistral",   "MISTRAL_API_KEY",   "https://api.mistral.ai"),
        ("groq",      "GROQ_API_KEY",      "https://api.groq.com"),
        ("ollama",    "",                  "http://localhost:11434"),
    ];

    let cfg = load_global().unwrap_or_default();
    let active = cfg.ai.active_provider_name().to_string();

    println!();
    println!("{}", "  Providers IA disponibles".bold());
    println!("  {}", "─".repeat(68));
    println!(
        "  {:<12} {:<12} {:<14} {:<24} Statut",
        "Provider", "Configuré", "Clé API", "Modèle"
    );
    println!("  {}", "─".repeat(68));

    for &(name, key_env, _base_url) in KNOWN {
        let prov_cfg = cfg.ai.providers.get(name);
        let configured = prov_cfg.is_some();

        let (_key_status, key_colored) = if name == "ollama" {
            ("N/A (local)", "N/A (local)".dimmed().to_string())
        } else if let Some(prov) = prov_cfg {
            let env = prov.api_key_env.as_deref().unwrap_or(key_env);
            if std::env::var(env).is_ok() {
                ("présente", format!("{} ({})", "✓".green(), env))
            } else {
                ("absente", format!("{} ({})", "✗".red(), env))
            }
        } else {
            let set = std::env::var(key_env).is_ok();
            if set {
                ("présente", format!("{} ({})", "●".yellow(), key_env))
            } else {
                ("non définie", "—".dimmed().to_string())
            }
        };

        let model_str = prov_cfg
            .map(|p| if p.model.is_empty() { "—".to_string() } else { p.model.clone() })
            .unwrap_or_else(|| "—".to_string());

        let status = if name == active && configured {
            "← ACTIF".cyan().bold().to_string()
        } else if !configured {
            "non configuré".dimmed().to_string()
        } else {
            "configuré".green().to_string()
        };

        let configured_str = if configured {
            "✓".green().to_string()
        } else {
            "✗".dimmed().to_string()
        };

        println!(
            "  {:<12} {:<12} {:<26} {:<24} {}",
            name,
            configured_str,
            key_colored,
            model_str,
            status,
        );
    }

    // ── Routing config ────────────────────────────────────────────────────────
    println!();
    println!("  {}", "Routing (ai.routing.*)".bold());
    println!("  {}", "─".repeat(40));

    let routing = &cfg.ai.routing;
    let fmt = |opt: &Option<String>| opt.as_deref().unwrap_or("(actif par défaut)").to_string();

    println!("  {:<14} {}", "Triage :", fmt(&routing.triage));
    println!("  {:<14} {}", "Rapport :", fmt(&routing.report));
    println!("  {:<14} {}", "Payloads :", fmt(&routing.payloads));
    println!(
        "  {:<14} {}",
        "Fallback :",
        routing.fallback.as_deref().unwrap_or("(non configuré)").yellow()
    );

    println!();
    println!("  {}", "Configurez via : nevelio config set ai.routing.triage groq".dimmed());

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn ping_provider(name: &str, prov: &nevelio_config::ProviderConfig) -> bool {
    let url = match name {
        "anthropic" => "https://api.anthropic.com",
        "openai"    => "https://api.openai.com",
        "mistral"   => "https://api.mistral.ai",
        "groq"      => "https://api.groq.com",
        "ollama"    => prov.base_url.as_deref().unwrap_or("http://localhost:11434"),
        _           => return false,
    };

    // Simple TCP connect check (no HTTP request, no tokens consumed)
    use std::net::{TcpStream, ToSocketAddrs};
    let host_port = if let Some(rest) = url.strip_prefix("https://") {
        format!("{rest}:443")
    } else {
        format!("{}:80", url.trim_start_matches("http://"))
    };

    // Resolve hostname via DNS, then attempt TCP connection
    let Ok(mut addrs) = host_port.to_socket_addrs() else { return false };
    let Some(addr) = addrs.next()                   else { return false };
    TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3)).is_ok()
}

fn default_key_env(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openai"    => "OPENAI_API_KEY",
        "mistral"   => "MISTRAL_API_KEY",
        "groq"      => "GROQ_API_KEY",
        "bedrock"   => "AWS_ACCESS_KEY_ID",
        _           => "API_KEY",
    }
}

fn default_model(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "claude-sonnet-4-6",
        "openai"    => "gpt-4o",
        "mistral"   => "mistral-large-latest",
        "groq"      => "llama-3.1-70b-versatile",
        "ollama"    => "llama3.2",
        "bedrock"   => "anthropic.claude-3-5-sonnet-20241022-v2:0",
        _           => "unknown",
    }
}

fn read_line_optional() -> Option<String> {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let line = stdin.lock().lines().next()?.ok()?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

fn confirm_yes() -> bool {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    if let Some(Ok(line)) = stdin.lock().lines().next() {
        let s = line.trim().to_lowercase();
        matches!(s.as_str(), "o" | "oui" | "y" | "yes" | "sí" | "si")
    } else {
        false
    }
}
