mod audit;
mod output;
mod disclaimer;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use hw_core::{HardwareFinding, HwHtmlReporter, HwModule, HwReport, HwScanContext};
use hw_cpu::CpuModule;
use hw_dma::DmaModule;
use hw_firmware::FirmwareModule;
use hw_jtag::JtagModule;
use hw_memory::MemoryModule;
use hw_sidechannel::SideChannelModule;

rust_i18n::i18n!("locales", fallback = "fr");
use rust_i18n::t;

// ── CLI définition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "nevelio-hw",
    version = "0.1.0",
    about   = "Nevelio Hardware Security — hardware security audit",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Accept the legal disclaimer without interactive prompt
    #[arg(long, global = true)]
    accept_legal: bool,

    /// Verbose mode: show details for each check
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Language override: fr, en, es (default: auto-detect from NEVELIO_LANG / $LANG)
    #[arg(long, global = true)]
    lang: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Run a hardware audit
    Scan {
        /// Modules to run (default: all)
        #[arg(long, value_delimiter = ',')]
        modules: Option<Vec<String>>,

        /// Output format
        #[arg(long, default_value = "text")]
        output: OutputFormat,

        /// Output file path (default: stdout)
        #[arg(long)]
        out_file: Option<String>,

        /// Simulation mode — skip destructive active checks (flashrom, etc.)
        #[arg(long, default_value_t = true)]
        dry_run: bool,

        /// Run active checks (flashrom, memory tests) — overrides --dry-run
        #[arg(long, conflicts_with = "dry_run")]
        active: bool,

        /// Target URL for the timing side-channel module (e.g. https://api.example.com)
        #[arg(long)]
        target: Option<String>,
    },
    /// List and inspect available modules
    Modules {
        #[command(subcommand)]
        action: ModulesAction,
    },
}

#[derive(Subcommand)]
enum ModulesAction {
    /// List all modules
    List,
    /// Show details of a module
    Show { name: String },
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Text,
    Json,
    /// JSON compatible with the main Nevelio report format
    NevelioJson,
    Html,
}

// ── Point d'entrée ────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    let lang = cli.lang.as_deref()
        .map(detect_lang_from_str)
        .unwrap_or_else(detect_lang_from_env);
    rust_i18n::set_locale(lang);

    match cli.command {
        Command::Modules { action } => handle_modules(action),

        Command::Scan { modules, output, out_file, dry_run, active, target } => {
            if !cli.accept_legal {
                disclaimer::show_and_confirm()?;
            }
            let ctx = HwScanContext {
                dry_run: dry_run && !active,
                target,
                verbose: cli.verbose,
            };
            handle_scan(modules, output, out_file, ctx, cli.verbose)
        }
    }
}

fn detect_lang_from_str(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "en" | "english" => "en",
        "es" | "spanish" | "español" => "es",
        _ => "fr",
    }
}

fn detect_lang_from_env() -> &'static str {
    if let Ok(l) = std::env::var("NEVELIO_LANG") {
        return detect_lang_from_str(&l);
    }
    if let Ok(l) = std::env::var("LANG") {
        if l.starts_with("en") { return "en"; }
        if l.starts_with("es") { return "es"; }
    }
    "fr"
}

// ── Scan ──────────────────────────────────────────────────────────────────────

fn handle_scan(
    module_filter: Option<Vec<String>>,
    format:        OutputFormat,
    out_file:      Option<String>,
    ctx:           HwScanContext,
    verbose:       bool,
) -> Result<()> {
    let all_modules: Vec<Box<dyn HwModule>> = vec![
        Box::new(CpuModule),
        Box::new(FirmwareModule),
        Box::new(DmaModule),
        Box::new(SideChannelModule),
        Box::new(JtagModule),
        Box::new(MemoryModule),
    ];

    let modules: Vec<&Box<dyn HwModule>> = match &module_filter {
        None => all_modules.iter().collect(),
        Some(filter) => all_modules.iter()
            .filter(|m| filter.iter().any(|f| m.name().contains(f.as_str())))
            .collect(),
    };

    if ctx.dry_run {
        eprintln!("{}  {}", "[!]".yellow(), t!("cli.dry_run_warning"));
    }
    if let Some(t) = &ctx.target {
        eprintln!("  {}  {} : {}", "→".dimmed(), t!("cli.target_label"), t.cyan());
    }

    eprintln!();
    eprintln!("  {}  {}", "⚙".cyan(), t!("cli.banner"));
    eprintln!("  {}  {} {}\n", "→".dimmed(), modules.len(), t!("cli.modules_selected"));

    let log_path = audit::default_log_path();
    let mut auditor = audit::AuditLogger::new(&log_path);

    let mut all_findings: Vec<HardwareFinding> = Vec::new();

    for module in &modules {
        if verbose {
            eprint!("  {}  {}…", "·".dimmed(), module.name());
        }
        let t0 = std::time::Instant::now();
        let findings = module.run(&ctx);
        let elapsed  = t0.elapsed().as_millis() as u64;

        let max_sev = findings.iter()
            .map(|f| f.severity.to_string())
            .max_by_key(|s| match s.as_str() {
                "CRITICAL" => 4,
                "HIGH"     => 3,
                "MEDIUM"   => 2,
                "LOW"      => 1,
                _          => 0,
            })
            .unwrap_or_else(|| "NONE".into());

        if verbose {
            eprintln!(" {}", t!("cli.findings_elapsed", elapsed = elapsed.to_string(), count = findings.len().to_string()));
        }

        auditor.record(
            format!("module:{}", module.name()),
            findings.len(),
            &max_sev,
            elapsed,
        );

        all_findings.extend(findings);
    }

    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let report = HwReport::build(all_findings);

    auditor.record(
        format!("scan:complete dry_run={}", ctx.dry_run),
        report.summary.total,
        if report.summary.critical > 0 { "CRITICAL" }
        else if report.summary.high > 0 { "HIGH" }
        else { "INFORMATIVE" },
        0,
    );

    if let Err(e) = auditor.save() {
        eprintln!("  {}  {} : {}", "!".yellow(), t!("cli.audit_save_error"), e);
    } else if verbose {
        eprintln!("  {}  {} : {}", "✓".green(), t!("cli.audit_saved"), log_path.cyan());
    }

    let rendered = match format {
        OutputFormat::Json        => report.to_json(),
        OutputFormat::NevelioJson => report.to_nevelio_json(),
        OutputFormat::Text        => output::render_text(&report),
        OutputFormat::Html        => HwHtmlReporter::generate(&report),
    };

    match out_file {
        Some(path) => {
            std::fs::write(&path, &rendered)?;
            eprintln!("\n  {}  {} {}", "✓".green(), t!("cli.report_written"), path.cyan());
        }
        None => println!("{}", rendered),
    }

    Ok(())
}

// ── Modules ───────────────────────────────────────────────────────────────────

fn handle_modules(action: ModulesAction) -> Result<()> {
    let all_modules: Vec<Box<dyn HwModule>> = vec![
        Box::new(CpuModule),
        Box::new(FirmwareModule),
        Box::new(DmaModule),
        Box::new(SideChannelModule),
        Box::new(JtagModule),
        Box::new(MemoryModule),
    ];

    match action {
        ModulesAction::List => {
            println!("\n  {} {} :\n", "⚙".cyan(), t!("cli.modules_available"));
            for m in &all_modules {
                println!("  {:20} — {}", m.name().bold(), m.description());
            }
            println!();
        }
        ModulesAction::Show { name } => {
            match all_modules.iter().find(|m| m.name().contains(&name)) {
                Some(m) => {
                    println!("\n  {}  {}", "⚙".cyan(), m.name().bold());
                    println!("  {}\n", m.description());
                }
                None => {
                    eprintln!("  {}  {}", "✗".red(), t!("cli.module_not_found", name = name));
                    eprintln!("  {} : {}",
                        t!("cli.modules_list_hint"),
                        all_modules.iter().map(|m| m.name()).collect::<Vec<_>>().join(", "));
                }
            }
        }
    }

    Ok(())
}
