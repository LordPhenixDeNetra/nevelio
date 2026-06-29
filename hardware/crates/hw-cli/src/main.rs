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

// ── CLI définition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "nevelio-hw",
    version = "0.1.0",
    about   = "Nevelio Hardware Security — audit de sécurité matérielle",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Accepter le disclaimer légal sans prompt interactif
    #[arg(long, global = true)]
    accept_legal: bool,

    /// Mode verbose : affiche les détails de chaque check
    #[arg(long, short, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Lancer un audit hardware
    Scan {
        /// Modules à exécuter (défaut : tous)
        #[arg(long, value_delimiter = ',')]
        modules: Option<Vec<String>>,

        /// Format de sortie
        #[arg(long, default_value = "text")]
        output: OutputFormat,

        /// Chemin du fichier de sortie (défaut : stdout)
        #[arg(long)]
        out_file: Option<String>,

        /// Mode simulation — ne lance pas les checks actifs (flashrom, etc.)
        #[arg(long, default_value_t = true)]
        dry_run: bool,

        /// Exécuter les checks actifs (flashrom, tests mémoire) — annule --dry-run
        #[arg(long, conflicts_with = "dry_run")]
        active: bool,

        /// URL cible pour le module timing side-channel (ex: https://api.example.com)
        #[arg(long)]
        target: Option<String>,
    },
    /// Lister et inspecter les modules disponibles
    Modules {
        #[command(subcommand)]
        action: ModulesAction,
    },
}

#[derive(Subcommand)]
enum ModulesAction {
    /// Lister tous les modules
    List,
    /// Afficher le détail d'un module
    Show { name: String },
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Text,
    Json,
    Html,
}

// ── Point d'entrée ────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

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
            handle_scan(modules, output, out_file, ctx)
        }
    }
}

// ── Scan ──────────────────────────────────────────────────────────────────────

fn handle_scan(
    module_filter: Option<Vec<String>>,
    format:        OutputFormat,
    out_file:      Option<String>,
    ctx:           HwScanContext,
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
        eprintln!(
            "{}  Mode --dry-run actif : les checks destructifs (flashrom, tests mémoire) sont désactivés.",
            "[!]".yellow()
        );
    }
    if let Some(t) = &ctx.target {
        eprintln!("  {}  Cible timing oracle : {}", "→".dimmed(), t.cyan());
    }

    eprintln!();
    eprintln!("  {}  Nevelio Hardware Security v0.1.0", "⚙".cyan());
    eprintln!("  {}  {} module(s) sélectionné(s)\n", "→".dimmed(), modules.len());

    let mut all_findings: Vec<HardwareFinding> = Vec::new();

    for module in &modules {
        if ctx.verbose {
            eprint!("  {}  {}…", "·".dimmed(), module.name());
        }
        let findings = module.run(&ctx);
        if ctx.verbose {
            eprintln!(" {} finding(s)", findings.len());
        }
        all_findings.extend(findings);
    }

    all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let report = HwReport::build(all_findings);

    let rendered = match format {
        OutputFormat::Json => report.to_json(),
        OutputFormat::Text => output::render_text(&report),
        OutputFormat::Html => HwHtmlReporter::generate(&report),
    };

    match out_file {
        Some(path) => {
            std::fs::write(&path, &rendered)?;
            eprintln!("\n  {}  Rapport écrit dans {}", "✓".green(), path.cyan());
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
            println!("\n  {} Modules disponibles :\n", "⚙".cyan());
            for m in &all_modules {
                println!(
                    "  {:20} — {}",
                    m.name().bold(),
                    m.description()
                );
            }
            println!();
        }
        ModulesAction::Show { name } => {
            let found = all_modules.iter().find(|m| m.name().contains(&name));
            match found {
                Some(m) => {
                    println!("\n  {}  {}", "⚙".cyan(), m.name().bold());
                    println!("  {}\n", m.description());
                }
                None => {
                    eprintln!("  {} Module '{}' introuvable.", "✗".red(), name);
                    eprintln!("  Modules disponibles : {}",
                        all_modules.iter().map(|m| m.name()).collect::<Vec<_>>().join(", "));
                }
            }
        }
    }

    Ok(())
}
