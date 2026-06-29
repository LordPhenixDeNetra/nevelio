use anyhow::{bail, Result};
use colored::Colorize;
use std::io::{self, BufRead, Write};

pub fn show_and_confirm() -> Result<()> {
    println!();
    println!("  {} ╔══════════════════════════════════════════════════════════╗", " ".dimmed());
    println!("  {} ║  AVERTISSEMENT LÉGAL — Nevelio Hardware Security         ║", " ".dimmed());
    println!("  {} ╚══════════════════════════════════════════════════════════╝", " ".dimmed());
    println!();
    println!(
        "  Cet outil effectue des tests de sécurité {} sur le\n  hardware et le firmware du système local.",
        "actifs".bold()
    );
    println!();
    println!("  {} Utilisation autorisée uniquement :", "⚠".yellow().bold());
    println!("    • Sur du matériel dont vous êtes propriétaire");
    println!("    • Avec une autorisation écrite explicite (contrat de pentest)");
    println!("    • Dans un environnement de laboratoire isolé");
    println!();
    println!("  {} Cadre légal :", "⚠".yellow());
    println!("    • France  : Articles 323-1 à 323-8 du Code Pénal");
    println!("    • UE      : Directive NIS2 + RGPD");
    println!("    • USA     : Computer Fraud and Abuse Act (CFAA)");
    println!();
    println!(
        "  Tapez {} pour continuer ou {} pour annuler :",
        "oui".green().bold(),
        "Ctrl+C".red()
    );
    print!("  > ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;

    if line.trim().to_lowercase() != "oui" {
        bail!("Disclaimer non accepté — abandon.");
    }

    println!();
    Ok(())
}
