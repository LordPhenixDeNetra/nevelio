use chrono::Utc;
use colored::Colorize;
use std::io::{self, Write};
use std::path::PathBuf;

const LEGAL_TEXT: &str = "
\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}
                  AVERTISSEMENT LEGAL
\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}
Nevelio est un outil de pentest d'API conçu EXCLUSIVEMENT
pour des systèmes que vous possédez ou sur lesquels vous
avez une autorisation écrite explicite.

Utiliser cet outil sans autorisation est ILLEGAL dans la
plupart des juridictions (CFAA, Directive UE sur les
attaques informatiques, Sénégal Loi n° 2008-11).

En continuant, vous confirmez que :
  1. Vous avez une autorisation explicite pour tester la cible.
  2. Vous acceptez l'entière responsabilité légale de vos actes.
  3. Vous traiterez toutes les découvertes comme confidentielles.
\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}";

fn marker_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|h| {
        PathBuf::from(h)
            .join(".config")
            .join("nevelio")
            .join("legal_accepted")
    })
}

fn is_already_accepted() -> bool {
    marker_path().is_some_and(|p| p.exists())
}

fn persist_acceptance() {
    if let Some(path) = marker_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, Utc::now().to_rfc3339());
    }
}

/// Persist acceptance when `--accept-legal` is passed on the CLI.
pub fn persist_acceptance_if_needed() {
    if !is_already_accepted() {
        persist_acceptance();
    }
}

pub fn display_and_confirm() -> anyhow::Result<()> {
    if is_already_accepted() {
        return Ok(());
    }

    println!("{}", LEGAL_TEXT.yellow());
    print!("Acceptez-vous ces conditions ? [o/N] : ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match input.trim().to_lowercase().as_str() {
        "o" | "oui" | "y" | "yes" => {
            persist_acceptance();
            Ok(())
        }
        _ => {
            eprintln!("{}", "Scan annulé. Avertissement légal non accepté.".red());
            std::process::exit(1);
        }
    }
}

const ASCII_ART: &str = r#"
  _   _                _ _
 | \ | | _____   _____| (_) ___
 |  \| |/ _ \ \ / / _ \ | |/ _ \
 | |\  |  __/\ V /  __/ | | (_) |
 |_| \_|\___| \_/ \___|_|_|\___/
"#;

pub fn display_banner() {
    println!("{}", ASCII_ART.cyan().bold());
    println!(
        "  {}  {}",
        format!("v{}", env!("CARGO_PKG_VERSION")).bold().white(),
        "API Security Scanner — Usage autorisé uniquement".dimmed()
    );
    println!("{}", "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan());
    println!();
}
