use chrono::Utc;
use colored::Colorize;
use rust_i18n::t;
use std::io::{self, Write};
use std::path::PathBuf;

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

    let sep = "━".repeat(51);
    let legal_text = format!(
        "\n{}\n                  {}\n{}\n{}\n{}",
        sep,
        t!("legal.title"),
        sep,
        t!("legal.body"),
        sep,
    );
    println!("{}", legal_text.yellow());
    print!("{}", t!("legal.prompt"));
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    // Accept in all supported languages: French (o/oui), English (y/yes), Spanish (s/sí/si)
    match input.trim().to_lowercase().as_str() {
        "o" | "oui" | "y" | "yes" | "s" | "sí" | "si" => {
            persist_acceptance();
            Ok(())
        }
        _ => {
            eprintln!("{}", t!("legal.cancelled").red());
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
        t!("legal.tagline").dimmed()
    );
    println!("{}", "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan());
    println!();
}
