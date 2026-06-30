use anyhow::{bail, Result};
use colored::Colorize;
use rust_i18n::t;
use std::io::{self, BufRead, Write};

pub fn show_and_confirm() -> Result<()> {
    println!();
    println!("  {} ╔══════════════════════════════════════════════════════════╗", " ".dimmed());
    println!("  {} ║  {:<56}║", " ".dimmed(), t!("disclaimer.title"));
    println!("  {} ╚══════════════════════════════════════════════════════════╝", " ".dimmed());
    println!();
    let active_word = t!("disclaimer.active_word").to_string().bold().to_string();
    println!("  {}", t!("disclaimer.intro", kind = active_word));
    println!();
    println!("  {} {}", "⚠".yellow().bold(), t!("disclaimer.usage_title"));
    println!("    • {}", t!("disclaimer.usage_1"));
    println!("    • {}", t!("disclaimer.usage_2"));
    println!("    • {}", t!("disclaimer.usage_3"));
    println!();
    println!("  {} {}", "⚠".yellow(), t!("disclaimer.legal_title"));
    println!("    • {}", t!("disclaimer.legal_fr"));
    println!("    • {}", t!("disclaimer.legal_eu"));
    println!("    • {}", t!("disclaimer.legal_us"));
    println!();
    println!(
        "  {}",
        t!(
            "disclaimer.confirm_prompt",
            yes    = t!("disclaimer.confirm_word").green().bold().to_string(),
            cancel = "Ctrl+C".red().to_string()
        )
    );
    print!("  > ");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;

    let input = line.trim().to_lowercase();
    let confirm_word = t!("disclaimer.confirm_word").to_string();
    if input != confirm_word && input != "yes" && input != "oui" && input != "si" {
        bail!("{}", t!("disclaimer.rejected"));
    }

    println!();
    Ok(())
}
