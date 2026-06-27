use anyhow::Result;

rust_i18n::i18n!("locales");

mod ai_suggestions;
mod args;
mod commands;
mod config;
mod diff;
mod legal;
mod locale;
mod modules;
mod output;
mod shell;
mod tui;
mod watch;

#[tokio::main]
async fn main() -> Result<()> {
    commands::run().await
}
