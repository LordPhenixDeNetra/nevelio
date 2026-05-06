use anyhow::Result;

rust_i18n::i18n!("locales");

mod ai_suggestions;
mod args;
mod commands;
mod config;
mod legal;
mod locale;
mod output;
mod tui;

#[tokio::main]
async fn main() -> Result<()> {
    commands::run().await
}
