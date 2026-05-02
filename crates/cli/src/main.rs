use anyhow::Result;

mod ai_suggestions;
mod args;
mod commands;
mod config;
mod legal;
mod output;
mod tui;

#[tokio::main]
async fn main() -> Result<()> {
    commands::run().await
}
