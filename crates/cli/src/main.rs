use anyhow::Result;

rust_i18n::i18n!("locales");

mod agent_cmd;
mod ai_suggestions;
mod args;
mod commands;
mod config;
mod config_cmd;
mod diff;
mod issue;
mod legal;
mod locale;
mod mcp;
mod modules;
mod notify;
mod output;
mod scan;
mod script;
mod serve;
mod shell;
mod tui;
mod watch;

#[tokio::main]
async fn main() -> Result<()> {
    commands::run().await
}
