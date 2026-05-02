use anyhow::Result;

mod args;
mod commands;
mod config;
mod legal;
mod output;

#[tokio::main]
async fn main() -> Result<()> {
    commands::run().await
}
