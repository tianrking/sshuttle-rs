mod app;
mod config;
mod doctor;
mod platform;
mod proxy;

use clap::Parser;
use config::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    app::run(cli).await
}
