pub mod commands;
pub mod commands_pretty;
pub mod handlers;
pub mod handlers_pretty;
pub mod help_examples;
pub mod interactive;
pub mod pretty;

use clap::Parser;
use commands::Cli;
use handlers::handle_command;

/// Main CLI entry point
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Cli::parse();

    // Initialize logging
    init_logging()?;

    // Handle the command with enhanced error formatting
    handle_command(args.command).await
}

/// Initialize logging system
fn init_logging() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    // Only initialize if not already initialized
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize logging - surface any errors
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .try_init()
        .map_err(|e| format!("Failed to initialize logging: {}", e))?;

    Ok(())
}

/// Graceful error handling
pub fn handle_error(error: &dyn std::error::Error) {
    eprintln!("Fatal error: {}", error);
    tracing::error!("Application error: {}", error);
}
