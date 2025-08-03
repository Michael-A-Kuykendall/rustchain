use crate::cli::commands::{Cli, Commands, PluginCommands};
use crate::cli::subcommands::invariant::handle_invariant_check;
use crate::server::api::serve_api;
use clap::Parser;
use std::process;

pub fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Run { mission } => {
            println!("Running mission: {}", mission);
            Ok(())
        }
        Commands::Invariant => {
            handle_invariant_check();
            Ok(())
        }
        Commands::Serve { port } => {
            println!("Starting server on port {}...", port);
            
            // Create runtime with proper error handling
            let rt = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(e) => {
                    eprintln!("Failed to create Tokio runtime: {}", e);
                    process::exit(1);
                }
            };
            
            if let Err(e) = rt.block_on(serve_api(port)) {
                eprintln!("Server error: {}", e);
                process::exit(1);
            }
            
            Ok(())
        }
        Commands::Plugin(PluginCommands::List) => {
            println!("Available plugins:");
            Ok(())
        }
        Commands::Plugin(PluginCommands::Load { path }) => {
            println!("Loading plugin from: {}", path);
            Ok(())
        }
    };
    
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
