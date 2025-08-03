use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(name = "rustchain", version = "0.1", author = "RustChain")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Run {
        #[clap(value_parser)]
        mission: String,
    },
    Invariant,
    Plugin {
        #[clap(subcommand)]
        cmd: PluginCommands,
    },
    Api,
}

#[derive(Subcommand)]
pub enum PluginCommands {
    List,
    Info {
        #[clap(value_parser)]
        id: String,
    },
}
---

file: cli/main.rs
---
use crate::cli::commands::{Cli, Commands, PluginCommands};
use crate::cli::subcommands::invariant::handle_invariant_check;
use crate::server::api::serve_api;
use clap::Parser;

pub fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { mission } => {
            println!("Running mission: {}", mission);
        }
        Commands::Invariant => {
            handle_invariant_check();
        }
        Commands::Plugin { cmd } => match cmd {
            PluginCommands::List => {
                println!("Listing plugins...");
            }
            PluginCommands::Info { id } => {
                println!("Plugin info: {}", id);
            }
        },
        Commands::Api => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(serve_api());
        }
    }
}
---

file: lib.rs
---
pub mod cli;
---
