use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rustchain")]
#[command(about = "RustChain AI Agent System")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Run a mission")]
    Run {
        #[arg(help = "Path to mission file")]
        mission: String,
    },
    #[command(about = "Check invariants")]
    Invariant,
    #[command(about = "Start server")]
    Serve {
        #[arg(long, default_value = "3000")]
        port: u16,
    },
    #[command(subcommand)]
    Plugin(PluginCommands),
}

#[derive(Subcommand)]
pub enum PluginCommands {
    #[command(about = "List plugins")]
    List,
    #[command(about = "Load plugin")]
    Load {
        #[arg(help = "Plugin path")]
        path: String,
    },
}

// Implementation moved to cli/main.rs with proper error handling
