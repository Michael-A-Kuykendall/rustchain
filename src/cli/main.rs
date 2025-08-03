use clap::Parser;
use crate::core::error::RustChainError;
use crate::engine::mission_loader::load_mission;
use crate::engine::executor::run_mission;
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "RustChain")]
#[command(about = "Run mission stacks defined in YAML", long_about = None)]
struct Args {
    /// Path to mission YAML file
    #[arg(short, long)]
    mission: String,
}

fn main() -> Result<(), RustChainError> {
    let args = Args::parse();
    let mission = load_mission(&args.mission)?;
    run_mission(&mission)?;
    println!("✅ Mission completed successfully.");
    Ok(())
}
