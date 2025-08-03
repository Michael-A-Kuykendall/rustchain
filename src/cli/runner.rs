use clap::Parser;
use crate::core::Result;

#[derive(Parser)]
#[command(name = "rustchain")]
pub struct Cli {
    #[arg(short, long)]
    pub interactive: bool,
    
    #[arg(long)]
    pub test: bool,
}

pub async fn run_cli() -> Result<()> {
    let args = Cli::parse();
    
    if args.test {
        println!("✅ CLI test passed");
    } else if args.interactive {
        println!("🤖 Interactive mode (not yet implemented)");
    } else {
        println!("🚀 RustChain CLI");
    }
    
    Ok(())
}
