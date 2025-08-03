use rustchain::{cli::run_cli, init_logging};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    
    tracing::info!("🚀 RustChain starting...");
    run_cli().await?;
    tracing::info!("✅ RustChain completed");
    
    Ok(())
}
