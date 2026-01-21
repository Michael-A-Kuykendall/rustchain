use rustchain::cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Delegate to CLI (it will handle tracing initialization)
    cli::run().await.map_err(|e| anyhow::anyhow!("{}", e))
}
