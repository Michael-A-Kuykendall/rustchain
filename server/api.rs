use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn serve_api(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    
    // Bind with proper error handling instead of unwrap
    let listener = TcpListener::bind(&addr).await
        .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;
    
    println!("🚀 RustChain API Server listening on http://{}", addr);
    
    loop {
        let (stream, peer_addr) = listener.accept().await
            .map_err(|e| format!("Failed to accept connection: {}", e))?;
        
        println!("📡 New connection from: {}", peer_addr);
        
        // Handle connection
        tokio::spawn(async move {
            // Connection handling logic here
            println!("Processing request from {}", peer_addr);
        });
    }
}
