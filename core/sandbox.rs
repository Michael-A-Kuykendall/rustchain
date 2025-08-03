use std::process::{Command, Stdio};
use std::io::Write;
use std::time::Duration;
use tokio::time::timeout;

pub struct Sandbox;

impl Sandbox {
    pub async fn run_code(code: &str, timeout_ms: u64) -> Result<String, String> {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(code)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn: {}", e))?;

        let output = timeout(Duration::from_millis(timeout_ms), child.wait_with_output())
            .await
            .map_err(|_| "Execution timed out".to_string())?
            .map_err(|e| format!("Execution error: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !stderr.is_empty() {
            Err(stderr)
        } else {
            Ok(stdout)
        }
    }
}
---

file: core/tools.rs
---
mod sandbox;
use sandbox::Sandbox;

pub struct SandboxTool;

#[async_trait]
impl Tool for SandboxTool {
    async fn name(&self) -> String {
        "sandbox".into()
    }

    async fn call(&self, input: &str) -> String {
        match Sandbox::run_code(input, 1000).await {
            Ok(output) => output,
            Err(err) => format!("Sandbox error: {}", err),
        }
    }
}
---

file: lib.rs
---
pub mod sandbox;
---
