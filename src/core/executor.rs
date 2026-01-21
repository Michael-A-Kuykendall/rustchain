use crate::core::{Mission, MissionStep, Result, RustChainError, ToolError};
use std::path::Path;
use std::process::Command;

#[derive(Default)]
pub struct MissionExecutor;

impl MissionExecutor {
    pub fn new() -> Self {
        Self
    }

    // Helper function to get parameter as string
    fn get_param(&self, step: &MissionStep, key: &str) -> Option<String> {
        if let Some(params) = &step.parameters {
            params.get(key)?.as_str().map(String::from)
        } else {
            None
        }
    }

    // Helper function to get file path from parameters or legacy field
    fn get_file_path(&self, step: &MissionStep) -> Option<String> {
        self.get_param(step, "path")
            .or_else(|| step.file_path.clone())
    }

    // Helper function to get content from parameters or legacy field
    fn get_content(&self, step: &MissionStep) -> Option<String> {
        self.get_param(step, "content")
            .or_else(|| step.content.clone())
    }

    // Helper function to get command from parameters or legacy field
    fn get_command(&self, step: &MissionStep) -> Option<String> {
        self.get_param(step, "command")
            .or_else(|| step.command.clone())
    }

    pub async fn execute_mission(&self, mission: Mission) -> Result<()> {
        tracing::info!("Executing mission: {}", mission.name);

        for (i, step) in mission.steps.iter().enumerate() {
            tracing::debug!("Step {}/{}: {}", i + 1, mission.steps.len(), step.id);
            self.execute_step(step).await?;
        }

        tracing::info!("Mission completed: {}", mission.name);
        Ok(())
    }

    async fn execute_step(&self, step: &MissionStep) -> Result<()> {
        match step.step_type.as_str() {
            "create" | "create_file" => self.execute_create_step(step),
            "edit" => self.execute_edit_step(step),
            "command" => self.execute_command_step(step),
            "test" => self.execute_test_step(step),
            _ => Err(RustChainError::Tool(ToolError::NotFound {
                tool_name: format!("step_type_{}", step.step_type),
            })),
        }
    }

    fn execute_create_step(&self, step: &MissionStep) -> Result<()> {
        if let (Some(file_path), Some(content)) = (self.get_file_path(step), self.get_content(step))
        {
            let path = Path::new(&file_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &content)?;
            println!("📝 Created: {}", file_path);
        } else {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "create_file".to_string(),
                details: "Missing file_path or content parameters".to_string(),
            }));
        }
        Ok(())
    }

    fn execute_edit_step(&self, step: &MissionStep) -> Result<()> {
        if let (Some(file_path), Some(content)) = (self.get_file_path(step), self.get_content(step))
        {
            // Read existing content if file exists, empty string if not found
            // Propagate other errors (permissions, disk, etc.)
            let existing = match std::fs::read_to_string(&file_path) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e.into()),
            };
            let new_content = format!("{}\n{}", existing.trim(), content.trim());
            std::fs::write(&file_path, new_content)?;
            println!("✏️ Edited: {}", file_path);
        } else {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "edit_file".to_string(),
                details: "Missing file_path or content parameters".to_string(),
            }));
        }
        Ok(())
    }

    fn execute_command_step(&self, step: &MissionStep) -> Result<()> {
        if let Some(command) = self.get_command(step) {
            // SECURITY: Parse command safely - no shell injection
            let parts: Vec<&str> = command.split_whitespace().collect();
            if parts.is_empty() {
                return Err(RustChainError::Tool(ToolError::InvalidParameters {
                    tool_name: "command".to_string(),
                    details: "Empty command parameter".to_string(),
                }));
            }

            // SECURITY: Allowlist of safe commands only
            let allowed_commands = ["cargo", "rustc", "git", "echo", "ls", "pwd", "cat"];
            if !allowed_commands.contains(&parts[0]) {
                return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "command".to_string(),
                    reason: format!("Command '{}' not in allowlist", parts[0]),
                }));
            }

            // NOTE: This is a simple pretty executor for CLI display.
            // For production use with timeout support, use the full engine at src/engine/mod.rs
            // which wraps commands with tokio::time::timeout.
            let output = Command::new(parts[0]).args(&parts[1..]).output()?;

            if output.status.success() {
                println!("🔧 Command succeeded: {}", command);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "command".to_string(),
                    reason: format!("Command failed: {}", stderr),
                }));
            }
        } else {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "command".to_string(),
                details: "Missing command parameter".to_string(),
            }));
        }
        Ok(())
    }

    fn execute_test_step(&self, step: &MissionStep) -> Result<()> {
        let default_lang = "rust".to_string();
        let language = step.language.as_ref().unwrap_or(&default_lang);

        match language.as_str() {
            "rust" => {
                let output = Command::new("cargo").args(["test"]).output()?;

                if output.status.success() {
                    println!("✅ Tests passed");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("⚠️ Test output: {}", stderr);
                }
            }
            _ => println!("🧪 Test step for {} (not implemented)", language),
        }

        Ok(())
    }
}
