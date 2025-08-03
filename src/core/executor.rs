use crate::core::{Mission, MissionStep, Result, RustChainError};
use std::path::Path;
use std::process::Command;

pub struct MissionExecutor;

impl MissionExecutor {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn execute_mission(&self, mission: Mission) -> Result<()> {
        println!("🚀 Executing mission: {}", mission.name);
        
        for (i, step) in mission.steps.iter().enumerate() {
            println!("📋 Step {}/{}: {}", i + 1, mission.steps.len(), step.id);
            self.execute_step(step).await?;
        }
        
        println!("✅ Mission completed: {}", mission.name);
        Ok(())
    }
    
    async fn execute_step(&self, step: &MissionStep) -> Result<()> {
        match step.step_type.as_str() {
            "create" => self.execute_create_step(step),
            "edit" => self.execute_edit_step(step),
            "command" => self.execute_command_step(step),
            "test" => self.execute_test_step(step),
            _ => Err(RustChainError::Tool(format!("Unknown step type: {}", step.step_type))),
        }
    }
    
    fn execute_create_step(&self, step: &MissionStep) -> Result<()> {
        if let (Some(file_path), Some(content)) = (&step.file_path, &step.content) {
            let path = Path::new(file_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)?;
            println!("📝 Created: {}", file_path);
        } else {
            return Err(RustChainError::Tool("Create step missing file_path or content".to_string()));
        }
        Ok(())
    }
    
    fn execute_edit_step(&self, step: &MissionStep) -> Result<()> {
        if let (Some(file_path), Some(content)) = (&step.file_path, &step.content) {
            let existing = std::fs::read_to_string(file_path).unwrap_or_default();
            let new_content = format!("{}\n{}", existing.trim(), content.trim());
            std::fs::write(file_path, new_content)?;
            println!("✏️ Edited: {}", file_path);
        } else {
            return Err(RustChainError::Tool("Edit step missing file_path or content".to_string()));
        }
        Ok(())
    }
    
    fn execute_command_step(&self, step: &MissionStep) -> Result<()> {
        if let Some(command) = &step.command {
            let output = Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()?;
            
            if output.status.success() {
                println!("🔧 Command succeeded: {}", command);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(RustChainError::Tool(format!("Command failed: {}", stderr)));
            }
        } else {
            return Err(RustChainError::Tool("Command step missing command".to_string()));
        }
        Ok(())
    }
    
    fn execute_test_step(&self, step: &MissionStep) -> Result<()> {
        let default_lang = "rust".to_string();
        let language = step.language.as_ref().unwrap_or(&default_lang);
        
        match language.as_str() {
            "rust" => {
                let output = Command::new("cargo")
                    .args(&["test"])
                    .output()?;
                
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
