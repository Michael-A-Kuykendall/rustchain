use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::core::Result;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub llm: LlmConfig,
    pub tools: ToolsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LlmConfig {
    pub default_backend: String,
    pub ollama_base_url: String,
    pub ollama_model: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolsConfig {
    pub enabled: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}

impl Config {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| crate::core::RustChainError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        Ok(config)
    }
    
    pub fn default() -> Self {
        Self {
            llm: LlmConfig {
                default_backend: "ollama".to_string(),
                ollama_base_url: "http://localhost:11434".to_string(),
                ollama_model: "tinyllama".to_string(),
                timeout_seconds: 30,
            },
            tools: ToolsConfig {
                enabled: vec!["echo".to_string(), "math".to_string()],
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
            },
        }
    }
}
