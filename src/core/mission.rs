use crate::core::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Mission {
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<MissionStep>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MissionStep {
    pub id: String,
    pub step_type: String,
    pub parameters: Option<serde_json::Value>,
    // Legacy fields for backward compatibility
    pub file_path: Option<String>,
    pub content: Option<String>,
    pub command: Option<String>,
    pub language: Option<String>,
    pub description: Option<String>,
}

pub fn load_mission(path: &Path) -> Result<Mission> {
    let content = std::fs::read_to_string(path)?;
    let data: serde_yaml::Value = serde_yaml::from_str(&content).map_err(|e| {
        crate::core::RustChainError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;

    let mission_data = data.get("mission").unwrap_or(&data);
    let mission: Mission = serde_yaml::from_value(mission_data.clone()).map_err(|e| {
        crate::core::RustChainError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;

    Ok(mission)
}
