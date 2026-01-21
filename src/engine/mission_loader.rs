use crate::core::error::RustChainError;
use schemars::JsonSchema;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MissionFile {
    pub description: String,
    pub tasks: Vec<MissionTask>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MissionTask {
    pub op: String,
    pub file: String,
    pub edit: String,
}

pub fn load_mission(path: &str) -> Result<MissionFile, RustChainError> {
    let contents = fs::read_to_string(path)?;
    let parsed: MissionFile = serde_yaml::from_str(&contents)
        .map_err(|e| RustChainError::Schema(format!("YAML parse error: {}", e)))?;
    Ok(parsed)
}
