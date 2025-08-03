use std::collections::{HashMap, HashSet};
use std::fs;
use crate::core::error::RustChainError;
use crate::engine::mission_loader::MissionFile;

pub fn scan_mission_files(paths: &[&str]) -> Result<(), RustChainError> {
    let mut file_map: HashMap<String, Vec<String>> = HashMap::new();

    for path in paths {
        let contents = fs::read_to_string(path)?;
        let mission: MissionFile = serde_yaml::from_str(&contents)
            .map_err(|e| RustChainError::Schema(format!("Parse error: {}", e)))?;

        for task in &mission.tasks {
            file_map
                .entry(task.file.clone())
                .or_default()
                .push(path.to_string());
        }
    }

    println!("🔍 Mission File Conflict Report");
    for (file, sources) in &file_map {
        if sources.len() > 1 {
            println!("[⚠️ Conflict] File '{}' modified by: {:?}", file, sources);
        }
    }

    Ok(())
}
