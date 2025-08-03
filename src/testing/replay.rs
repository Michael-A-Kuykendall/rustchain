use std::fs;
use serde::Deserialize;
use crate::core::error::RustChainError;
use crate::engine::mission_loader::MissionFile;

#[derive(Debug, Deserialize)]
pub struct ReplayCase {
    pub mission_path: String,
    pub expected_output: String,
}

pub fn run_replay_test(case_path: &str) -> Result<(), RustChainError> {
    let contents = fs::read_to_string(case_path)?;
    let test_case: ReplayCase = serde_yaml::from_str(&contents)
        .map_err(|e| RustChainError::Test(format!("Parse error: {}", e)))?;

    let mission_yaml = fs::read_to_string(&test_case.mission_path)?;
    let parsed: MissionFile = serde_yaml::from_str(&mission_yaml)
        .map_err(|e| RustChainError::Test(format!("Mission parse failed: {}", e)))?;

    let fake_stdout = format!("Stub: executed {}", parsed.description);
    if fake_stdout.trim() != test_case.expected_output.trim() {
        return Err(RustChainError::Test("Replay mismatch".into()));
    }

    Ok(())
}
