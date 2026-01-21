use crate::core::error::{ConfigError, RustChainError};
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub struct RustChainConfig {
    pub endpoints: HashMap<String, String>,
    pub timeouts: HashMap<String, u64>,
    pub feature_flags: HashMap<String, bool>,
}

static CONFIG: OnceLock<RustChainConfig> = OnceLock::new();

pub fn load_config(config: RustChainConfig) -> Result<(), RustChainError> {
    CONFIG
        .set(config)
        .map_err(|_| RustChainError::Config(ConfigError::parse_error("Config already loaded")))
}

pub fn get_config() -> Result<RustChainConfig, RustChainError> {
    CONFIG
        .get()
        .cloned()
        .ok_or_else(|| RustChainError::Config(ConfigError::parse_error("Config not loaded")))
}
