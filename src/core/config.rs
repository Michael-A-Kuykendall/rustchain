use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use crate::core::error::RustChainError;

#[derive(Clone, Debug)]
pub struct RustChainConfig {
    pub endpoints: HashMap<String, String>,
    pub timeouts: HashMap<String, u64>,
    pub feature_flags: HashMap<String, bool>,
}

static CONFIG: Lazy<Mutex<Option<RustChainConfig>>> = Lazy::new(|| Mutex::new(None));

pub fn load_config(config: RustChainConfig) {
    let mut global = CONFIG.lock().unwrap();
    *global = Some(config);
}

pub fn get_config() -> Result<RustChainConfig, RustChainError> {
    let global = CONFIG.lock().unwrap();
    global.clone().ok_or_else(|| RustChainError::Config("Config not loaded".into()))
}
