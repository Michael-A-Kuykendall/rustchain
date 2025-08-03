use crate::core::config::{RustChainConfig, load_config};
use std::fs;
use std::collections::HashMap;
use toml::Value;
use crate::core::error::RustChainError;

pub fn bootstrap_config(path: &str) -> Result<(), RustChainError> {
    let contents = fs::read_to_string(path)?;
    let parsed: Value = contents.parse::<Value>()
        .map_err(|e| RustChainError::Config(format!("TOML parse error: {}", e)))?;

    let endpoints = parsed.get("endpoints")
        .and_then(|v| v.as_table())
        .map(|t| {
            t.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_else(HashMap::new);

    let timeouts = parsed.get("timeouts")
        .and_then(|v| v.as_table())
        .map(|t| {
            t.iter()
                .map(|(k, v)| (k.clone(), v.as_integer().unwrap_or(0) as u64))
                .collect()
        })
        .unwrap_or_else(HashMap::new);

    let feature_flags = parsed.get("feature_flags")
        .and_then(|v| v.as_table())
        .map(|t| {
            t.iter()
                .map(|(k, v)| (k.clone(), v.as_bool().unwrap_or(false)))
                .collect()
        })
        .unwrap_or_else(HashMap::new);

    let config = RustChainConfig {
        endpoints,
        timeouts,
        feature_flags,
    };

    load_config(config);
    Ok(())
}
