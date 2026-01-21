use std::collections::HashMap;
use crate::core::error::RustChainError;

#[derive(Default)]
pub struct ContextState {
    pub vars: HashMap<String, String>,
    pub history: Vec<String>,
}

impl ContextState {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            history: Vec::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.vars.insert(key.to_string(), value.to_string());
    }

    pub fn record(&mut self, entry: &str) {
        self.history.push(entry.to_string());
    }

    pub fn summarize(&self) -> Result<String, RustChainError> {
        Ok(self.history.join("\n"))
    }
}
