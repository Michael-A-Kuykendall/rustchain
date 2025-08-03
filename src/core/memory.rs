use crate::core::error::RustChainError;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub trait MemoryStore: Send + Sync {
    fn store(&mut self, key: &str, value: &str) -> Result<(), RustChainError>;
    fn retrieve(&self, key: &str) -> Result<Option<String>, RustChainError>;
    fn cleanup(&mut self) -> Result<(), RustChainError>;
    fn summarize(&self) -> Result<String, RustChainError>;
    fn list_keys(&self) -> Result<Vec<String>, RustChainError>;
}

pub struct InMemoryStore {
    data: HashMap<String, (String, Instant)>,
    ttl_seconds: u64,
}

impl InMemoryStore {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            data: HashMap::new(),
            ttl_seconds,
        }
    }
}

impl MemoryStore for InMemoryStore {
    fn store(&mut self, key: &str, value: &str) -> Result<(), RustChainError> {
        self.data.insert(key.to_string(), (value.to_string(), Instant::now()));
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Option<String>, RustChainError> {
        if let Some((val, timestamp)) = self.data.get(key) {
            if timestamp.elapsed().as_secs() < self.ttl_seconds {
                return Ok(Some(val.clone()));
            }
        }
        Ok(None)
    }

    fn cleanup(&mut self) -> Result<(), RustChainError> {
        self.data.retain(|_, (_, ts)| ts.elapsed().as_secs() < self.ttl_seconds);
        Ok(())
    }

    fn summarize(&self) -> Result<String, RustChainError> {
        let summary = self.data
            .values()
            .map(|(v, _)| v.clone())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(format!("Summary: {}", &summary))
    }

    fn list_keys(&self) -> Result<Vec<String>, RustChainError> {
        Ok(self.data.keys().cloned().collect())
    }
}
