use std::collections::HashMap;
use crate::core::Result;

pub trait MemoryStore: Send + Sync {
    fn store(&mut self, key: &str, value: &str) -> Result<()>;
    fn retrieve(&self, key: &str) -> Result<Option<String>>;
    fn list_keys(&self) -> Result<Vec<String>>;
}

pub struct InMemoryStore {
    data: HashMap<String, String>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl MemoryStore for InMemoryStore {
    fn store(&mut self, key: &str, value: &str) -> Result<()> {
        self.data.insert(key.to_string(), value.to_string());
        Ok(())
    }
    
    fn retrieve(&self, key: &str) -> Result<Option<String>> {
        Ok(self.data.get(key).cloned())
    }
    
    fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self.data.keys().cloned().collect())
    }
}
