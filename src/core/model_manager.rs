use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use crate::core::llm::LLMBackend;

#[async_trait]
pub trait ModelManager: Send + Sync {
    async fn get_model(&self, name: &str) -> Option<Arc<dyn LLMBackend>>;
    async fn register_model(&mut self, name: String, model: Arc<dyn LLMBackend>);
}

pub struct DefaultModelManager {
    models: HashMap<String, Arc<dyn LLMBackend>>,
}

impl DefaultModelManager {
    pub fn new() -> Self {
        Self { models: HashMap::new() }
    }
}

#[async_trait]
impl ModelManager for DefaultModelManager {
    async fn get_model(&self, name: &str) -> Option<Arc<dyn LLMBackend>> {
        self.models.get(name).cloned()
    }

    async fn register_model(&mut self, name: String, model: Arc<dyn LLMBackend>) {
        self.models.insert(name, model);
    }
}
