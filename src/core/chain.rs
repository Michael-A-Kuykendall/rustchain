use crate::core::error::RustChainError;
use async_trait::async_trait;

#[async_trait]
pub trait ChainNode: Send + Sync {
    async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError>;
}

pub struct ChainContext {
    pub vars: std::collections::HashMap<String, String>,
}

impl ChainContext {
    pub fn new() -> Self {
        Self { vars: std::collections::HashMap::new() }
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.vars.insert(key.to_string(), value.to_string());
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
}

pub struct SequentialChain {
    steps: Vec<Box<dyn ChainNode>>,
}

impl SequentialChain {
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    pub fn add(&mut self, step: Box<dyn ChainNode>) {
        self.steps.push(step);
    }

    pub async fn run(&mut self, context: &mut ChainContext) -> Result<(), RustChainError> {
        for step in &self.steps {
            step.run(context).await?;
        }
        Ok(())
    }
}
