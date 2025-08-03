use crate::core::error::RustChainError;
use async_trait::async_trait;
use std::collections::HashMap;
use serde_json::Value;

#[derive(Debug)]
pub enum ToolResult {
    Success(String),
    StructuredJson(Value),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ToolCapability {
    Basic,
    WasmPlugin,
    SystemAccess,
    NetworkAccess,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Vec<ToolCapability>;
    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError>;
}

pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { tools: HashMap::new() }
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&Box<dyn Tool>> {
        self.tools.get(name)
    }

    pub fn list(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    pub fn tools_by_capability(&self, cap: ToolCapability) -> Vec<&Box<dyn Tool>> {
        self.tools
            .values()
            .filter(|tool| tool.capabilities().contains(&cap))
            .collect()
    }
}
