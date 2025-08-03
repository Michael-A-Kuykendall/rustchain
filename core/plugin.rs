use async_trait::async_trait;
use crate::core::tools::Tool;
use std::sync::Arc;

#[async_trait]
pub trait ToolPlugin: Send + Sync {
    async fn register_tools(&self) -> Vec<Arc<dyn Tool>>;
}
---

file: core/tools.rs
---
use std::collections::HashMap;
use std::sync::Arc;
use crate::core::plugin::ToolPlugin;

lazy_static::lazy_static! {
    static ref TOOL_REGISTRY: tokio::sync::RwLock<HashMap<String, Arc<dyn Tool>>> = tokio::sync::RwLock::new(HashMap::new());
}

pub async fn register_plugin_tools(plugin: Arc<dyn ToolPlugin>) {
    let tools = plugin.register_tools().await;
    let mut registry = TOOL_REGISTRY.write().await;
    for tool in tools {
        let name = tool.name().await;
        registry.insert(name, tool);
    }
}

pub async fn get_tool(name: &str) -> Option<Arc<dyn Tool>> {
    let registry = TOOL_REGISTRY.read().await;
    registry.get(name).cloned()
}
---

file: lib.rs
---
pub mod plugin;
---
