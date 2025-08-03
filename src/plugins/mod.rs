use crate::core::tools::{Tool, ToolCapability};
use std::collections::HashMap;

pub trait PluginTool: Tool {}

pub struct PluginRegistry {
    tools: HashMap<String, Box<dyn PluginTool>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self { tools: HashMap::new() }
    }

    pub fn register(&mut self, tool: Box<dyn PluginTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn list(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&Box<dyn PluginTool>> {
        self.tools.get(name)
    }

    pub fn tools_by_capability(&self, cap: ToolCapability) -> Vec<&Box<dyn PluginTool>> {
        self.tools
            .values()
            .filter(|t| t.capabilities().contains(&cap))
            .collect()
    }
}
