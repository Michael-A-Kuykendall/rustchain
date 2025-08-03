use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PluginDescriptor {
    pub id: String,
    pub kind: String,
    pub registered_tools: Vec<String>,
}

pub struct PluginRegistry {
    plugins: HashMap<String, PluginDescriptor>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    pub fn register(&mut self, descriptor: PluginDescriptor) {
        self.plugins.insert(descriptor.id.clone(), descriptor);
    }

    pub fn list(&self) -> Vec<PluginDescriptor> {
        self.plugins.values().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<PluginDescriptor> {
        self.plugins.get(id).cloned()
    }
}
---

file: engine/context.rs
---
use crate::core::plugin_registry::PluginRegistry;

pub struct RuntimeContext {
    pub plugin_registry: PluginRegistry,
    // existing fields...
}

impl RuntimeContext {
    pub fn new() -> Self {
        Self {
            plugin_registry: PluginRegistry::new(),
            // existing init...
        }
    }
}
---

file: lib.rs
---
pub mod plugin_registry;
---
