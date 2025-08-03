use crate::core::plugin::{ToolPlugin};
use crate::core::plugin_registry::{PluginDescriptor, PluginRegistry};
use crate::core::tools::register_plugin_tools;
use std::sync::Arc;

pub async fn load_plugin(
    registry: &mut PluginRegistry,
    plugin: Arc<dyn ToolPlugin>,
    id: &str,
    kind: &str,
) {
    register_plugin_tools(plugin.clone()).await;
    let descriptor = PluginDescriptor {
        id: id.into(),
        kind: kind.into(),
        registered_tools: vec![], // Stub: extend later with reflection
    };
    registry.register(descriptor);
}
---

file: cli/main.rs
---
use crate::core::plugin_loader::load_plugin;
use crate::core::plugin_registry::PluginRegistry;
use std::sync::Arc;

pub fn handle_plugin_load(path: &str) {
    println!("Loading plugin from: {}", path);
    // Stub: In reality, dynamically load .so or precompiled crate
    let dummy_plugin: Arc<dyn crate::core::plugin::ToolPlugin> = todo!("Load plugin object");
    let mut registry = PluginRegistry::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(load_plugin(&mut registry, dummy_plugin, path, "custom"));
}
---

file: lib.rs
---
pub mod plugin_loader;
---
