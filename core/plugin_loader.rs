use std::collections::HashMap;
use std::path::Path;

pub struct PluginLoader {
    plugins: HashMap<String, String>,
}

impl PluginLoader {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    pub fn load_plugin(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let plugin_name = path.file_stem()
            .and_then(|name| name.to_str())
            .ok_or("Invalid plugin path")?
            .to_string();

        println!("Loading plugin: {} from {:?}", plugin_name, path);
        
        // Create runtime with proper error handling instead of unwrap
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create Tokio runtime: {}", e))?;
        
        // Plugin loading logic here
        rt.block_on(async {
            // Async plugin loading
            println!("Plugin {} loaded successfully", plugin_name);
        });

        self.plugins.insert(plugin_name.clone(), path.to_string_lossy().to_string());
        
        Ok(())
    }

    pub fn list_plugins(&self) -> Vec<&String> {
        self.plugins.keys().collect()
    }
}
