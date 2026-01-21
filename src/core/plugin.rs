use crate::core::{Result, RuntimeContext};
use std::collections::{HashMap, HashSet};

/// Enterprise plugin trait for runtime feature extension
/// This enables clean separation between community and enterprise features
pub trait EnterprisePlugin: Send + Sync {
    /// Plugin identification
    fn name(&self) -> &str;

    /// Initialize plugin with the runtime context
    fn initialize(&mut self, context: &mut RuntimeContext) -> Result<()>;

    /// List of features this plugin provides
    fn features(&self) -> Vec<String>;

    /// Cleanup when plugin is unloaded
    fn shutdown(&mut self) -> Result<()>;

    /// Plugin version for compatibility checking
    fn version(&self) -> &str {
        "1.0.0"
    }

    /// Check if plugin is compatible with runtime version
    fn is_compatible(&self, runtime_version: &str) -> bool {
        // Simple compatibility check - can be enhanced
        runtime_version.starts_with("0.1") || runtime_version.starts_with("1.")
    }
}

/// Plugin manager for loading and managing enterprise plugins
pub struct PluginManager {
    plugins: HashMap<String, Box<dyn EnterprisePlugin>>,
    enabled_features: HashSet<String>,
    runtime_version: String,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            enabled_features: HashSet::new(),
            runtime_version: "0.1.0".to_string(),
        }
    }

    /// Register a plugin with the manager
    pub fn register(&mut self, plugin: Box<dyn EnterprisePlugin>) -> Result<()> {
        let name = plugin.name().to_string();

        // Check compatibility
        if !plugin.is_compatible(&self.runtime_version) {
            return Err(crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!(
                        "Plugin {} is not compatible with runtime version {}",
                        name, self.runtime_version
                    ),
                },
            ));
        }

        // Add features to enabled set
        let features = plugin.features();
        for feature in features {
            self.enabled_features.insert(feature);
        }

        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Initialize all registered plugins
    pub fn initialize_all(&mut self, context: &mut RuntimeContext) -> Result<()> {
        for (name, plugin) in self.plugins.iter_mut() {
            plugin.initialize(context).map_err(|e| {
                crate::core::error::RustChainError::Config(
                    crate::core::error::ConfigError::PluginError {
                        message: format!("Failed to initialize plugin {}: {}", name, e),
                    },
                )
            })?;
        }
        Ok(())
    }

    /// Check if a feature is enabled through plugins
    pub fn has_feature(&self, feature: &str) -> bool {
        self.enabled_features.contains(feature)
    }

    /// Get list of all enabled features
    pub fn enabled_features(&self) -> Vec<String> {
        self.enabled_features.iter().cloned().collect()
    }

    /// Get list of loaded plugin names
    pub fn loaded_plugins(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }

    /// Shutdown all plugins
    pub fn shutdown_all(&mut self) -> Result<()> {
        let mut errors = Vec::new();

        for (name, plugin) in self.plugins.iter_mut() {
            if let Err(e) = plugin.shutdown() {
                errors.push(format!("Plugin {} shutdown error: {}", name, e));
            }
        }

        if !errors.is_empty() {
            return Err(crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!("Plugin shutdown errors: {}", errors.join("; ")),
                },
            ));
        }

        self.plugins.clear();
        self.enabled_features.clear();
        Ok(())
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RuntimeContext;

    struct MockPlugin {
        name: String,
        features: Vec<String>,
        initialized: bool,
    }

    impl MockPlugin {
        fn new(name: &str, features: Vec<&str>) -> Self {
            Self {
                name: name.to_string(),
                features: features.into_iter().map(|s| s.to_string()).collect(),
                initialized: false,
            }
        }
    }

    impl EnterprisePlugin for MockPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn initialize(&mut self, _context: &mut RuntimeContext) -> Result<()> {
            self.initialized = true;
            Ok(())
        }

        fn features(&self) -> Vec<String> {
            self.features.clone()
        }

        fn shutdown(&mut self) -> Result<()> {
            self.initialized = false;
            Ok(())
        }
    }

    #[test]
    fn test_plugin_manager_creation() {
        let manager = PluginManager::new();
        assert_eq!(manager.loaded_plugins().len(), 0);
        assert_eq!(manager.enabled_features().len(), 0);
    }

    #[test]
    fn test_plugin_registration() {
        let mut manager = PluginManager::new();
        let plugin = Box::new(MockPlugin::new("test", vec!["feature1", "feature2"]));

        assert!(manager.register(plugin).is_ok());
        assert_eq!(manager.loaded_plugins().len(), 1);
        assert_eq!(manager.enabled_features().len(), 2);
        assert!(manager.has_feature("feature1"));
        assert!(manager.has_feature("feature2"));
        assert!(!manager.has_feature("feature3"));
    }

    #[test]
    fn test_plugin_initialization() {
        let mut manager = PluginManager::new();
        let plugin = Box::new(MockPlugin::new("test", vec!["feature1"]));

        manager.register(plugin).unwrap();

        let mut context = RuntimeContext::new();
        assert!(manager.initialize_all(&mut context).is_ok());
    }

    #[test]
    fn test_plugin_shutdown() {
        let mut manager = PluginManager::new();
        let plugin = Box::new(MockPlugin::new("test", vec!["feature1"]));

        manager.register(plugin).unwrap();
        assert_eq!(manager.loaded_plugins().len(), 1);

        assert!(manager.shutdown_all().is_ok());
        assert_eq!(manager.loaded_plugins().len(), 0);
        assert_eq!(manager.enabled_features().len(), 0);
    }
}
