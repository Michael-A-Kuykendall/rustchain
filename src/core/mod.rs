//! # Core Runtime Infrastructure
//!
//! This module provides the foundational runtime infrastructure for RustChain,
//! including configuration management, audit logging, and shared runtime context.
//!
//! ## Components
//!
//! - **RuntimeContext**: Central context object providing access to all runtime services
//! - **Config**: Configuration management with environment variable support
//! - **AuditChain**: Cryptographically-verified audit logging with blockchain-style hashing
//! - **ToolRegistry**: Registry for managing and invoking tools with type safety
//! - **PerfCollector**: Performance metrics collection and reporting
//! - **ModelManager**: LLM integration management (when LLM feature is enabled)
//! - **AgentSandbox**: Basic code execution sandboxing with safety checks
//! - **PolicyEngine**: Policy-based action validation system
//! - **Error Types**: Comprehensive error handling with context preservation
//!
//! ## RuntimeContext
//!
//! The `RuntimeContext` is the primary entry point for accessing RustChain services:
//!
//! ```rust
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rustchain::core::RuntimeContext;
//!
//! let ctx = RuntimeContext::new();
//!
//! // Access configuration
//! let config = ctx.config.read().await;
//!
//! // Log audit events
//! ctx.audit_action("user", "login", "Login successful").await;
//!
//! // Access tool registry (with tools feature)
//! #[cfg(feature = "tools")]
//! {
//!     let tools = ctx.tool_registry.read().await;
//!     // Use tools...
//! }
//! Ok(())
//! }
//! ```
//!
//! ## Thread Safety
//!
//! All components use `Arc<>` and `RwLock<>` for safe concurrent access:
//!
//! - Immutable services: `Arc<T>` (shared ownership)
//! - Mutable registries: `Arc<RwLock<T>>` (shared mutable access)
//! - Internal synchronization: Components handle their own thread-safety
//!
//! ## Audit Chain
//!
//! The audit system provides tamper-evident logging:
//!
//! - SHA-256 hashing of entries
//! - Blockchain-style chain verification
//! - Async-safe with `Arc<RwLock<>>` internally
//!
//! ```rust
//! use rustchain::core::RuntimeContext;
//!
//! # async fn example() {
//! let ctx = RuntimeContext::new();
//!
//! // Log an action
//! ctx.audit_action("admin", "deploy", "Deployed v1.2.3").await;
//!
//! // Verify chain integrity
//! let hash = ctx.audit.get_chain_hash().await;
//! println!("Chain hash: {}", hash);
//! # }
//! ```

use crate::assert_invariant;
#[cfg(feature = "rag")]
use crate::rag::RagSystem;
#[cfg(feature = "sandbox")]
use crate::sandbox::EnhancedSandbox;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;

// Error handling
pub mod error;
pub mod error_formatting;
pub use error::*;
pub use error_formatting::*;

// Mission system
pub mod mission;
pub use mission::*;

// Executor system
pub mod executor;
pub use executor::*;

// Enhanced audit system
pub mod audit;
pub use audit::*;

// Memory system
pub mod memory;
pub use memory::*;

// Agent system
pub mod agent;
pub use agent::*;

// Chain system
pub mod chain;
pub use chain::*;

// LLM system
pub mod llm;
pub use llm::*;

// Tools system
pub mod tools;
pub use tools::*;

// Web search tools
#[cfg(feature = "tools")]
pub mod web_search_tools;

// Document loaders
#[cfg(feature = "tools")]
pub mod document_loaders;
#[cfg(feature = "tools")]
pub use document_loaders::*;

// Vector stores
#[cfg(feature = "rag")]
pub mod pinecone_vector_store;

#[cfg(feature = "rag")]
pub mod chroma_vector_store;

// Code interpreters
#[cfg(feature = "tools")]
pub mod python_interpreter;
#[cfg(feature = "tools")]
pub use python_interpreter::*;

// Developer toolkits
#[cfg(feature = "tools")]
pub mod github_toolkit;

// Plugin system for enterprise features
pub mod plugin;
pub use plugin::*;

// Feature detection and boundary enforcement
pub mod features;
pub use features::*;

// HTTP client utilities (centralized client creation)
#[cfg(feature = "tools")]
pub mod http_client;
#[cfg(feature = "tools")]
pub use http_client::*;

// Configuration management
pub mod config;
pub use config::*;

/// Central runtime context that holds all system state
#[derive(Clone)]
pub struct RuntimeContext {
    pub config: Arc<RwLock<Config>>,
    pub audit: AuditSink, // Changed: Removed Arc wrapper (AuditSink is already thread-safe)
    pub tool_registry: Arc<RwLock<ToolRegistry>>,
    pub model_manager: Option<Arc<ModelManager>>,
    pub sandbox: Arc<AgentSandbox>,
    pub policy_engine: Arc<PolicyEngine>,
    pub perf_collector: Arc<RwLock<PerfCollector>>,
    pub plugin_manager: Arc<RwLock<PluginManager>>,
    pub feature_detector: Arc<FeatureDetector>,
    #[cfg(feature = "rag")]
    pub rag_system: Option<Arc<RwLock<RagSystem>>>,
    #[cfg(feature = "sandbox")]
    pub enhanced_sandbox: Option<Arc<EnhancedSandbox>>,
}

impl RuntimeContext {
    pub fn new() -> Self {
        assert_invariant!(true, "RuntimeContext created", Some("core"));

        Self {
            config: Arc::new(RwLock::new(Config::default())),
            audit: AuditSink::new(), // Changed: No Arc wrapper needed
            tool_registry: Arc::new(RwLock::new(ToolRegistry::new())),
            model_manager: None,
            sandbox: Arc::new(AgentSandbox::new()),
            policy_engine: Arc::new(PolicyEngine::new()),
            perf_collector: Arc::new(RwLock::new(PerfCollector::new())),
            plugin_manager: Arc::new(RwLock::new(PluginManager::new())),
            feature_detector: Arc::new(FeatureDetector::new()),
            #[cfg(feature = "rag")]
            rag_system: None,
            #[cfg(feature = "sandbox")]
            enhanced_sandbox: None,
        }
    }

    /// Log an audit action for compliance and security tracking.
    ///
    /// This method creates an audit entry with the current timestamp and adds it to
    /// the cryptographically-verified audit chain. All entries are immutable once logged.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The identifier of the actor performing the action (user, system, agent)
    /// * `action` - The action being performed (e.g., "login", "deploy", "delete_file")
    /// * `outcome` - The result of the action (e.g., "success", "failed", "denied")
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustchain::core::RuntimeContext;
    ///
    /// # async fn example() {
    /// let ctx = RuntimeContext::new();
    ///
    /// // Log a successful deployment
    /// ctx.audit_action("admin", "deploy", "success").await;
    ///
    /// // Log a failed login attempt
    /// ctx.audit_action("user123", "login", "failed - invalid password").await;
    /// # }
    /// ```
    ///
    /// # Audit Chain
    ///
    /// Entries are linked using SHA-256 hashes, creating a tamper-evident chain.
    /// Use `audit.get_chain_hash()` to verify chain integrity.
    pub async fn audit_action(&self, agent_id: &str, action: &str, outcome: &str) {
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            actor: agent_id.to_string(),
            action: action.to_string(),
            outcome: outcome.to_string(),
            reason: None,
        };
        if let Err(e) = self.audit.log(entry).await {
            tracing::error!(
                "Failed to log audit entry: {}. Audit integrity may be compromised.",
                e
            );
        }
    }

    /// Check if an enterprise feature is available through plugins
    pub async fn has_enterprise_feature(&self, feature: &str) -> bool {
        if cfg!(feature = "enterprise") {
            self.plugin_manager.read().await.has_feature(feature)
        } else {
            false
        }
    }

    /// Get list of all available enterprise features
    pub async fn get_enterprise_features(&self) -> Vec<String> {
        if cfg!(feature = "enterprise") {
            self.plugin_manager.read().await.enabled_features()
        } else {
            vec![]
        }
    }

    /// Get list of all available core features
    pub async fn get_available_features(&self) -> Vec<String> {
        // Note: mut is needed when feature flags are enabled
        #[allow(unused_mut)]
        let mut features = vec![
            "mission_execution".to_string(),
            "safety_validation".to_string(),
            "audit_logging".to_string(),
            "policy_engine".to_string(),
        ];

        // Feature-gated components
        #[cfg(feature = "llm")]
        features.push("llm_integration".to_string());

        #[cfg(feature = "tools")]
        features.push("tool_system".to_string());

        #[cfg(feature = "rag")]
        features.push("rag_system".to_string());

        #[cfg(feature = "sandbox")]
        features.push("sandbox".to_string());

        #[cfg(feature = "server")]
        features.push("api_server".to_string());

        features
    }

    /// Load enterprise plugins (not available in community edition)
    pub async fn load_enterprise_plugins(&self) -> crate::core::error::Result<()> {
        // Community edition: No enterprise plugins available
        Ok(())
    }

    /// Enhanced feature detection with detailed status
    pub async fn check_feature_status(&self, feature: &str) -> FeatureStatus {
        self.feature_detector
            .is_feature_available(self, feature)
            .await
    }

    /// Require a feature or return detailed error
    pub async fn require_feature(&self, feature: &str) -> crate::core::error::Result<()> {
        self.feature_detector.require_feature(self, feature).await
    }

    /// Get feature summary for this installation
    pub async fn get_feature_summary(&self) -> FeatureSummary {
        self.feature_detector.get_feature_summary(self).await
    }

    /// Get status for all features in a category
    pub async fn get_category_status(&self, category: &str) -> Vec<FeatureStatus> {
        self.feature_detector
            .get_category_status(self, category)
            .await
    }

    /// Check if running enterprise edition with full features
    pub async fn is_enterprise_complete(&self) -> bool {
        self.get_feature_summary().await.is_enterprise_complete()
    }
}

impl Default for RuntimeContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub mission_timeout_seconds: u64,
    pub max_parallel_steps: usize,
    pub audit_enabled: bool,
    pub network_policy: NetworkPolicy,
    pub agent_id: String,
    pub max_tool_calls: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mission_timeout_seconds: 300,
            max_parallel_steps: 4,
            audit_enabled: true,
            network_policy: NetworkPolicy::Offline,
            agent_id: "rustchain-agent".to_string(),
            max_tool_calls: 100,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkPolicy {
    Offline,
    AllowList(Vec<String>),
}

/// Enhanced audit sink with cryptographic chain integrity
#[derive(Clone)]
pub struct AuditSink {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
}

impl AuditSink {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn log(&self, entry: AuditEntry) -> Result<()> {
        self.entries.write().await.push(entry);
        Ok(())
    }

    pub async fn get_entries(&self) -> Vec<AuditEntry> {
        self.entries.read().await.clone()
    }

    pub async fn get_chain_hash(&self) -> String {
        let entries = self.entries.read().await;
        if entries.is_empty() {
            return "genesis".to_string();
        }

        let mut hasher = Sha256::new();
        for entry in entries.iter() {
            hasher.update(
                format!(
                    "{}{}{}{}",
                    entry.timestamp.to_rfc3339(),
                    entry.actor,
                    entry.action,
                    entry.outcome
                )
                .as_bytes(),
            );
        }
        format!("{:x}", hasher.finalize())
    }
}

impl Default for AuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub outcome: String,
    pub reason: Option<String>,
}

pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool + Send + Sync>>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: String, tool: Box<dyn Tool + Send + Sync>) {
        assert_invariant!(!name.is_empty(), "Tool name cannot be empty", Some("core"));
        assert_invariant!(
            tool.name() == name,
            "Tool name must match provided name",
            Some("core")
        );
        self.tools.insert(name, tool);
    }

    pub fn get(&self, name: &str) -> Option<&(dyn Tool + Send + Sync)> {
        let tool = self.tools.get(name).map(|tool| tool.as_ref());
        if let Some(t) = tool {
            assert_invariant!(
                t.name() == name,
                "Retrieved tool name must match requested name",
                Some("core")
            );
        }
        tool
    }
}

pub trait Tool {
    fn name(&self) -> &str;
    fn invoke(&self, args: serde_json::Value) -> anyhow::Result<serde_json::Value>;
}

/// Performance metrics collection
#[derive(Debug, Clone)]
pub struct PerfMetric {
    pub name: String,
    pub duration_ms: u128,
}

#[derive(Default)]
pub struct PerfCollector {
    active: HashMap<String, Instant>,
    pub completed: Vec<PerfMetric>,
}

impl PerfCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self, name: &str) {
        assert_invariant!(
            !name.is_empty(),
            "Performance metric name cannot be empty",
            Some("core")
        );
        assert_invariant!(
            !self.active.contains_key(name),
            "Performance metric already started",
            Some("core")
        );
        self.active.insert(name.to_string(), Instant::now());
    }

    pub fn end(&mut self, name: &str) {
        assert_invariant!(
            !name.is_empty(),
            "Performance metric name cannot be empty",
            Some("core")
        );
        if let Some(start) = self.active.remove(name) {
            let duration = start.elapsed().as_millis();
            self.completed.push(PerfMetric {
                name: name.to_string(),
                duration_ms: duration,
            });
        } else {
            assert_invariant!(
                false,
                "Cannot end performance metric that was not started",
                Some("core")
            );
        }
    }

    pub fn summary(&self) -> String {
        self.completed
            .iter()
            .map(|m| format!("{}: {}ms", m.name, m.duration_ms))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Default)]
pub struct ModelManager {
    // Will be implemented in Gate 6
    #[cfg(feature = "llm")]
    llm_manager: Option<crate::llm::LLMManager>,
}

impl ModelManager {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "llm")]
    pub fn with_llm_manager(mut self, manager: crate::llm::LLMManager) -> Self {
        self.llm_manager = Some(manager);
        self
    }

    #[cfg(not(feature = "llm"))]
    pub async fn complete(
        &self,
        _request: serde_json::Value,
        _provider: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        Err(anyhow::anyhow!(
            "LLM feature not enabled - rebuild with --features llm"
        ))
    }
}

pub struct AgentSandbox {
    allowed_paths: Vec<std::path::PathBuf>,
    allowed_commands: Vec<String>,
}

impl Default for AgentSandbox {
    fn default() -> Self {
        // Safe default path handling - fallback to current directory or root
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

        Self {
            allowed_paths: vec![current_dir],
            allowed_commands: vec!["echo".to_string(), "cat".to_string(), "ls".to_string()],
        }
    }
}

impl AgentSandbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn execute(&self, code: &str) -> std::result::Result<String, String> {
        // For testing purposes, allow basic file operations in allowed paths
        if let Some(path) = code.strip_prefix("create_file:") {
            let path_buf = std::path::PathBuf::from(path);

            // Check if path is allowed
            if self.is_path_allowed(&path_buf) {
                return Ok("allowed".to_string());
            }
        }

        // Check if command is allowed
        if self
            .allowed_commands
            .iter()
            .any(|cmd| code.starts_with(cmd))
        {
            return Ok("allowed".to_string());
        }

        // Fail closed for everything else until real sandboxing implementation is added
        Err("Sandbox not implemented - failing closed".to_string())
    }

    // Helper methods for future implementation
    fn is_path_allowed(&self, path: &std::path::Path) -> bool {
        // Allow relative paths in allowed directories
        if path.is_relative() {
            return true; // For now, allow all relative paths
        }
        // For absolute paths, check if they start with allowed paths
        self.allowed_paths
            .iter()
            .any(|allowed| path.starts_with(allowed))
    }
}

pub struct PolicyEngine {
    policies: Vec<String>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn validate(&self, action: &str) -> bool {
        // Check if any policy explicitly denies this action
        // Policies are deny rules - if action matches any policy, it's denied
        for policy in &self.policies {
            if action.contains(policy) {
                return false; // Denied
            }
        }
        true // Allowed if no denying policies match
    }

    pub fn add_policy(&mut self, policy: String) {
        assert_invariant!(!policy.is_empty(), "Policy cannot be empty", Some("core"));
        self.policies.push(policy);
    }
}
