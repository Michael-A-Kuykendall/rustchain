use crate::core::error::{ExecutionError, RustChainError};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
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

    /// Create a new registry with default tools registered
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register_defaults();
        registry
    }

    /// Register default tools based on available features and environment
    pub fn register_defaults(&mut self) {
        #[cfg(feature = "tools")]
        {
            tracing::info!("Registering tools feature components...");

            // Register web search tools if environment variables are available
            crate::core::web_search_tools::register_web_search_tools(self);

            // Register document loaders
            tracing::info!("About to register document loaders...");
            crate::core::document_loaders::register_document_loaders(self);

            // Register code interpreters
            crate::core::python_interpreter::register_python_interpreter(self);

            // Register developer toolkits
            crate::core::github_toolkit::register_github_client(self);

            // Register HTTP client for web requests
            self.register_http_tool();
        }

        #[cfg(feature = "rag")]
        {
            // Register vector stores if environment variables are available
            crate::core::pinecone_vector_store::register_pinecone_vector_store(self);
            crate::core::chroma_vector_store::register_chroma_vector_store(self);
        }
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|tool| tool.as_ref())
    }

    pub fn list(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    pub fn tools_by_capability(&self, cap: ToolCapability) -> Vec<&dyn Tool> {
        self.tools
            .values()
            .filter(|tool| tool.capabilities().contains(&cap))
            .map(|tool| tool.as_ref())
            .collect()
    }

    pub fn count(&self) -> usize {
        self.tools.len()
    }

    pub fn clear(&mut self) {
        self.tools.clear();
    }

    pub fn remove(&mut self, name: &str) -> Option<Box<dyn Tool>> {
        self.tools.remove(name)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    pub fn get_tool(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|tool| tool.as_ref())
    }

    pub fn get_capabilities(&self, name: &str) -> Option<Vec<ToolCapability>> {
        self.tools.get(name).map(|tool| tool.capabilities())
    }

    /// Register HTTP tool for web requests
    fn register_http_tool(&mut self) {
        self.register(Box::new(HttpToolBridge::new()));
        tracing::info!("Registered HTTP tool for ToolRegistry");
    }
}

/// Bridge adapter that allows ToolManager's HttpTool to work with ToolRegistry
#[derive(Default)]
pub struct HttpToolBridge;

impl HttpToolBridge {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Tool for HttpToolBridge {
    fn name(&self) -> &'static str {
        "http"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::NetworkAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        #[cfg(feature = "tools")]
        {
            use crate::core::RuntimeContext;
            use crate::tools::{HttpTool, ToolCall, ToolExecutor};

            // Parse input as JSON parameters
            let params: serde_json::Value = serde_json::from_str(input).map_err(|e| {
                RustChainError::Execution(ExecutionError::step_failed(
                    "http",
                    "parse_input",
                    format!("Invalid JSON input: {}", e),
                ))
            })?;

            // Create a ToolCall from the parameters
            let tool_call = ToolCall::new("http".to_string(), params);

            // Create a minimal RuntimeContext
            let context = RuntimeContext::new();

            // Execute using the actual HttpTool
            let http_tool = HttpTool;
            let result = http_tool.execute(tool_call, &context).await.map_err(|e| {
                RustChainError::Execution(ExecutionError::step_failed(
                    "http",
                    "http_request",
                    format!("HTTP request failed: {}", e),
                ))
            })?;

            // Convert tools::ToolResult to core::ToolResult
            if result.success {
                Ok(ToolResult::StructuredJson(result.output))
            } else {
                Ok(ToolResult::Error(
                    result
                        .error
                        .unwrap_or_else(|| "HTTP request failed".to_string()),
                ))
            }
        }

        #[cfg(not(feature = "tools"))]
        {
            let _ = input; // Suppress unused parameter warning
            Err(RustChainError::Execution(ExecutionError::step_failed(
                "http",
                "feature_disabled",
                "Tools feature not enabled".to_string(),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::json;

    // Mock tools for testing
    struct MockBasicTool {
        name: &'static str,
        result: ToolResult,
        should_fail: bool,
    }

    impl MockBasicTool {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                result: ToolResult::Success("mock success".to_string()),
                should_fail: false,
            }
        }

        fn with_result(mut self, result: ToolResult) -> Self {
            self.result = result;
            self
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl Tool for MockBasicTool {
        fn name(&self) -> &'static str {
            self.name
        }

        fn capabilities(&self) -> Vec<ToolCapability> {
            vec![ToolCapability::Basic]
        }

        async fn invoke(&self, _input: &str) -> Result<ToolResult, RustChainError> {
            if self.should_fail {
                Err(RustChainError::Tool(
                    crate::core::error::ToolError::execution_failed(
                        self.name,
                        "Mock tool failure".to_string(),
                    ),
                ))
            } else {
                Ok(self.result.clone())
            }
        }
    }

    struct MockNetworkTool;

    #[async_trait]
    impl Tool for MockNetworkTool {
        fn name(&self) -> &'static str {
            "network_tool"
        }

        fn capabilities(&self) -> Vec<ToolCapability> {
            vec![ToolCapability::NetworkAccess, ToolCapability::Basic]
        }

        async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
            if input.contains("fail") {
                Ok(ToolResult::Error("Network operation failed".to_string()))
            } else {
                Ok(ToolResult::StructuredJson(json!({
                    "status": "success",
                    "data": "network response"
                })))
            }
        }
    }

    struct MockSystemTool;

    #[async_trait]
    impl Tool for MockSystemTool {
        fn name(&self) -> &'static str {
            "system_tool"
        }

        fn capabilities(&self) -> Vec<ToolCapability> {
            vec![ToolCapability::SystemAccess, ToolCapability::WasmPlugin]
        }

        async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
            Ok(ToolResult::Success(format!("System executed: {}", input)))
        }
    }

    #[tokio::test]
    async fn test_tool_result_variants() {
        // Test all ToolResult variants
        let success = ToolResult::Success("success message".to_string());
        let structured = ToolResult::StructuredJson(json!({"key": "value"}));
        let error = ToolResult::Error("error message".to_string());

        // Test Debug implementation
        assert!(format!("{:?}", success).contains("Success"));
        assert!(format!("{:?}", structured).contains("StructuredJson"));
        assert!(format!("{:?}", error).contains("Error"));

        // Verify content
        match success {
            ToolResult::Success(msg) => assert_eq!(msg, "success message"),
            _ => panic!("Expected Success variant"),
        }

        match structured {
            ToolResult::StructuredJson(val) => {
                assert_eq!(val["key"], "value");
            }
            _ => panic!("Expected StructuredJson variant"),
        }

        match error {
            ToolResult::Error(msg) => assert_eq!(msg, "error message"),
            _ => panic!("Expected Error variant"),
        }
    }

    #[test]
    fn test_tool_capability_variants() {
        // Test all ToolCapability variants
        let basic = ToolCapability::Basic;
        let wasm = ToolCapability::WasmPlugin;
        let system = ToolCapability::SystemAccess;
        let network = ToolCapability::NetworkAccess;

        // Test Debug, Clone, PartialEq, Eq, Hash implementations
        assert_eq!(basic.clone(), ToolCapability::Basic);
        assert_ne!(basic, wasm);
        assert_ne!(system, network);

        // Test in HashMap (Hash trait)
        let mut cap_map = HashMap::new();
        cap_map.insert(basic.clone(), "basic");
        cap_map.insert(wasm.clone(), "wasm");
        cap_map.insert(system.clone(), "system");
        cap_map.insert(network.clone(), "network");

        assert_eq!(cap_map.get(&basic), Some(&"basic"));
        assert_eq!(cap_map.get(&wasm), Some(&"wasm"));
        assert_eq!(cap_map.len(), 4);
    }

    #[tokio::test]
    async fn test_mock_basic_tool() {
        let tool = MockBasicTool::new("test_basic");

        assert_eq!(tool.name(), "test_basic");
        assert_eq!(tool.capabilities(), vec![ToolCapability::Basic]);

        let result = tool.invoke("test input").await.unwrap();
        match result {
            ToolResult::Success(msg) => assert_eq!(msg, "mock success"),
            _ => panic!("Expected Success result"),
        }
    }

    #[tokio::test]
    async fn test_mock_basic_tool_with_custom_result() {
        let tool = MockBasicTool::new("custom_tool")
            .with_result(ToolResult::StructuredJson(json!({"custom": "data"})));

        let result = tool.invoke("input").await.unwrap();
        match result {
            ToolResult::StructuredJson(val) => {
                assert_eq!(val["custom"], "data");
            }
            _ => panic!("Expected StructuredJson result"),
        }
    }

    #[tokio::test]
    async fn test_mock_basic_tool_failure() {
        let tool = MockBasicTool::new("failing_tool").with_failure();

        let result = tool.invoke("input").await;
        assert!(result.is_err());

        match result {
            Err(RustChainError::Tool(e)) => {
                assert!(e.to_string().contains("Mock tool failure"));
            }
            _ => panic!("Expected Tool error"),
        }
    }

    #[tokio::test]
    async fn test_mock_network_tool() {
        let tool = MockNetworkTool;

        assert_eq!(tool.name(), "network_tool");
        assert_eq!(
            tool.capabilities(),
            vec![ToolCapability::NetworkAccess, ToolCapability::Basic]
        );

        // Test success case
        let result = tool.invoke("success").await.unwrap();
        match result {
            ToolResult::StructuredJson(val) => {
                assert_eq!(val["status"], "success");
                assert_eq!(val["data"], "network response");
            }
            _ => panic!("Expected StructuredJson result"),
        }

        // Test error case
        let result = tool.invoke("fail").await.unwrap();
        match result {
            ToolResult::Error(msg) => {
                assert_eq!(msg, "Network operation failed");
            }
            _ => panic!("Expected Error result"),
        }
    }

    #[tokio::test]
    async fn test_mock_system_tool() {
        let tool = MockSystemTool;

        assert_eq!(tool.name(), "system_tool");
        assert_eq!(
            tool.capabilities(),
            vec![ToolCapability::SystemAccess, ToolCapability::WasmPlugin]
        );

        let result = tool.invoke("system command").await.unwrap();
        match result {
            ToolResult::Success(msg) => {
                assert_eq!(msg, "System executed: system command");
            }
            _ => panic!("Expected Success result"),
        }
    }

    #[tokio::test]
    async fn test_tool_registry_basic_operations() {
        let mut registry = ToolRegistry::new();

        // Test empty registry
        assert_eq!(registry.count(), 0);
        assert!(registry.list().is_empty());
        assert!(!registry.contains("nonexistent"));

        // Register a tool
        registry.register(Box::new(MockBasicTool::new("tool1")));
        assert_eq!(registry.count(), 1);
        assert!(registry.contains("tool1"));

        // Test list
        let tools = registry.list();
        assert_eq!(tools.len(), 1);
        assert!(tools.contains(&"tool1".to_string()));

        // Test get
        let tool = registry.get("tool1");
        assert!(tool.is_some());
        assert_eq!(tool.unwrap().name(), "tool1");

        // Test get non-existent
        assert!(registry.get("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_tool_registry_multiple_tools() {
        let mut registry = ToolRegistry::new();

        // Register multiple tools
        registry.register(Box::new(MockBasicTool::new("basic1")));
        registry.register(Box::new(MockBasicTool::new("basic2")));
        registry.register(Box::new(MockNetworkTool));
        registry.register(Box::new(MockSystemTool));

        assert_eq!(registry.count(), 4);

        let tools = registry.list();
        assert_eq!(tools.len(), 4);
        assert!(tools.contains(&"basic1".to_string()));
        assert!(tools.contains(&"basic2".to_string()));
        assert!(tools.contains(&"network_tool".to_string()));
        assert!(tools.contains(&"system_tool".to_string()));
    }

    #[test]
    fn test_tool_registry_tools_by_capability() {
        let mut registry = ToolRegistry::new();

        registry.register(Box::new(MockBasicTool::new("basic1")));
        registry.register(Box::new(MockBasicTool::new("basic2")));
        registry.register(Box::new(MockNetworkTool));
        registry.register(Box::new(MockSystemTool));

        // Test Basic capability (should include basic1, basic2, network_tool)
        let basic_tools = registry.tools_by_capability(ToolCapability::Basic);
        assert_eq!(basic_tools.len(), 3);

        // Test NetworkAccess capability (should include only network_tool)
        let network_tools = registry.tools_by_capability(ToolCapability::NetworkAccess);
        assert_eq!(network_tools.len(), 1);
        assert_eq!(network_tools[0].name(), "network_tool");

        // Test SystemAccess capability (should include only system_tool)
        let system_tools = registry.tools_by_capability(ToolCapability::SystemAccess);
        assert_eq!(system_tools.len(), 1);
        assert_eq!(system_tools[0].name(), "system_tool");

        // Test WasmPlugin capability (should include only system_tool)
        let wasm_tools = registry.tools_by_capability(ToolCapability::WasmPlugin);
        assert_eq!(wasm_tools.len(), 1);
        assert_eq!(wasm_tools[0].name(), "system_tool");
    }

    #[test]
    fn test_tool_registry_get_capabilities() {
        let mut registry = ToolRegistry::new();

        registry.register(Box::new(MockBasicTool::new("basic_tool")));
        registry.register(Box::new(MockNetworkTool));

        // Test getting capabilities for existing tools
        let basic_caps = registry.get_capabilities("basic_tool");
        assert!(basic_caps.is_some());
        assert_eq!(basic_caps.unwrap(), vec![ToolCapability::Basic]);

        let network_caps = registry.get_capabilities("network_tool");
        assert!(network_caps.is_some());
        assert_eq!(
            network_caps.unwrap(),
            vec![ToolCapability::NetworkAccess, ToolCapability::Basic]
        );

        // Test getting capabilities for non-existent tool
        let nonexistent_caps = registry.get_capabilities("nonexistent");
        assert!(nonexistent_caps.is_none());
    }

    #[test]
    fn test_tool_registry_remove() {
        let mut registry = ToolRegistry::new();

        registry.register(Box::new(MockBasicTool::new("removable_tool")));
        registry.register(Box::new(MockBasicTool::new("permanent_tool")));

        assert_eq!(registry.count(), 2);
        assert!(registry.contains("removable_tool"));

        // Remove existing tool
        let removed = registry.remove("removable_tool");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "removable_tool");

        assert_eq!(registry.count(), 1);
        assert!(!registry.contains("removable_tool"));
        assert!(registry.contains("permanent_tool"));

        // Try to remove non-existent tool
        let not_removed = registry.remove("nonexistent");
        assert!(not_removed.is_none());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_tool_registry_clear() {
        let mut registry = ToolRegistry::new();

        registry.register(Box::new(MockBasicTool::new("tool1")));
        registry.register(Box::new(MockBasicTool::new("tool2")));
        registry.register(Box::new(MockNetworkTool));

        assert_eq!(registry.count(), 3);

        registry.clear();

        assert_eq!(registry.count(), 0);
        assert!(registry.list().is_empty());
        assert!(!registry.contains("tool1"));
        assert!(!registry.contains("tool2"));
        assert!(!registry.contains("network_tool"));
    }

    #[test]
    fn test_tool_registry_overwrite() {
        let mut registry = ToolRegistry::new();

        // Register a tool
        registry.register(Box::new(MockBasicTool::new("tool1")));
        assert_eq!(registry.count(), 1);

        // Register another tool with the same name (should overwrite)
        registry.register(Box::new(MockBasicTool::new("tool1")));
        assert_eq!(registry.count(), 1);

        let tool = registry.get("tool1").unwrap();
        assert_eq!(tool.name(), "tool1");
    }

    #[tokio::test]
    async fn test_tool_trait_object_usage() {
        // Test using Tool as a trait object
        let tool: Box<dyn Tool> = Box::new(MockBasicTool::new("trait_object_tool"));

        assert_eq!(tool.name(), "trait_object_tool");
        assert_eq!(tool.capabilities(), vec![ToolCapability::Basic]);

        let result = tool.invoke("test").await.unwrap();
        match result {
            ToolResult::Success(msg) => assert_eq!(msg, "mock success"),
            _ => panic!("Expected Success result"),
        }
    }

    #[tokio::test]
    async fn test_multiple_capability_tool() {
        let tool = MockNetworkTool;
        let capabilities = tool.capabilities();

        assert_eq!(capabilities.len(), 2);
        assert!(capabilities.contains(&ToolCapability::NetworkAccess));
        assert!(capabilities.contains(&ToolCapability::Basic));

        // Test that the tool appears in searches for both capabilities
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(MockNetworkTool));

        let basic_tools = registry.tools_by_capability(ToolCapability::Basic);
        assert_eq!(basic_tools.len(), 1);

        let network_tools = registry.tools_by_capability(ToolCapability::NetworkAccess);
        assert_eq!(network_tools.len(), 1);

        assert_eq!(basic_tools[0].name(), network_tools[0].name());
    }

    #[tokio::test]
    async fn test_tool_result_cloning() {
        // Test ToolResult can be cloned (needed for MockBasicTool)
        let original = ToolResult::Success("cloneable".to_string());
        let cloned = original.clone();

        match (original, cloned) {
            (ToolResult::Success(orig), ToolResult::Success(clone)) => {
                assert_eq!(orig, clone);
            }
            _ => panic!("Clone failed"),
        }

        let json_original = ToolResult::StructuredJson(json!({"clone": "test"}));
        let json_cloned = json_original.clone();

        match (json_original, json_cloned) {
            (ToolResult::StructuredJson(orig), ToolResult::StructuredJson(clone)) => {
                assert_eq!(orig, clone);
            }
            _ => panic!("JSON clone failed"),
        }

        let error_original = ToolResult::Error("cloneable error".to_string());
        let error_cloned = error_original.clone();

        match (error_original, error_cloned) {
            (ToolResult::Error(orig), ToolResult::Error(clone)) => {
                assert_eq!(orig, clone);
            }
            _ => panic!("Error clone failed"),
        }
    }

    #[tokio::test]
    async fn test_edge_cases() {
        let mut registry = ToolRegistry::new();

        // Test with empty tool name (edge case)
        struct EmptyNameTool;

        #[async_trait]
        impl Tool for EmptyNameTool {
            fn name(&self) -> &'static str {
                ""
            }

            fn capabilities(&self) -> Vec<ToolCapability> {
                vec![]
            }

            async fn invoke(&self, _input: &str) -> Result<ToolResult, RustChainError> {
                Ok(ToolResult::Success("empty name tool".to_string()))
            }
        }

        registry.register(Box::new(EmptyNameTool));
        assert_eq!(registry.count(), 1);
        assert!(registry.contains(""));

        let tool = registry.get("").unwrap();
        assert_eq!(tool.name(), "");
        assert!(tool.capabilities().is_empty());

        // Test tool with no capabilities
        let no_cap_tools = registry.tools_by_capability(ToolCapability::Basic);
        assert_eq!(no_cap_tools.len(), 0);
    }

    #[test]
    fn test_large_registry_performance() {
        let mut registry = ToolRegistry::new();

        // Register many tools to test performance
        for i in 0..100 {
            registry.register(Box::new(
                MockBasicTool::new("tool").with_result(ToolResult::Success(format!("Tool {}", i))),
            ));
        }

        // The registry should overwrite tools with the same name
        assert_eq!(registry.count(), 1); // Only one tool named "tool"

        // Register tools with unique names
        registry.clear();
        for i in 0..50 {
            let _tool_name = format!("tool_{}", i);
            // Since MockBasicTool only accepts &'static str, we'll create a different approach
            struct UniqueNameTool {
                index: usize,
            }

            #[async_trait]
            impl Tool for UniqueNameTool {
                fn name(&self) -> &'static str {
                    // This is a limitation - we can't easily create unique static strings
                    // Use fixed name to test registry behavior
                    "unique_tool"
                }

                fn capabilities(&self) -> Vec<ToolCapability> {
                    vec![ToolCapability::Basic]
                }

                async fn invoke(&self, _input: &str) -> Result<ToolResult, RustChainError> {
                    Ok(ToolResult::Success(format!("Tool {}", self.index)))
                }
            }

            registry.register(Box::new(UniqueNameTool { index: i }));
        }

        // All tools have the same name, so only 1 should remain
        assert_eq!(registry.count(), 1);

        // Test that operations still work efficiently
        let tools = registry.list();
        assert_eq!(tools.len(), 1);

        let basic_tools = registry.tools_by_capability(ToolCapability::Basic);
        assert_eq!(basic_tools.len(), 1);
    }
}
