#[allow(unused_imports)]
use crate::core::error::{ExecutionError, LlmError, RustChainError};
#[cfg(feature = "tools")]
use crate::core::ToolError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[async_trait]
pub trait ChainNode: Send + Sync {
    async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError>;
    fn name(&self) -> &str;
    fn node_type(&self) -> &str;
}

#[derive(Clone, Debug, Default)]
pub struct ChainContext {
    pub vars: HashMap<String, String>,
    pub history: Vec<ChainEvent>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ChainContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.vars.insert(key.to_string(), value.to_string());
        self.history.push(ChainEvent::VarSet {
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }

    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.vars
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    pub fn record_event(&mut self, event: ChainEvent) {
        self.history.push(event);
    }

    pub fn get_history(&self) -> &[ChainEvent] {
        &self.history
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChainEvent {
    NodeExecuted { name: String, success: bool },
    VarSet { key: String, value: String },
    Error { message: String },
    LLMCall { prompt: String, response: String },
    ToolCall { tool: String, result: String },
}

/// Sequential chain executor
pub struct SequentialChain {
    steps: Vec<Box<dyn ChainNode>>,
    name: String,
    halt_on_error: bool,
}

impl SequentialChain {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            steps: Vec::new(),
            name: name.into(),
            halt_on_error: true,
        }
    }

    pub fn with_halt_on_error(mut self, halt: bool) -> Self {
        self.halt_on_error = halt;
        self
    }

    pub fn add(&mut self, step: Box<dyn ChainNode>) {
        info!("Adding step '{}' to chain '{}'", step.name(), self.name);
        self.steps.push(step);
    }

    pub async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
        info!(
            "Running sequential chain '{}' with {} steps",
            self.name,
            self.steps.len()
        );

        for (i, step) in self.steps.iter().enumerate() {
            debug!(
                "Executing step {}/{}: {}",
                i + 1,
                self.steps.len(),
                step.name()
            );

            match step.run(context).await {
                Ok(_) => {
                    context.record_event(ChainEvent::NodeExecuted {
                        name: step.name().to_string(),
                        success: true,
                    });
                }
                Err(e) => {
                    warn!("Step '{}' failed: {}", step.name(), e);
                    context.record_event(ChainEvent::NodeExecuted {
                        name: step.name().to_string(),
                        success: false,
                    });
                    context.record_event(ChainEvent::Error {
                        message: e.to_string(),
                    });

                    if self.halt_on_error {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }
}

/// LLM Chain - combines prompt template with LLM call
pub struct LLMChain {
    name: String,
    prompt_template: String,
    output_key: String,
    model: Option<String>,
    temperature: Option<f32>,
}

impl LLMChain {
    pub fn new(name: impl Into<String>, prompt_template: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            prompt_template: prompt_template.into(),
            output_key: "llm_output".to_string(),
            model: None,
            temperature: None,
        }
    }

    pub fn with_output_key(mut self, key: impl Into<String>) -> Self {
        self.output_key = key.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    pub fn with_temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp);
        self
    }

    fn format_prompt(&self, context: &ChainContext) -> String {
        let mut prompt = self.prompt_template.clone();

        // Replace variables in template
        for (key, value) in &context.vars {
            let placeholder = format!("{{{{{}}}}}", key);
            prompt = prompt.replace(&placeholder, value);
        }

        prompt
    }
}

#[async_trait]
impl ChainNode for LLMChain {
    async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
        let prompt = self.format_prompt(context);

        debug!("LLM chain '{}' calling with prompt: {}", self.name, prompt);

        #[cfg(feature = "llm")]
        {
            use crate::llm::{create_default_llm_manager, ChatMessage, LLMRequest, MessageRole};

            let manager = create_default_llm_manager()
                .map_err(|_e| RustChainError::Llm(LlmError::service_unavailable("default")))?;

            let request = LLMRequest {
                messages: vec![ChatMessage {
                    role: MessageRole::User,
                    content: prompt.clone(),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                }],
                model: self.model.clone(),
                temperature: self.temperature,
                max_tokens: Some(1000),
                stream: false,
                tools: None,
                metadata: HashMap::new(),
            };

            let response = manager
                .complete(request, None)
                .await
                .map_err(|e| RustChainError::Llm(LlmError::response_error(e.to_string())))?;

            context.set(&self.output_key, &response.content);
            context.record_event(ChainEvent::LLMCall {
                prompt,
                response: response.content,
            });

            Ok(())
        }

        #[cfg(not(feature = "llm"))]
        {
            // LLM feature is disabled - return clear error instead of fake data
            Err(RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message:
                        "LLM feature not enabled. Rebuild with --features llm to use LLMChain."
                            .to_string(),
                },
            ))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn node_type(&self) -> &str {
        "LLMChain"
    }
}

/// Tool Chain - executes a tool with parameters from context
pub struct ToolChain {
    name: String,
    tool_name: String,
    param_mapping: HashMap<String, String>, // context_key -> param_key
    output_key: String,
}

impl ToolChain {
    pub fn new(name: impl Into<String>, tool_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tool_name: tool_name.into(),
            param_mapping: HashMap::new(),
            output_key: "tool_output".to_string(),
        }
    }

    pub fn with_param(
        mut self,
        param_key: impl Into<String>,
        context_key: impl Into<String>,
    ) -> Self {
        self.param_mapping
            .insert(context_key.into(), param_key.into());
        self
    }

    pub fn with_output_key(mut self, key: impl Into<String>) -> Self {
        self.output_key = key.into();
        self
    }
}

#[async_trait]
impl ChainNode for ToolChain {
    async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
        #[cfg(feature = "tools")]
        {
            use crate::core::RuntimeContext;
            use crate::tools::{create_default_tool_manager, ToolCall};

            // Build parameters from context
            let mut params = serde_json::Map::new();
            for (context_key, param_key) in &self.param_mapping {
                if let Some(value) = context.get(context_key) {
                    params.insert(param_key.clone(), serde_json::Value::String(value));
                }
            }

            let tool_call =
                ToolCall::new(self.tool_name.clone(), serde_json::Value::Object(params));

            let tool_manager = create_default_tool_manager();
            let runtime_context = RuntimeContext::new();

            let result = tool_manager
                .execute_tool(tool_call, &runtime_context)
                .await
                .map_err(|e| {
                    RustChainError::Tool(ToolError::execution_failed("unknown", e.to_string()))
                })?;

            // Serialize output - propagate error instead of silently swallowing
            let output = serde_json::to_string(&result.output).map_err(|e| {
                tracing::error!(
                    tool = %self.tool_name,
                    error = %e,
                    "Failed to serialize tool output - this indicates a bug in the tool"
                );
                RustChainError::Tool(ToolError::execution_failed(
                    &self.tool_name,
                    format!("Failed to serialize tool output: {}", e),
                ))
            })?;

            context.set(&self.output_key, &output);

            context.record_event(ChainEvent::ToolCall {
                tool: self.tool_name.clone(),
                result: output,
            });

            if !result.success {
                return Err(RustChainError::Tool(ToolError::execution_failed(
                    &self.tool_name,
                    result
                        .error
                        .unwrap_or_else(|| "Tool execution failed".to_string()),
                )));
            }

            Ok(())
        }

        #[cfg(not(feature = "tools"))]
        {
            return Err(RustChainError::Tool(
                crate::core::error::ToolError::not_found(format!(
                    "Tool '{}' requires 'tools' feature to be enabled",
                    self.tool_name
                )),
            ));
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn node_type(&self) -> &str {
        "ToolChain"
    }
}

/// Transform Chain - applies a transformation function to context variables
pub struct TransformChain {
    name: String,
    input_key: String,
    output_key: String,
    transform: Box<dyn Fn(&str) -> String + Send + Sync>,
}

impl TransformChain {
    pub fn new<F>(name: String, input_key: String, output_key: String, transform: F) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        Self {
            name,
            input_key,
            output_key,
            transform: Box::new(transform),
        }
    }
}

#[async_trait]
impl ChainNode for TransformChain {
    async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
        let input = context.get(&self.input_key).ok_or_else(|| {
            RustChainError::Exec(format!(
                "Input key '{}' not found in context",
                self.input_key
            ))
        })?;

        let output = (self.transform)(&input);
        context.set(&self.output_key, &output);

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn node_type(&self) -> &str {
        "TransformChain"
    }
}

/// Router Chain - conditionally executes different chains based on input
pub struct RouterChain {
    name: String,
    router_fn: Box<dyn Fn(&ChainContext) -> String + Send + Sync>,
    routes: HashMap<String, Box<dyn ChainNode>>,
    default_route: Option<Box<dyn ChainNode>>,
}

impl RouterChain {
    pub fn new<F>(name: String, router_fn: F) -> Self
    where
        F: Fn(&ChainContext) -> String + Send + Sync + 'static,
    {
        Self {
            name,
            router_fn: Box::new(router_fn),
            routes: HashMap::new(),
            default_route: None,
        }
    }

    pub fn add_route(mut self, key: impl Into<String>, chain: Box<dyn ChainNode>) -> Self {
        self.routes.insert(key.into(), chain);
        self
    }

    pub fn with_default(mut self, chain: Box<dyn ChainNode>) -> Self {
        self.default_route = Some(chain);
        self
    }
}

#[async_trait]
impl ChainNode for RouterChain {
    async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
        let route_key = (self.router_fn)(context);

        debug!("Router '{}' selected route: {}", self.name, route_key);

        if let Some(chain) = self.routes.get(&route_key) {
            chain.run(context).await
        } else if let Some(default) = &self.default_route {
            debug!("Using default route for '{}'", self.name);
            default.run(context).await
        } else {
            Err(RustChainError::Exec(format!(
                "No route found for key '{}' and no default route",
                route_key
            )))
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn node_type(&self) -> &str {
        "RouterChain"
    }
}

/// Map-Reduce Chain - applies a chain to multiple inputs in parallel
pub struct MapReduceChain {
    name: String,
    map_chain: Box<dyn ChainNode>,
    reduce_fn: Box<dyn Fn(Vec<String>) -> String + Send + Sync>,
    input_key: String,
    output_key: String,
}

impl MapReduceChain {
    pub fn new<F>(
        name: String,
        map_chain: Box<dyn ChainNode>,
        reduce_fn: F,
        input_key: String,
        output_key: String,
    ) -> Self
    where
        F: Fn(Vec<String>) -> String + Send + Sync + 'static,
    {
        Self {
            name,
            map_chain,
            reduce_fn: Box::new(reduce_fn),
            input_key,
            output_key,
        }
    }
}

#[async_trait]
impl ChainNode for MapReduceChain {
    async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
        let input = context.get(&self.input_key).ok_or_else(|| {
            RustChainError::Execution(ExecutionError::step_failed(
                "map_reduce_input",
                "unknown",
                format!("Input key '{}' not found", self.input_key),
            ))
        })?;

        // Split input (assuming newline separated for simplicity)
        let chunks: Vec<&str> = input.split('\n').filter(|s| !s.is_empty()).collect();
        let mut results = Vec::new();

        for chunk in chunks {
            let mut chunk_context = ChainContext::new();
            chunk_context.set("input", chunk);

            self.map_chain.run(&mut chunk_context).await?;

            if let Some(result) = chunk_context.get("output") {
                results.push(result);
            }
        }

        let reduced = (self.reduce_fn)(results);
        context.set(&self.output_key, &reduced);

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn node_type(&self) -> &str {
        "MapReduceChain"
    }
}

/// Create common chain patterns
pub mod patterns {
    use super::*;

    /// Create a summarization chain
    pub fn summarization_chain() -> SequentialChain {
        let mut chain = SequentialChain::new("summarization".to_string());

        chain.add(Box::new(
            LLMChain::new(
                "summarize".to_string(),
                "Please summarize the following text:\n\n{{input}}".to_string(),
            )
            .with_output_key("summary".to_string()),
        ));

        chain
    }

    /// Create a question-answering chain
    pub fn qa_chain() -> SequentialChain {
        let mut chain = SequentialChain::new("qa".to_string());

        chain.add(Box::new(
            LLMChain::new(
                "answer".to_string(),
                "Context: {{context}}\n\nQuestion: {{question}}\n\nAnswer:".to_string(),
            )
            .with_output_key("answer".to_string()),
        ));

        chain
    }

    /// Create a translation chain
    pub fn translation_chain(target_language: &str) -> SequentialChain {
        let mut chain = SequentialChain::new("translation".to_string());

        chain.add(Box::new(
            LLMChain::new(
                "translate".to_string(),
                format!(
                    "Translate the following text to {}:\n\n{{{{input}}}}",
                    target_language
                ),
            )
            .with_output_key("translation".to_string()),
        ));

        chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // tokio_test not needed for these tests

    #[tokio::test]
    async fn test_chain_context_basic_operations() {
        let mut context = ChainContext::new();

        // Test set and get
        context.set("key1", "value1");
        assert_eq!(context.get("key1"), Some("value1".to_string()));
        assert_eq!(context.get("nonexistent"), None);

        // Test get_or with default
        assert_eq!(context.get_or("key1", "default"), "value1");
        assert_eq!(context.get_or("nonexistent", "default"), "default");

        // Test history tracking
        assert_eq!(context.history.len(), 1);
        match &context.history[0] {
            ChainEvent::VarSet { key, value } => {
                assert_eq!(key, "key1");
                assert_eq!(value, "value1");
            }
            _ => panic!("Expected VarSet event"),
        }
    }

    #[tokio::test]
    async fn test_chain_context_event_recording() {
        let mut context = ChainContext::new();

        context.record_event(ChainEvent::NodeExecuted {
            name: "test_node".to_string(),
            success: true,
        });

        context.record_event(ChainEvent::Error {
            message: "test error".to_string(),
        });

        let history = context.get_history();
        assert_eq!(history.len(), 2);

        match &history[0] {
            ChainEvent::NodeExecuted { name, success } => {
                assert_eq!(name, "test_node");
                assert!(success);
            }
            _ => panic!("Expected NodeExecuted event"),
        }

        match &history[1] {
            ChainEvent::Error { message } => {
                assert_eq!(message, "test error");
            }
            _ => panic!("Expected Error event"),
        }
    }

    #[tokio::test]
    async fn test_sequential_chain_empty() {
        let chain = SequentialChain::new("empty_chain".to_string());
        let mut context = ChainContext::new();

        let result = chain.run(&mut context).await;
        assert!(result.is_ok());
        assert_eq!(context.history.len(), 0);
    }

    // Mock chain node for testing
    struct MockChainNode {
        name: String,
        should_fail: bool,
    }

    impl MockChainNode {
        fn new(name: &str, should_fail: bool) -> Self {
            Self {
                name: name.to_string(),
                should_fail,
            }
        }
    }

    #[async_trait]
    impl ChainNode for MockChainNode {
        async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
            if self.should_fail {
                Err(RustChainError::Exec(format!(
                    "Mock failure in {}",
                    self.name
                )))
            } else {
                context.set(&format!("{}_output", self.name), "success");
                Ok(())
            }
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn node_type(&self) -> &str {
            "MockNode"
        }
    }

    #[tokio::test]
    async fn test_sequential_chain_success() {
        let mut chain = SequentialChain::new("test_chain".to_string());
        chain.add(Box::new(MockChainNode::new("step1", false)));
        chain.add(Box::new(MockChainNode::new("step2", false)));

        let mut context = ChainContext::new();
        let result = chain.run(&mut context).await;

        assert!(result.is_ok());
        assert_eq!(context.get("step1_output"), Some("success".to_string()));
        assert_eq!(context.get("step2_output"), Some("success".to_string()));

        // Check history for executed nodes (includes both VarSet and NodeExecuted events)
        let history = context.get_history();
        assert!(history.len() >= 2); // At least 2 NodeExecuted events

        let node_executed_count = history
            .iter()
            .filter(|event| matches!(event, ChainEvent::NodeExecuted { .. }))
            .count();
        assert_eq!(node_executed_count, 2);

        for event in history {
            if let ChainEvent::NodeExecuted { name: _, success } = event {
                assert!(success);
            }
        }
    }

    #[tokio::test]
    async fn test_sequential_chain_failure_halt_on_error() {
        let mut chain = SequentialChain::new("test_chain".to_string());
        chain.add(Box::new(MockChainNode::new("step1", false)));
        chain.add(Box::new(MockChainNode::new("step2", true))); // This will fail
        chain.add(Box::new(MockChainNode::new("step3", false)));

        let mut context = ChainContext::new();
        let result = chain.run(&mut context).await;

        assert!(result.is_err());
        assert_eq!(context.get("step1_output"), Some("success".to_string()));
        assert_eq!(context.get("step2_output"), None); // Failed step shouldn't set output
        assert_eq!(context.get("step3_output"), None); // Should not execute

        // Check that error was recorded
        let history = context.get_history();
        let has_error = history
            .iter()
            .any(|event| matches!(event, ChainEvent::Error { .. }));
        assert!(has_error);
    }

    #[tokio::test]
    async fn test_sequential_chain_failure_continue_on_error() {
        let mut chain = SequentialChain::new("test_chain".to_string()).with_halt_on_error(false);

        chain.add(Box::new(MockChainNode::new("step1", false)));
        chain.add(Box::new(MockChainNode::new("step2", true))); // This will fail
        chain.add(Box::new(MockChainNode::new("step3", false)));

        let mut context = ChainContext::new();
        let result = chain.run(&mut context).await;

        assert!(result.is_ok()); // Should succeed despite failure
        assert_eq!(context.get("step1_output"), Some("success".to_string()));
        assert_eq!(context.get("step2_output"), None); // Failed step
        assert_eq!(context.get("step3_output"), Some("success".to_string())); // Should execute
    }

    #[tokio::test]
    async fn test_llm_chain_template_formatting() {
        let chain = LLMChain::new(
            "test_llm".to_string(),
            "Hello {{name}}, your age is {{age}}".to_string(),
        );

        let mut context = ChainContext::new();
        context.set("name", "Alice");
        context.set("age", "25");

        let formatted = chain.format_prompt(&context);
        assert_eq!(formatted, "Hello Alice, your age is 25");
    }

    #[cfg(not(feature = "llm"))]
    #[tokio::test]
    async fn test_llm_chain_mock_execution() {
        // This test runs without the LLM feature to test proper error handling
        let chain = LLMChain::new("test_llm".to_string(), "Say hello to {{name}}".to_string())
            .with_output_key("greeting".to_string());

        let mut context = ChainContext::new();
        context.set("name", "Bob");

        let result = chain.run(&mut context).await;
        // Should fail with Config error when LLM feature is not enabled
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RustChainError::Config(_)));

        // Context should remain unchanged
        assert_eq!(context.get("name"), Some("Bob".to_string()));
        assert_eq!(context.get("greeting"), None);
    }

    #[cfg(feature = "llm")]
    #[tokio::test]
    async fn test_llm_chain_with_llm_feature() {
        // This test runs with the LLM feature enabled but handles errors gracefully
        let chain = LLMChain::new("test_llm".to_string(), "Say hello to {{name}}".to_string())
            .with_output_key("greeting".to_string());

        let mut context = ChainContext::new();
        context.set("name", "Bob");

        let result = chain.run(&mut context).await;

        // The LLM chain may fail if no providers are available, which is expected in testing
        // We check that it either succeeds or fails with a specific LLM-related error
        match result {
            Ok(_) => {
                // If it succeeds, check that output was set
                let output = context.get("greeting");
                assert!(output.is_some());
            }
            Err(RustChainError::Llm(_)) => {
                // Expected failure when no LLM providers are configured
            }
            Err(other) => {
                panic!("Unexpected error type: {:?}", other);
            }
        }
    }

    #[tokio::test]
    async fn test_tool_chain_mock_execution() {
        let chain = ToolChain::new("test_tool".to_string(), "create_file".to_string())
            .with_param("path".to_string(), "filepath".to_string())
            .with_output_key("result".to_string());

        let mut context = ChainContext::new();
        context.set("filepath", "test_output.txt");

        let result = chain.run(&mut context).await;
        assert!(result.is_ok());

        // Should have tool response with file creation result
        let output = context.get("result").unwrap();
        assert!(output.contains("path"));
        assert!(output.contains("test_output.txt"));

        // Check that tool call was recorded
        let history = context.get_history();
        let has_tool_call = history
            .iter()
            .any(|event| matches!(event, ChainEvent::ToolCall { .. }));
        assert!(has_tool_call);
    }

    #[tokio::test]
    async fn test_transform_chain() {
        let chain = TransformChain::new(
            "uppercase".to_string(),
            "input".to_string(),
            "output".to_string(),
            |s| s.to_uppercase(),
        );

        let mut context = ChainContext::new();
        context.set("input", "hello world");

        let result = chain.run(&mut context).await;
        assert!(result.is_ok());
        assert_eq!(context.get("output"), Some("HELLO WORLD".to_string()));
    }

    #[tokio::test]
    async fn test_transform_chain_missing_input() {
        let chain = TransformChain::new(
            "uppercase".to_string(),
            "missing_key".to_string(),
            "output".to_string(),
            |s| s.to_uppercase(),
        );

        let mut context = ChainContext::new();

        let result = chain.run(&mut context).await;
        assert!(result.is_err());

        if let Err(RustChainError::Exec(msg)) = result {
            assert!(msg.contains("Input key 'missing_key' not found"));
        } else {
            panic!("Expected Exec error");
        }
    }

    #[tokio::test]
    async fn test_router_chain_with_route() {
        let mut router = RouterChain::new("test_router".to_string(), |context| {
            context
                .get("route")
                .unwrap_or_else(|| "default".to_string())
        });

        router = router.add_route(
            "path_a".to_string(),
            Box::new(MockChainNode::new("route_a", false)),
        );
        router = router.add_route(
            "path_b".to_string(),
            Box::new(MockChainNode::new("route_b", false)),
        );

        let mut context = ChainContext::new();
        context.set("route", "path_a");

        let result = router.run(&mut context).await;
        assert!(result.is_ok());
        assert_eq!(context.get("route_a_output"), Some("success".to_string()));
        assert_eq!(context.get("route_b_output"), None);
    }

    #[tokio::test]
    async fn test_router_chain_with_default() {
        let router = RouterChain::new("test_router".to_string(), |context| {
            context
                .get("route")
                .unwrap_or_else(|| "unknown".to_string())
        })
        .with_default(Box::new(MockChainNode::new("default_route", false)));

        let mut context = ChainContext::new();
        context.set("route", "nonexistent_route");

        let result = router.run(&mut context).await;
        assert!(result.is_ok());
        assert_eq!(
            context.get("default_route_output"),
            Some("success".to_string())
        );
    }

    #[tokio::test]
    async fn test_router_chain_no_route_no_default() {
        let router = RouterChain::new("test_router".to_string(), |_context| {
            "nonexistent".to_string()
        });

        let mut context = ChainContext::new();

        let result = router.run(&mut context).await;
        assert!(result.is_err());

        if let Err(RustChainError::Exec(msg)) = result {
            assert!(msg.contains("No route found"));
        } else {
            panic!("Expected Exec error");
        }
    }

    #[tokio::test]
    async fn test_map_reduce_chain() {
        // Mock chain that reverses input
        struct ReverseChain;

        #[async_trait]
        impl ChainNode for ReverseChain {
            async fn run(&self, context: &mut ChainContext) -> Result<(), RustChainError> {
                let input = context.get("input").unwrap_or_default();
                let reversed: String = input.chars().rev().collect();
                context.set("output", &reversed);
                Ok(())
            }

            fn name(&self) -> &str {
                "reverse"
            }
            fn node_type(&self) -> &str {
                "ReverseChain"
            }
        }

        let chain = MapReduceChain::new(
            "map_reduce_test".to_string(),
            Box::new(ReverseChain),
            |results| results.join(" | "),
            "input_lines".to_string(),
            "final_result".to_string(),
        );

        let mut context = ChainContext::new();
        context.set("input_lines", "hello\nworld\ntest");

        let result = chain.run(&mut context).await;
        assert!(result.is_ok());

        let output = context.get("final_result").unwrap();
        assert!(output.contains("olleh")); // "hello" reversed
        assert!(output.contains("dlrow")); // "world" reversed
        assert!(output.contains("tset")); // "test" reversed
    }

    #[tokio::test]
    async fn test_map_reduce_chain_missing_input() {
        struct NoOpChain;

        #[async_trait]
        impl ChainNode for NoOpChain {
            async fn run(&self, _context: &mut ChainContext) -> Result<(), RustChainError> {
                Ok(())
            }
            fn name(&self) -> &str {
                "noop"
            }
            fn node_type(&self) -> &str {
                "NoOpChain"
            }
        }

        let chain = MapReduceChain::new(
            "map_reduce_test".to_string(),
            Box::new(NoOpChain),
            |results| results.join(","),
            "missing_input".to_string(),
            "output".to_string(),
        );

        let mut context = ChainContext::new();

        let result = chain.run(&mut context).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_patterns_summarization() {
        let chain = patterns::summarization_chain();
        assert_eq!(chain.name, "summarization");
        assert_eq!(chain.steps.len(), 1);
    }

    #[test]
    fn test_chain_patterns_qa() {
        let chain = patterns::qa_chain();
        assert_eq!(chain.name, "qa");
        assert_eq!(chain.steps.len(), 1);
    }

    #[test]
    fn test_chain_patterns_translation() {
        let chain = patterns::translation_chain("Spanish");
        assert_eq!(chain.name, "translation");
        assert_eq!(chain.steps.len(), 1);
    }

    #[tokio::test]
    async fn test_complex_chain_composition() {
        // Test a complex chain that combines multiple chain types
        let mut main_chain = SequentialChain::new("complex_pipeline".to_string());

        // Step 1: Transform input to uppercase
        main_chain.add(Box::new(TransformChain::new(
            "uppercase_input".to_string(),
            "user_input".to_string(),
            "processed_input".to_string(),
            |s| s.to_uppercase(),
        )));

        // Step 2: Mock LLM processing
        main_chain.add(Box::new(
            LLMChain::new(
                "process_text".to_string(),
                "Process this text: {{processed_input}}".to_string(),
            )
            .with_output_key("llm_result".to_string()),
        ));

        // Step 3: Transform LLM result
        main_chain.add(Box::new(TransformChain::new(
            "finalize".to_string(),
            "llm_result".to_string(),
            "final_output".to_string(),
            |s| format!("Final: {}", s),
        )));

        let mut context = ChainContext::new();
        context.set("user_input", "hello world");

        let result = main_chain.run(&mut context).await;

        // The test should handle both success and failure cases
        match result {
            Ok(_) => {
                // If it succeeds, verify each step ran correctly
                assert_eq!(
                    context.get("processed_input"),
                    Some("HELLO WORLD".to_string())
                );
                assert!(context.get("llm_result").is_some());
                assert!(context.get("final_output").unwrap().starts_with("Final:"));

                // Verify all events were recorded
                let history = context.get_history();
                assert!(history.len() >= 5); // Various events from the chain execution

                // Count different event types
                let node_executions = history
                    .iter()
                    .filter(|e| matches!(e, ChainEvent::NodeExecuted { .. }))
                    .count();
                let var_sets = history
                    .iter()
                    .filter(|e| matches!(e, ChainEvent::VarSet { .. }))
                    .count();
                let _llm_calls = history
                    .iter()
                    .filter(|e| matches!(e, ChainEvent::LLMCall { .. }))
                    .count();

                // We should have various types of events
                assert!(node_executions > 0);
                assert!(var_sets > 0);
            }
            Err(RustChainError::Llm(_)) => {
                // Expected failure when no LLM providers are configured or models unavailable
                // The transform step should still have run
                assert_eq!(
                    context.get("processed_input"),
                    Some("HELLO WORLD".to_string())
                );

                // Check that some events were still recorded (from the transform step)
                let history = context.get_history();
                assert!(!history.is_empty());
            }
            Err(RustChainError::Config(_)) => {
                // Expected failure when LLM feature is not enabled
                // The transform step should still have run
                assert_eq!(
                    context.get("processed_input"),
                    Some("HELLO WORLD".to_string())
                );

                // Check that some events were still recorded (from the transform step)
                let history = context.get_history();
                assert!(!history.is_empty());
            }
            Err(other) => {
                panic!("Unexpected error type: {:?}", other);
            }
        }
    }

    #[tokio::test]
    async fn test_chain_error_propagation() {
        let mut chain = SequentialChain::new("error_test".to_string());

        // Add a failing step
        chain.add(Box::new(MockChainNode::new("failing_step", true)));

        let mut context = ChainContext::new();

        let result = chain.run(&mut context).await;
        assert!(result.is_err());

        // Verify error was recorded in history
        let history = context.get_history();
        let has_error_event = history.iter().any(|event| {
            matches!(event, ChainEvent::Error { message } if message.contains("Mock failure"))
        });
        assert!(has_error_event);

        let has_failed_execution = history
            .iter()
            .any(|event| matches!(event, ChainEvent::NodeExecuted { success: false, .. }));
        assert!(has_failed_execution);
    }

    #[test]
    fn test_sequential_chain_empty_creation() {
        // Test that empty chain can be created - should be valid to have empty chain
        let chain = SequentialChain::new("empty_test_chain".to_string());
        assert_eq!(chain.name, "empty_test_chain");
        assert_eq!(chain.steps.len(), 0);
    }

    #[test]
    fn test_map_reduce_chain_creation() {
        // Test map-reduce chain creation with parameters
        struct TestMapChain;

        #[async_trait]
        impl ChainNode for TestMapChain {
            async fn run(&self, _context: &mut ChainContext) -> Result<(), RustChainError> {
                Ok(())
            }
            fn name(&self) -> &str {
                "test"
            }
            fn node_type(&self) -> &str {
                "test"
            }
        }

        let result = MapReduceChain::new(
            "test_map_reduce".to_string(),
            Box::new(TestMapChain),
            |results| results.join(","),
            "input_key".to_string(),
            "output_key".to_string(),
        );
        assert_eq!(result.name, "test_map_reduce");
        assert_eq!(result.input_key, "input_key");
        assert_eq!(result.output_key, "output_key");
    }

    #[test]
    fn test_router_chain_creation() {
        // Test router chain creation without routes
        let router = RouterChain::new("test_router".to_string(), |_ctx| "default".to_string());
        assert_eq!(router.name, "test_router");
        assert_eq!(router.routes.len(), 0);
        assert!(router.default_route.is_none());
    }

    #[test]
    fn test_chain_context_variable_override() {
        // Test context variable override behavior
        let mut context = ChainContext::new();
        context.set("key1", "value1");
        context.set("key1", "value2"); // Override

        assert_eq!(context.get("key1"), Some("value2".to_string()));
    }

    #[test]
    fn test_transform_chain_creation() {
        // Test transform chain creation with edge case handling function
        let transform = TransformChain::new(
            "edge_case_transform".to_string(),
            "input".to_string(),
            "output".to_string(),
            |s: &str| {
                if s.is_empty() {
                    "default".to_string()
                } else {
                    s.to_uppercase()
                }
            },
        );
        assert_eq!(transform.name, "edge_case_transform");
        assert_eq!(transform.input_key, "input");
        assert_eq!(transform.output_key, "output");
    }

    #[test]
    fn test_llm_chain_template_creation() {
        // Test LLM chain creation with template containing variables
        let template = "Hello {{name}}, welcome to {{place}}!";
        let chain = LLMChain::new("template_test".to_string(), template.to_string());
        assert_eq!(chain.name, "template_test");
        assert_eq!(chain.prompt_template, template);
        assert_eq!(chain.output_key, "llm_output");
    }

    #[test]
    fn test_sequential_chain_halt_on_error_setting() {
        // Test that sequential chain can be configured for error handling
        let chain = SequentialChain::new("error_test".to_string()).with_halt_on_error(false);
        assert_eq!(chain.name, "error_test");
        assert!(!chain.halt_on_error);

        let chain2 = SequentialChain::new("halt_test".to_string()).with_halt_on_error(true);
        assert!(chain2.halt_on_error);
    }

    #[test]
    fn test_tool_chain_configuration() {
        // Test tool chain creation and configuration
        let tool_chain = ToolChain::new("test_tool_chain".to_string(), "file_create".to_string())
            .with_param("path".to_string(), "file_path".to_string())
            .with_output_key("creation_result".to_string());

        assert_eq!(tool_chain.name, "test_tool_chain");
        assert_eq!(tool_chain.tool_name, "file_create");
        assert_eq!(tool_chain.output_key, "creation_result");
        assert!(tool_chain.param_mapping.contains_key("file_path"));
    }
}
