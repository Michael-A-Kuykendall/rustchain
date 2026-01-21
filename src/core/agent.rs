use crate::core::error::{ExecutionError, MemoryError, RustChainError, ToolError};
use crate::core::llm::LLMBackend;
use crate::core::memory::MemoryStore;
use crate::core::tools::{ToolRegistry, ToolResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Agent with autonomous reasoning and action capabilities
pub struct Agent<'a> {
    pub name: String,
    pub memory: &'a mut dyn MemoryStore,
    pub tools: &'a ToolRegistry,
    pub llm: &'a dyn LLMBackend,
    pub max_iterations: usize,
    pub verbose: bool,
    state: AgentState,
}

impl<'a> Agent<'a> {
    pub fn new(
        name: String,
        memory: &'a mut dyn MemoryStore,
        tools: &'a ToolRegistry,
        llm: &'a dyn LLMBackend,
    ) -> Self {
        Self {
            name,
            memory,
            tools,
            llm,
            max_iterations: 10,
            verbose: false,
            state: AgentState::Idle,
        }
    }

    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Main agent execution loop - ReAct pattern (Reasoning + Acting)
    pub async fn run(&mut self, objective: &str) -> Result<String, RustChainError> {
        info!("Agent {} starting with objective: {}", self.name, objective);

        self.state = AgentState::Running;
        self.memory.store("objective", objective)?;

        let mut iteration = 0;
        let mut final_answer = None;

        while iteration < self.max_iterations && final_answer.is_none() {
            iteration += 1;

            if self.verbose {
                println!("\n=== Iteration {} ===", iteration);
            }

            // Gather current context
            let observation = self.observe().await?;

            // Analyze situation and determine approach
            let thought = self.think(&observation, objective).await?;

            if self.verbose {
                println!("Thought: {}", thought);
            }

            // Choose next action
            let action = self.decide_action(&thought).await?;

            if self.verbose {
                println!("Action: {:?}", action);
            }

            // Execute chosen action
            match action {
                AgentAction::UseTool { tool, input } => {
                    let result = self.use_tool(&tool, &input).await?;
                    self.memory
                        .store(&format!("tool_result_{}", iteration), &result)?;

                    if self.verbose {
                        println!("Tool Result: {}", result);
                    }
                }
                AgentAction::Answer(answer) => {
                    final_answer = Some(answer.clone());
                    self.memory.store("final_answer", &answer)?;
                }
                AgentAction::RequestMoreInfo(question) => {
                    // In a real scenario, this would interact with the user
                    if self.verbose {
                        println!("Agent needs more info: {}", question);
                    }
                    self.memory
                        .store(&format!("question_{}", iteration), &question)?;
                }
                AgentAction::Think => {
                    // Continue thinking in next iteration
                    continue;
                }
            }

            // Periodic progress reflection
            if iteration % 3 == 0 {
                let reflection = self.reflect().await?;
                if self.verbose {
                    println!("Reflection: {}", reflection);
                }
            }
        }

        self.state = AgentState::Completed;

        final_answer.ok_or_else(|| {
            RustChainError::Execution(ExecutionError::timeout(
                &self.name,
                (self.max_iterations * 10000) as u64, // Rough estimate of timeout
            ))
        })
    }

    /// Observe current state from memory and context
    async fn observe(&self) -> Result<String, RustChainError> {
        let keys = self.memory.list_keys().map_err(|e| {
            RustChainError::Memory(MemoryError::serialization_failed(format!(
                "Failed to list keys: {}",
                e
            )))
        })?;
        let mut history = String::new();
        for key in keys {
            if let Ok(Some(value)) = self.memory.retrieve(&key) {
                history.push_str(&format!("{}: {}\n", key, value));
            }
        }
        Ok(format!("Current context:\n{}", history))
    }

    /// Think about what to do next
    async fn think(
        &mut self,
        observation: &str,
        objective: &str,
    ) -> Result<String, RustChainError> {
        let prompt = format!(
            "You are {}, an AI agent. Your objective is: {}\n\n\
            Current observation:\n{}\n\n\
            Available tools: {:?}\n\n\
            What should you do next? Think step by step.",
            self.name,
            objective,
            observation,
            self.tools.list()
        );

        let thought = self.llm.generate(&prompt).await?;
        self.memory.store(
            &format!("thought_{}", chrono::Utc::now().timestamp()),
            &thought,
        )?;

        Ok(thought)
    }

    /// Decide on the next action based on thinking
    async fn decide_action(&self, thought: &str) -> Result<AgentAction, RustChainError> {
        let prompt = format!(
            "Based on this thought: {}\n\n\
            Decide on ONE of these actions:\n\
            1. USE_TOOL <tool_name> <input> - Use a specific tool\n\
            2. ANSWER <final_answer> - Provide the final answer\n\
            3. ASK <question> - Request more information\n\
            4. THINK - Continue thinking\n\n\
            Respond with only the action in the specified format.",
            thought
        );

        let response = self.llm.generate(&prompt).await?;

        // Parse the action
        let action = if response.starts_with("USE_TOOL") {
            let parts: Vec<&str> = response.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                AgentAction::UseTool {
                    tool: parts[1].to_string(),
                    input: parts[2].to_string(),
                }
            } else {
                AgentAction::Think
            }
        } else if response.starts_with("ANSWER") {
            let answer = response.strip_prefix("ANSWER").unwrap_or("").trim();
            AgentAction::Answer(answer.to_string())
        } else if response.starts_with("ASK") {
            let question = response.strip_prefix("ASK").unwrap_or("").trim();
            AgentAction::RequestMoreInfo(question.to_string())
        } else {
            AgentAction::Think
        };

        Ok(action)
    }

    /// Use a tool
    pub async fn use_tool(&self, tool_name: &str, input: &str) -> Result<String, RustChainError> {
        if let Some(tool) = self.tools.get(tool_name) {
            match tool.invoke(input).await? {
                ToolResult::Success(s) => Ok(s),
                ToolResult::StructuredJson(val) => Ok(val.to_string()),
                ToolResult::Error(msg) => Err(RustChainError::Tool(ToolError::execution_failed(
                    "unknown", msg,
                ))),
            }
        } else {
            Err(RustChainError::Tool(ToolError::not_found(tool_name)))
        }
    }

    /// Reflect on progress and adjust strategy
    async fn reflect(&mut self) -> Result<String, RustChainError> {
        let prompt = format!(
            "You are {}. Reflect on your progress so far.\n\
            What have you learned? Are you making progress? \
            Should you adjust your approach?",
            self.name
        );

        let reflection = self.llm.generate(&prompt).await?;
        self.memory.store(
            &format!("reflection_{}", chrono::Utc::now().timestamp()),
            &reflection,
        )?;

        Ok(reflection)
    }
}

/// Actions an agent can take
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentAction {
    UseTool { tool: String, input: String },
    Answer(String),
    RequestMoreInfo(String),
    Think,
}

/// Agent state
#[derive(Debug, Clone, PartialEq)]
pub enum AgentState {
    Idle,
    Running,
    Waiting,
    Completed,
    Failed,
}

/// Multi-agent system for collaborative problem solving
#[derive(Default)]
pub struct MultiAgentSystem {
    agents: HashMap<String, Box<dyn AgentTrait>>,
    communication_channel: CommunicationChannel,
}

impl MultiAgentSystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_agent(&mut self, agent: Box<dyn AgentTrait>) {
        let name = agent.name().to_string();
        info!("Adding agent to system: {}", name);
        self.agents.insert(name, agent);
    }

    pub async fn collaborate_on(&mut self, task: &str) -> Result<String, RustChainError> {
        info!("Multi-agent collaboration on: {}", task);

        // Simple round-robin collaboration
        let mut results = Vec::new();

        for (name, agent) in &mut self.agents {
            debug!("Agent {} working on task", name);

            // Get previous results from communication channel
            let context = self.communication_channel.get_context();

            // Agent works on task with context
            let result = agent.process_task(task, &context).await?;

            // Share result with other agents
            self.communication_channel.broadcast(name, &result);

            results.push(result);
        }

        // Synthesize results
        Ok(results.join("\n\n"))
    }
}

/// Trait for agents that can work in multi-agent systems
#[async_trait]
pub trait AgentTrait: Send + Sync {
    fn name(&self) -> &str;
    async fn process_task(&mut self, task: &str, context: &str) -> Result<String, RustChainError>;
    async fn receive_message(&mut self, from: &str, message: &str) -> Result<(), RustChainError>;
}

/// Communication channel for multi-agent systems
#[derive(Default)]
pub struct CommunicationChannel {
    messages: Vec<Message>,
    context: String,
}

impl CommunicationChannel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn broadcast(&mut self, from: &str, content: &str) {
        self.messages.push(Message {
            from: from.to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now(),
        });

        // Update context with latest message
        self.context.push_str(&format!("\n[{}]: {}", from, content));
    }

    pub fn get_context(&self) -> String {
        self.context.clone()
    }

    pub fn get_messages(&self) -> &[Message] {
        &self.messages
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub from: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Specialized agent types
/// Research Agent - focuses on gathering information
pub struct ResearchAgent {
    name: String,
    sources: Vec<String>,
}

impl ResearchAgent {
    pub fn new(name: String) -> Self {
        Self {
            name,
            sources: Vec::new(),
        }
    }

    pub fn add_source(&mut self, source: String) {
        self.sources.push(source);
    }
}

#[async_trait]
impl AgentTrait for ResearchAgent {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_task(&mut self, task: &str, _context: &str) -> Result<String, RustChainError> {
        // Research agent would search through sources
        Ok(format!(
            "Research findings for '{}': [simulated research results from {:?}]",
            task, self.sources
        ))
    }

    async fn receive_message(&mut self, from: &str, message: &str) -> Result<(), RustChainError> {
        debug!("{} received message from {}: {}", self.name, from, message);
        Ok(())
    }
}

/// Planning Agent - creates action plans
pub struct PlanningAgent {
    name: String,
    strategies: Vec<String>,
}

impl PlanningAgent {
    pub fn new(name: String) -> Self {
        Self {
            name,
            strategies: vec![
                "divide_and_conquer".to_string(),
                "sequential".to_string(),
                "parallel".to_string(),
            ],
        }
    }
}

#[async_trait]
impl AgentTrait for PlanningAgent {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_task(&mut self, task: &str, context: &str) -> Result<String, RustChainError> {
        // Planning agent would create an action plan
        Ok(format!(
            "Plan for '{}' using strategy '{}':\n1. Analyze requirements\n2. Break down into subtasks\n3. Execute in parallel\n4. Synthesize results\nContext: {}",
            task, self.strategies[0], context
        ))
    }

    async fn receive_message(&mut self, from: &str, message: &str) -> Result<(), RustChainError> {
        debug!("{} received message from {}: {}", self.name, from, message);
        Ok(())
    }
}

/// Execution Agent - carries out planned actions
pub struct ExecutionAgent {
    name: String,
    capabilities: Vec<String>,
}

impl ExecutionAgent {
    pub fn new(name: String) -> Self {
        Self {
            name,
            capabilities: vec![
                "file_ops".to_string(),
                "http".to_string(),
                "compute".to_string(),
            ],
        }
    }
}

#[async_trait]
impl AgentTrait for ExecutionAgent {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_task(&mut self, task: &str, context: &str) -> Result<String, RustChainError> {
        // Execution agent would execute the plan
        Ok(format!(
            "Executing task '{}' with capabilities {:?}. Context: {}",
            task, self.capabilities, context
        ))
    }

    async fn receive_message(&mut self, from: &str, message: &str) -> Result<(), RustChainError> {
        debug!("{} received message from {}: {}", self.name, from, message);
        Ok(())
    }
}

/// Create a team of specialized agents
pub fn create_agent_team() -> MultiAgentSystem {
    let mut system = MultiAgentSystem::new();

    system.add_agent(Box::new(ResearchAgent::new("Researcher".to_string())));
    system.add_agent(Box::new(PlanningAgent::new("Planner".to_string())));
    system.add_agent(Box::new(ExecutionAgent::new("Executor".to_string())));

    system
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::RustChainError;

    use crate::core::tools::{Tool, ToolCapability};
    use async_trait::async_trait;
    use futures::stream::{self, BoxStream};
    use std::collections::HashMap;

    // Mock implementations for testing

    struct MockLLM {
        responses: HashMap<String, String>,
        default_response: String,
    }

    impl MockLLM {
        fn new() -> Self {
            let mut responses = HashMap::new();
            responses.insert(
                "think".to_string(),
                "I need to analyze this problem step by step.".to_string(),
            );
            responses.insert("action".to_string(), "USE_TOOL calculator 2+2".to_string());
            responses.insert(
                "answer".to_string(),
                "ANSWER The calculation result is 4".to_string(),
            );
            responses.insert(
                "reflect".to_string(),
                "I'm making good progress on this task.".to_string(),
            );

            Self {
                responses,
                default_response: "I need to think about this.".to_string(),
            }
        }

        fn with_response(mut self, key: &str, response: &str) -> Self {
            self.responses.insert(key.to_string(), response.to_string());
            self
        }
    }

    #[async_trait]
    impl LLMBackend for MockLLM {
        async fn generate(&self, prompt: &str) -> Result<String, RustChainError> {
            // Simple pattern matching for test responses
            if prompt.contains("Think step by step") {
                Ok(self
                    .responses
                    .get("think")
                    .unwrap_or(&self.default_response)
                    .clone())
            } else if prompt.contains("Decide on ONE of these actions") {
                Ok(self
                    .responses
                    .get("action")
                    .unwrap_or(&self.default_response)
                    .clone())
            } else if prompt.contains("Reflect on your progress") {
                Ok(self
                    .responses
                    .get("reflect")
                    .unwrap_or(&self.default_response)
                    .clone())
            } else {
                Ok(self.default_response.clone())
            }
        }

        async fn stream(
            &self,
            _prompt: &str,
        ) -> Result<BoxStream<'static, Result<String, RustChainError>>, RustChainError> {
            Ok(Box::pin(stream::once(async {
                Ok("mock response".to_string())
            })))
        }

        fn name(&self) -> &'static str {
            "MockLLM"
        }

        async fn health_check(&self) -> Result<bool, RustChainError> {
            Ok(true)
        }
    }

    struct MockTool {
        name: &'static str,
        result: String,
        should_fail: bool,
    }

    impl MockTool {
        fn new(name: &'static str, result: String) -> Self {
            Self {
                name,
                result,
                should_fail: false,
            }
        }

        fn failing(name: &'static str) -> Self {
            Self {
                name,
                result: String::new(),
                should_fail: true,
            }
        }
    }

    #[async_trait]
    impl Tool for MockTool {
        fn name(&self) -> &'static str {
            self.name
        }

        fn capabilities(&self) -> Vec<ToolCapability> {
            vec![ToolCapability::Basic]
        }

        async fn invoke(&self, _input: &str) -> Result<ToolResult, RustChainError> {
            if self.should_fail {
                Ok(ToolResult::Error("Mock tool error".to_string()))
            } else {
                Ok(ToolResult::Success(self.result.clone()))
            }
        }
    }

    #[tokio::test]
    async fn test_mock_llm() {
        let llm = MockLLM::new();

        let response = llm.generate("Think step by step about this").await.unwrap();
        assert_eq!(response, "I need to analyze this problem step by step.");

        let response = llm
            .generate("Decide on ONE of these actions")
            .await
            .unwrap();
        assert_eq!(response, "USE_TOOL calculator 2+2");

        let response = llm.generate("Reflect on your progress").await.unwrap();
        assert_eq!(response, "I'm making good progress on this task.");
    }

    #[tokio::test]
    async fn test_mock_tool_success() {
        let tool = MockTool::new("test_tool", "success result".to_string());

        assert_eq!(tool.name(), "test_tool");
        assert_eq!(tool.capabilities(), vec![ToolCapability::Basic]);

        let result = tool.invoke("test input").await.unwrap();
        match result {
            ToolResult::Success(s) => assert_eq!(s, "success result"),
            _ => panic!("Expected Success result"),
        }
    }

    #[tokio::test]
    async fn test_mock_tool_failure() {
        let tool = MockTool::failing("failing_tool");

        assert_eq!(tool.name(), "failing_tool");

        let result = tool.invoke("test input").await.unwrap();
        match result {
            ToolResult::Error(msg) => assert_eq!(msg, "Mock tool error"),
            _ => panic!("Expected Error result"),
        }
    }

    #[tokio::test]
    async fn test_tool_registry() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(MockTool::new("calculator", "result".to_string())));
        registry.register(Box::new(MockTool::new("search", "found".to_string())));

        let tools = registry.list();
        assert_eq!(tools.len(), 2);
        assert!(tools.contains(&"calculator".to_string()));
        assert!(tools.contains(&"search".to_string()));

        let tool = registry.get("calculator");
        assert!(tool.is_some());

        let tool = registry.get("nonexistent");
        assert!(tool.is_none());
    }

    #[tokio::test]
    async fn test_communication_channel() {
        let mut channel = CommunicationChannel::new();

        channel.broadcast("Agent1", "Hello world");
        channel.broadcast("Agent2", "Hi there");

        let context = channel.get_context();
        assert!(context.contains("[Agent1]: Hello world"));
        assert!(context.contains("[Agent2]: Hi there"));

        let messages = channel.get_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].from, "Agent1");
        assert_eq!(messages[0].content, "Hello world");
    }

    #[tokio::test]
    async fn test_multi_agent_system() {
        let mut system = MultiAgentSystem::new();

        system.add_agent(Box::new(ResearchAgent::new("Researcher".to_string())));
        system.add_agent(Box::new(PlanningAgent::new("Planner".to_string())));

        let result = system
            .collaborate_on("solve a complex problem")
            .await
            .unwrap();

        assert!(result.contains("Research findings"));
        assert!(result.contains("Plan for"));
    }

    #[tokio::test]
    async fn test_research_agent() {
        let mut agent = ResearchAgent::new("TestResearcher".to_string());
        agent.add_source("database1".to_string());
        agent.add_source("database2".to_string());

        assert_eq!(agent.name(), "TestResearcher");

        let result = agent
            .process_task("find information about AI", "")
            .await
            .unwrap();
        assert!(result.contains("Research findings"));
        assert!(result.contains("database1"));
        assert!(result.contains("database2"));

        // Test message receiving
        let msg_result = agent.receive_message("OtherAgent", "some info").await;
        assert!(msg_result.is_ok());
    }

    #[tokio::test]
    async fn test_planning_agent() {
        let mut agent = PlanningAgent::new("TestPlanner".to_string());

        assert_eq!(agent.name(), "TestPlanner");

        let result = agent
            .process_task("create a plan", "previous context")
            .await
            .unwrap();
        assert!(result.contains("Plan for"));
        assert!(result.contains("divide_and_conquer"));
        assert!(result.contains("previous context"));

        // Test message receiving
        let msg_result = agent.receive_message("OtherAgent", "plan update").await;
        assert!(msg_result.is_ok());
    }

    #[tokio::test]
    async fn test_execution_agent() {
        let mut agent = ExecutionAgent::new("TestExecutor".to_string());

        assert_eq!(agent.name(), "TestExecutor");

        let result = agent
            .process_task("execute plan", "context info")
            .await
            .unwrap();
        assert!(result.contains("Executing task"));
        assert!(result.contains("file_ops"));
        assert!(result.contains("context info"));

        // Test message receiving
        let msg_result = agent.receive_message("OtherAgent", "execute now").await;
        assert!(msg_result.is_ok());
    }

    #[tokio::test]
    async fn test_create_agent_team() {
        let system = create_agent_team();

        // Verify team has the expected agents
        // Note: We can't directly access agents in MultiAgentSystem due to private field,
        // but we can test that the function returns a valid system
        assert_eq!(system.agents.len(), 3);
    }

    #[test]
    fn test_agent_action_serialization() {
        let action = AgentAction::UseTool {
            tool: "test_tool".to_string(),
            input: "test_input".to_string(),
        };

        let serialized = serde_json::to_string(&action).unwrap();
        let deserialized: AgentAction = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            AgentAction::UseTool { tool, input } => {
                assert_eq!(tool, "test_tool");
                assert_eq!(input, "test_input");
            }
            _ => panic!("Deserialization failed"),
        }
    }

    #[test]
    fn test_agent_state_equality() {
        assert_eq!(AgentState::Idle, AgentState::Idle);
        assert_ne!(AgentState::Idle, AgentState::Running);
        assert_ne!(AgentState::Running, AgentState::Completed);
        assert_ne!(AgentState::Completed, AgentState::Failed);
        assert_ne!(AgentState::Failed, AgentState::Waiting);
    }

    #[test]
    fn test_message_creation() {
        let message = Message {
            from: "TestAgent".to_string(),
            content: "Test message".to_string(),
            timestamp: chrono::Utc::now(),
        };

        assert_eq!(message.from, "TestAgent");
        assert_eq!(message.content, "Test message");

        // Test cloning
        let cloned = message.clone();
        assert_eq!(cloned.from, message.from);
        assert_eq!(cloned.content, message.content);
    }

    #[tokio::test]
    async fn test_agent_action_parsing() {
        // Test parsing different action formats directly
        let llm = MockLLM::new().with_response("action", "USE_TOOL calculator 2+2");

        let response = llm
            .generate("Decide on ONE of these actions")
            .await
            .unwrap();

        // Simulate the parsing logic from decide_action
        let action = if response.starts_with("USE_TOOL") {
            let parts: Vec<&str> = response.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                AgentAction::UseTool {
                    tool: parts[1].to_string(),
                    input: parts[2].to_string(),
                }
            } else {
                AgentAction::Think
            }
        } else if response.starts_with("ANSWER") {
            let answer = response.strip_prefix("ANSWER").unwrap_or("").trim();
            AgentAction::Answer(answer.to_string())
        } else if response.starts_with("ASK") {
            let question = response.strip_prefix("ASK").unwrap_or("").trim();
            AgentAction::RequestMoreInfo(question.to_string())
        } else {
            AgentAction::Think
        };

        match action {
            AgentAction::UseTool { tool, input } => {
                assert_eq!(tool, "calculator");
                assert_eq!(input, "2+2");
            }
            _ => panic!("Expected UseTool action"),
        }
    }

    #[tokio::test]
    async fn test_answer_action_parsing() {
        let response = "ANSWER The result is 42";

        let action = if response.starts_with("ANSWER") {
            let answer = response.strip_prefix("ANSWER").unwrap_or("").trim();
            AgentAction::Answer(answer.to_string())
        } else {
            AgentAction::Think
        };

        match action {
            AgentAction::Answer(answer) => {
                assert_eq!(answer, "The result is 42");
            }
            _ => panic!("Expected Answer action"),
        }
    }

    #[tokio::test]
    async fn test_ask_action_parsing() {
        let response = "ASK What is the current temperature?";

        let action = if response.starts_with("ASK") {
            let question = response.strip_prefix("ASK").unwrap_or("").trim();
            AgentAction::RequestMoreInfo(question.to_string())
        } else {
            AgentAction::Think
        };

        match action {
            AgentAction::RequestMoreInfo(question) => {
                assert_eq!(question, "What is the current temperature?");
            }
            _ => panic!("Expected RequestMoreInfo action"),
        }
    }
}
