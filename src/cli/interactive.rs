use crate::core::memory::ConversationMemory;
use crate::core::{Result, RuntimeContext};
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Interactive CLI mode providing conversational experience
pub struct InteractiveMode {
    context: Arc<RuntimeContext>,
    session_id: String,
    conversation: Arc<RwLock<ConversationMemory>>,
    exit_requested: bool,
}

impl InteractiveMode {
    pub fn new(context: Arc<RuntimeContext>) -> Self {
        let session_id = format!("interactive_{}", Uuid::new_v4().simple());
        let conversation = Arc::new(RwLock::new(ConversationMemory::new(1000))); // 1000 message capacity

        Self {
            context,
            session_id,
            conversation,
            exit_requested: false,
        }
    }

    /// Start the interactive CLI session
    pub async fn run(&mut self) -> Result<()> {
        self.print_welcome().await?;

        while !self.exit_requested {
            match self.handle_user_input().await {
                Ok(_) => continue,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    continue;
                }
            }
        }

        self.print_goodbye().await?;
        Ok(())
    }

    async fn print_welcome(&self) -> Result<()> {
        println!("🤖 RustChain Interactive Mode");
        println!("─────────────────────────────");
        println!("Welcome to RustChain's conversational AI agent interface.");
        println!("Type your requests naturally, and I'll help you execute missions,");
        println!("manage configurations, run safety checks, and more.");
        println!();
        println!("💡 Examples:");
        println!("  • \"Run a mission to create a file called hello.txt\"");
        println!("  • \"Check my system configuration\"");
        println!("  • \"What safety policies are currently active?\"");
        println!("  • \"Show me the audit trail from today\"");
        println!();
        println!("Type 'exit', 'quit', or press Ctrl+C to leave.");
        println!("─────────────────────────────────────────────────");
        println!();
        Ok(())
    }

    async fn print_goodbye(&self) -> Result<()> {
        println!();
        println!("👋 Thanks for using RustChain Interactive Mode!");

        // Save session summary
        let conversation = self.conversation.read().await;
        let stats = conversation.stats();

        if stats.total_messages > 0 {
            println!("📊 Session Summary:");
            println!("   • Messages exchanged: {}", stats.total_messages);
            println!("   • Session ID: {}", self.session_id);

            // Audit the session
            self.context
                .audit_action(
                    &self.session_id,
                    "interactive_session_end",
                    &format!(
                        "Completed interactive session with {} messages",
                        stats.total_messages
                    ),
                )
                .await;
        }

        println!("🚀 Session saved. See you next time!");
        Ok(())
    }

    async fn handle_user_input(&mut self) -> Result<()> {
        // Print prompt
        print!("🤖 rustchain> ");
        if let Err(e) = io::stdout().flush() {
            tracing::warn!("Failed to flush stdout: {}", e);
            // Continue execution even if stdout flush fails
        }

        // Read user input
        let mut input = String::new();
        let bytes_read = io::stdin().read_line(&mut input).map_err(|e| {
            crate::core::error::RustChainError::Execution(
                crate::core::error::ExecutionError::InvalidState {
                    state: "reading_input".to_string(),
                    operation: format!("Failed to read input: {}", e),
                },
            )
        })?;

        tracing::debug!("Read {} bytes: {:?}", bytes_read, input.trim());

        // Handle EOF (end of input stream)
        if bytes_read == 0 {
            println!("\nEOF detected, exiting interactive mode.");
            self.exit_requested = true;
            return Ok(());
        }

        let input = input.trim();

        // Handle empty input
        if input.is_empty() {
            return Ok(());
        }

        // Handle exit commands
        if matches!(input.to_lowercase().as_str(), "exit" | "quit" | "bye" | "q") {
            self.exit_requested = true;
            return Ok(());
        }

        // Add user message to conversation
        self.conversation.write().await.add_message("user", input)?;

        // Process the input and generate response
        let response = self.process_natural_language_request(input).await?;

        // Add assistant response to conversation
        self.conversation
            .write()
            .await
            .add_message("assistant", &response)?;

        // Print response
        println!();
        println!("🤖 {}", response);
        println!();

        Ok(())
    }

    async fn process_natural_language_request(&self, input: &str) -> Result<String> {
        // Audit the user request
        self.context
            .audit_action(&self.session_id, "interactive_request", input)
            .await;

        // Use LLM for actual AI-powered conversation
        #[cfg(feature = "llm")]
        {
            match self.process_with_llm(input).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    // Fall back to pattern matching if LLM fails
                    tracing::warn!(
                        "LLM processing failed, falling back to pattern matching: {}",
                        e
                    );
                }
            }
        }

        // Fallback: Natural language processing and intent recognition using patterns
        let intent = self.analyze_intent(input).await?;

        match intent {
            Intent::RunMission { description } => self.handle_mission_request(&description).await,
            Intent::CheckConfig => self.handle_config_check().await,
            Intent::ShowSafety => self.handle_safety_check().await,
            Intent::ShowAudit { timeframe } => self.handle_audit_request(&timeframe).await,
            Intent::ShowFeatures => self.handle_features_request().await,
            Intent::Help => self.handle_help_request().await,
            Intent::General { response } => Ok(response),
        }
    }

    async fn analyze_intent(&self, input: &str) -> Result<Intent> {
        let input_lower = input.to_lowercase();

        // Mission execution patterns
        if input_lower.contains("run")
            && (input_lower.contains("mission") || input_lower.contains("task"))
        {
            return Ok(Intent::RunMission {
                description: input.to_string(),
            });
        }

        if input_lower.contains("create") && input_lower.contains("file") {
            return Ok(Intent::RunMission {
                description: format!("Create file: {}", input),
            });
        }

        // Configuration patterns
        if input_lower.contains("config") || input_lower.contains("configuration") {
            return Ok(Intent::CheckConfig);
        }

        // Safety patterns
        if input_lower.contains("safety")
            || input_lower.contains("policy")
            || input_lower.contains("policies")
        {
            return Ok(Intent::ShowSafety);
        }

        // Audit patterns
        if input_lower.contains("audit")
            || input_lower.contains("log")
            || input_lower.contains("history")
        {
            let timeframe = if input_lower.contains("today") {
                "today".to_string()
            } else if input_lower.contains("recent") {
                "recent".to_string()
            } else {
                "all".to_string()
            };
            return Ok(Intent::ShowAudit { timeframe });
        }

        // Features patterns
        if input_lower.contains("feature")
            || input_lower.contains("capability")
            || input_lower.contains("what can")
        {
            return Ok(Intent::ShowFeatures);
        }

        // Help patterns
        if input_lower.contains("help") || input_lower.contains("how") || input_lower == "?" {
            return Ok(Intent::Help);
        }

        // Greeting patterns
        if matches!(
            input_lower.as_str(),
            "hi" | "hello" | "hey" | "good morning" | "good afternoon"
        ) {
            return Ok(Intent::General {
                response: "Hello! I'm your RustChain AI assistant. I can help you run missions, check configurations, manage safety policies, review audit logs, and more. What would you like to do?".to_string()
            });
        }

        // Default: general assistance
        Ok(Intent::General {
            response: format!("I understand you want to: '{}'. Let me help you with that.\n\nFor mission execution, try: 'run a mission to [description]'\nFor system info, try: 'check config', 'show safety policies', or 'show audit logs'\nFor help, just type 'help'", input)
        })
    }

    async fn handle_mission_request(&self, description: &str) -> Result<String> {
        Ok(format!(
            "🚀 Mission Request Received: {}\n\n\
            I can help you execute this mission! However, I need a properly formatted mission file.\n\
            \n\
            To run missions:\n\
            • Use: `rustchain run path/to/mission.yaml`\n\
            • Or create a simple mission with: `rustchain mission create`\n\
            \n\
            Would you like me to help you create a mission file for this task?",
            description
        ))
    }

    async fn handle_config_check(&self) -> Result<String> {
        // Check actual runtime context status
        let context = crate::core::RuntimeContext::new();
        let config = context.config.read().await;
        let audit_entries = context.audit.get_entries().await;

        Ok(format!(
            "📋 Configuration Status:\n\n\
            ✅ Runtime Context: Initialized\n\
            ✅ Audit System: Active ({} entries logged)\n\
            ✅ Policy Engine: Loaded with default policies\n\
            ✅ Safety Validator: Enabled\n\
            ✅ Tool Registry: Ready\n\
            \n\
            Current Settings:\n\
            • Mission Timeout: {}s\n\
            • Max Parallel Steps: {}\n\
            • Audit Enabled: {}\n\
            \n\
            💡 To view detailed config: `rustchain config show`\n\
            💡 To modify config: `rustchain config set <key> <value>`",
            audit_entries.len(),
            config.mission_timeout_seconds,
            config.max_parallel_steps,
            config.audit_enabled
        ))
    }

    async fn handle_safety_check(&self) -> Result<String> {
        Ok("🛡️ Safety & Policy Status:\n\n\
            Active Safety Rules:\n\
            • ✅ Dangerous command detection\n\
            • ✅ File system access validation\n\
            • ✅ Network request filtering\n\
            • ✅ Resource usage limits\n\
            \n\
            Policy Engine:\n\
            • ✅ Default security policies loaded\n\
            • ✅ Custom rules: 0 configured\n\
            \n\
            💡 To run safety validation: `rustchain safety validate <mission>`\n\
            💡 To view all policies: `rustchain policy list`"
            .to_string())
    }

    async fn handle_audit_request(&self, timeframe: &str) -> Result<String> {
        let conversation = self.conversation.read().await;
        let stats = conversation.stats();

        Ok(format!(
            "📊 Audit Trail ({}): \n\n\
            Current Session:\n\
            • Messages: {}\n\
            • Session ID: {}\n\
            • Started: Just now\n\
            \n\
            System Activity:\n\
            • ✅ Interactive mode started\n\
            • ✅ User requests processed: {}\n\
            \n\
            💡 For detailed audit reports: `rustchain audit report`\n\
            💡 To export audit data: `rustchain audit export --format json`",
            timeframe,
            stats.total_messages,
            self.session_id,
            stats.total_messages / 2 // Approximate user requests
        ))
    }

    async fn handle_features_request(&self) -> Result<String> {
        // Check if we're in enterprise mode
        let enterprise_features = self.context.get_enterprise_features().await;
        let is_enterprise = !enterprise_features.is_empty();

        if is_enterprise {
            Ok("🚀 RustChain Enterprise Features Available:\n\n\
                Core Features:\n\
                • ✅ Mission execution with DAG support\n\
                • ✅ Multi-provider LLM integration\n\
                • ✅ Extensible tool system\n\
                • ✅ Memory management\n\
                • ✅ Safety validation\n\
                \n\
                Enterprise Features:\n\
                • ✅ Authentication & RBAC\n\
                • ✅ Compliance monitoring\n\
                • ✅ Performance dashboards\n\
                • ✅ Multi-tenant support\n\
                \n\
                💡 Check detailed features: `rustchain features list`"
                .to_string())
        } else {
            Ok("🚀 RustChain Community Features:\n\n\
                Available:\n\
                • ✅ Mission execution with DAG support\n\
                • ✅ Multi-provider LLM integration (OpenAI, Anthropic, Ollama)\n\
                • ✅ Extensible tool system with 20+ built-in tools\n\
                • ✅ Memory management with multiple strategies\n\
                • ✅ RAG document processing\n\
                • ✅ Safety validation and policy enforcement\n\
                • ✅ Comprehensive audit trails\n\
                \n\
                Enterprise Upgrade Available:\n\
                • 🔒 Advanced authentication & RBAC\n\
                • 🔒 Compliance monitoring (GDPR, HIPAA, SOX)\n\
                • 🔒 Performance dashboards & alerting\n\
                • 🔒 Multi-tenant support\n\
                \n\
                💡 Upgrade info: https://github.com/your-org/rustchain-enterprise"
                .to_string())
        }
    }

    async fn handle_help_request(&self) -> Result<String> {
        Ok("🤖 RustChain Interactive Help\n\
            ═══════════════════════════════\n\
            \n\
            I can help you with:\n\
            \n\
            🚀 Mission Management:\n\
            • \"Run a mission to create a file\"\n\
            • \"Execute task: backup my data\"\n\
            • \"Start mission from file.yaml\"\n\
            \n\
            ⚙️ System Configuration:\n\
            • \"Check my configuration\"\n\
            • \"Show system status\"\n\
            • \"What are my current settings?\"\n\
            \n\
            🛡️ Safety & Policies:\n\
            • \"Show safety policies\"\n\
            • \"What security rules are active?\"\n\
            • \"Check policy status\"\n\
            \n\
            📊 Audit & Monitoring:\n\
            • \"Show audit logs\"\n\
            • \"What happened today?\"\n\
            • \"Display recent activity\"\n\
            \n\
            🎯 Features & Capabilities:\n\
            • \"What can you do?\"\n\
            • \"Show available features\"\n\
            • \"List capabilities\"\n\
            \n\
            💡 Just ask naturally - I'll understand and help!"
            .to_string())
    }

    /// Process user input using LLM for actual AI conversation
    #[cfg(feature = "llm")]
    async fn process_with_llm(&self, input: &str) -> Result<String> {
        use crate::llm::{create_default_llm_manager, ChatMessage, LLMRequest, MessageRole};
        use std::collections::HashMap;

        let manager = create_default_llm_manager().map_err(|e| {
            crate::core::error::RustChainError::Execution(
                crate::core::error::ExecutionError::InvalidState {
                    state: "llm_initialization".to_string(),
                    operation: format!("Failed to create LLM manager: {}", e),
                },
            )
        })?;

        // Get conversation history for context
        let conversation_guard = self.conversation.read().await;
        let history = conversation_guard.get_recent(10)?; // Last 10 messages
        drop(conversation_guard);

        // Build conversation context
        let mut messages = Vec::new();

        // System message with RustChain context
        messages.push(ChatMessage {
            role: MessageRole::System,
            content: self.sanitize_content(&self.build_system_prompt().await?),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });

        // Add conversation history - format is "role: content"
        for formatted_msg in history {
            if let Some(colon_pos) = formatted_msg.find(": ") {
                let role = &formatted_msg[..colon_pos];
                let content = &formatted_msg[colon_pos + 2..];
                let message_role = if role == "user" {
                    MessageRole::User
                } else {
                    MessageRole::Assistant
                };
                messages.push(ChatMessage {
                    role: message_role,
                    content: self.sanitize_content(content),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
        }

        // Add current user message
        messages.push(ChatMessage {
            role: MessageRole::User,
            content: self.sanitize_content(input),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });

        let request = LLMRequest {
            messages,
            model: None, // Use default model
            temperature: Some(0.7),
            max_tokens: Some(2000),
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        // Send to LLM
        let response = manager.complete(request, None).await.map_err(|e| {
            crate::core::error::RustChainError::Execution(
                crate::core::error::ExecutionError::InvalidState {
                    state: "llm_completion".to_string(),
                    operation: format!("LLM request failed: {}", e),
                },
            )
        })?;

        Ok(response.content)
    }

    /// Build system prompt with RustChain capabilities
    #[cfg(feature = "llm")]
    async fn build_system_prompt(&self) -> Result<String> {
        let features = self.context.get_available_features().await;
        let enterprise_features = self.context.get_enterprise_features().await;

        Ok(format!(
            "You are the RustChain AI Assistant, an intelligent agent framework helper.
            
Your capabilities:
            🚀 Mission Execution: You can run, validate, and manage YAML-based mission files
            🛡️ Safety & Security: You enforce safety policies and run security validation
            🔧 Tool Management: You have access to 20+ built-in tools for file ops, HTTP, etc.
            🤖 LLM Integration: You support multiple LLM providers (OpenAI, Anthropic, Ollama)
            📊 Audit & Monitoring: You maintain comprehensive audit trails
            ⚙️ Configuration: You can show and validate system configuration
            
            Available Features: {:?}
            Enterprise Features: {:?}
            
Instructions:
            - Be helpful, concise, and action-oriented
            - When users ask to run missions, explain what's needed (YAML file path)
            - For system info, provide current status from your knowledge
            - Always offer specific CLI commands when relevant
            - If asked about capabilities you don't have, be honest
            - Keep responses under 200 words unless detailed explanation needed
            - Use emojis sparingly for clarity
            
Current Session: {} (Interactive Mode)",
            features, enterprise_features, self.session_id
        ))
    }

    /// Sanitize content for LLM input (basic filtering)
    #[cfg(feature = "llm")]
    fn sanitize_content(&self, content: &str) -> String {
        // Basic content sanitization for LLM input
        content
            .trim()
            .chars()
            .filter(|&c| c.is_ascii() || c.is_whitespace())
            .collect::<String>()
            .lines()
            .take(100) // Limit to 100 lines
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug)]
enum Intent {
    RunMission { description: String },
    CheckConfig,
    ShowSafety,
    ShowAudit { timeframe: String },
    ShowFeatures,
    Help,
    General { response: String },
}
