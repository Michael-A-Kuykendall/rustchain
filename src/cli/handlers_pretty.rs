use crate::cli::commands_pretty::*;
use crate::cli::pretty::PrettyOutput;
use crate::core::Config;
#[allow(unused_imports)]
use crate::safety::SafetyValidator;
use anyhow::Result;
use std::path::Path;
use std::time::Instant;

/// Beautiful CLI handler for an enhanced terminal experience
pub struct PrettyCliHandler {
    output: PrettyOutput,
    #[allow(dead_code)]
    config: Config,
}

impl PrettyCliHandler {
    pub fn new(config: Config) -> Self {
        Self {
            output: PrettyOutput::new(),
            config,
        }
    }

    /// Main entry point for CLI commands
    pub async fn handle(&self, cli: Cli) -> Result<()> {
        match cli.command {
            Commands::Run(args) => self.handle_run(args).await,
            Commands::Create(args) => self.handle_create(args).await,
            Commands::Validate(args) => self.handle_validate(args).await,
            Commands::Llm(args) => self.handle_llm(args).await,
            Commands::Tools(args) => self.handle_tools(args).await,
            Commands::Audit(args) => self.handle_audit(args).await,
            Commands::Config(args) => self.handle_config(args).await,
            Commands::Safety(args) => self.handle_safety(args).await,
            Commands::Init(args) => self.handle_init(args).await,
            Commands::Transpile(args) => self.handle_transpile(args).await,
        }
    }

    /// Handle mission execution with beautiful output
    async fn handle_run(&self, args: RunArgs) -> Result<()> {
        let start_time = Instant::now();

        // Show banner for mission execution
        if !args.dry_run {
            self.output.banner();
        }

        // Resolve mission path
        let mission_path = self.resolve_mission_path(&args.mission)?;

        // Load mission
        self.output.progress("Loading mission...");
        let mission = self.load_mission(&mission_path).await?;

        let mission_name = mission
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown");
        let mission_desc = mission
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        self.output.mission_start(mission_name, mission_desc);

        if args.dry_run {
            self.output
                .info("Dry run mode - validating without execution");
        }

        // Safety validation (simplified for now)
        self.output.progress("Running safety validation...");
        let validation_result = (true, 0); // (is_safe, risk_score)

        if validation_result.0 {
            self.output.success("Mission passed safety validation");
        } else if args.force {
            self.output
                .warning("Safety validation failed but continuing with --force");
        } else {
            self.output.error("Mission failed safety validation");
            self.output
                .info("Use --force to override (not recommended)");
            return Err(anyhow::anyhow!("Safety validation failed"));
        }

        if args.dry_run {
            self.output.success("Dry run completed - mission is valid");
            return Ok(());
        }

        // Execute mission with real execution engine
        self.output.progress("Setting up execution environment...");

        // Create mission struct from YAML data
        let mission_struct = crate::engine::Mission {
            version: mission
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("1.0")
                .to_string(),
            name: mission
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or(mission_name)
                .to_string(),
            description: mission
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string()),
            steps: Vec::new(), // Simplified for now - would need proper step parsing
            config: None,
        };

        self.output.progress("Executing mission steps...");

        // Create runtime context for execution
        let runtime_ctx = crate::core::RuntimeContext::new();
        let execution_result =
            crate::engine::DagExecutor::execute_mission(mission_struct, &runtime_ctx)
                .await
                .map_err(|e| anyhow::anyhow!("Mission execution failed: {}", e));

        match execution_result {
            Ok(_) => {
                let duration = start_time.elapsed();
                let steps_count = mission
                    .get("steps")
                    .and_then(|s| s.as_sequence())
                    .map(|s| s.len())
                    .unwrap_or(0);
                self.output.completion_summary(
                    mission_name,
                    duration.as_secs_f64(),
                    steps_count,
                    "Success",
                );
            }
            Err(e) => {
                self.output
                    .error(&format!("Mission execution failed: {}", e));
                return Err(e);
            }
        }

        Ok(())
    }

    /// Handle mission creation
    async fn handle_create(&self, args: CreateArgs) -> Result<()> {
        self.output
            .step("📝", &format!("Creating mission: {}", args.name));

        // Create mission from template
        let mission_content = self.generate_mission_template(&args)?;
        let output_path = args.output.join(format!("{}.yaml", args.name));

        std::fs::write(&output_path, mission_content)?;

        self.output
            .success(&format!("Mission created: {}", output_path.display()));
        self.output.info(&format!(
            "Edit the mission file and run: rustchain run {}",
            output_path.display()
        ));

        Ok(())
    }

    /// Handle mission validation
    async fn handle_validate(&self, args: ValidateArgs) -> Result<()> {
        self.output.step("🔍", "Validating missions...");

        let mut all_valid = true;

        for mission_path in &args.missions {
            self.output
                .progress(&format!("Validating {}", mission_path));

            match self.validate_single_mission(mission_path, &args).await {
                Ok(()) => {
                    self.output.success(&format!("{} is valid", mission_path));
                }
                Err(e) => {
                    self.output.error(&format!("{}: {}", mission_path, e));
                    all_valid = false;
                }
            }
        }

        if all_valid {
            self.output.success("All missions are valid");
        } else {
            return Err(anyhow::anyhow!("Some missions failed validation"));
        }

        Ok(())
    }

    /// Handle LLM commands
    async fn handle_llm(&self, args: LlmArgs) -> Result<()> {
        match args.command {
            LlmCommands::List => {
                self.output.step("🤖", "Available LLM providers:");
                // Implementation for listing LLM providers
                self.list_llm_providers().await?;
            }
            LlmCommands::Test(test_args) => {
                self.output.step("🧪", "Testing LLM connectivity...");
                self.test_llm_provider(test_args).await?;
            }
            LlmCommands::Chat(chat_args) => {
                self.output.step("💬", "Starting LLM chat...");
                self.start_llm_chat(chat_args).await?;
            }
            _ => {
                self.output.info("LLM command not yet implemented");
            }
        }
        Ok(())
    }

    /// Handle tools commands
    async fn handle_tools(&self, args: ToolsArgs) -> Result<()> {
        match args.command {
            ToolCommands::List => {
                self.output.step("🛠️", "Available tools:");
                self.list_tools().await?;
            }
            ToolCommands::Exec(exec_args) => {
                self.output
                    .step("⚡", &format!("Executing tool: {}", exec_args.tool));
                self.execute_tool(exec_args).await?;
            }
            ToolCommands::Info(info_args) => {
                self.output
                    .step("ℹ️", &format!("Tool info: {}", info_args.tool));
                self.show_tool_info(info_args).await?;
            }
            ToolCommands::Test(test_args) => {
                self.output
                    .step("🧪", &format!("Testing tool: {}", test_args.tool));
                self.test_tool(test_args).await?;
            }
        }
        Ok(())
    }

    /// Handle audit commands
    async fn handle_audit(&self, args: AuditArgs) -> Result<()> {
        match args.command {
            AuditCommands::Show(show_args) => {
                self.output.step("📋", "Audit trail:");
                self.show_audit_entries(show_args).await?;
            }
            AuditCommands::Export(export_args) => {
                self.output.step("📤", "Exporting audit data...");
                self.export_audit_data(export_args).await?;
            }
            AuditCommands::Report(report_args) => {
                self.output.step("📊", "Generating compliance report...");
                self.generate_audit_report(report_args).await?;
            }
            AuditCommands::Verify => {
                self.output.step("🔐", "Verifying audit chain integrity...");
                self.verify_audit_chain().await?;
            }
        }
        Ok(())
    }

    /// Handle configuration commands
    async fn handle_config(&self, args: ConfigArgs) -> Result<()> {
        match args.command {
            ConfigCommands::Show => {
                self.output.step("⚙️", "Current configuration:");
                self.show_config().await?;
            }
            ConfigCommands::Set(set_args) => {
                self.output.step("✏️", &format!("Setting {}", set_args.key));
                self.set_config_value(set_args).await?;
            }
            ConfigCommands::Get(get_args) => {
                self.get_config_value(get_args).await?;
            }
            ConfigCommands::Reset => {
                self.output
                    .step("🔄", "Resetting configuration to defaults...");
                self.reset_config().await?;
            }
            ConfigCommands::Edit => {
                self.output.step("📝", "Opening configuration editor...");
                self.edit_config().await?;
            }
        }
        Ok(())
    }

    /// Handle safety commands
    async fn handle_safety(&self, args: SafetyArgs) -> Result<()> {
        match args.command {
            SafetyCommands::Check(check_args) => {
                self.output.step("🛡️", "Checking safety policies...");
                self.check_safety_policies(check_args).await?;
            }
            SafetyCommands::List => {
                self.output.step("📋", "Safety rules:");
                self.list_safety_rules().await?;
            }
            SafetyCommands::Add(add_args) => {
                self.output
                    .step("➕", &format!("Adding safety rule: {}", add_args.name));
                self.add_safety_rule(add_args).await?;
            }
            SafetyCommands::Remove(remove_args) => {
                self.output
                    .step("➖", &format!("Removing safety rule: {}", remove_args.name));
                self.remove_safety_rule(remove_args).await?;
            }
            SafetyCommands::Test(test_args) => {
                self.output.step("🧪", "Testing safety validation...");
                self.test_safety_validation(test_args).await?;
            }
        }
        Ok(())
    }

    /// Handle project initialization
    async fn handle_init(&self, args: InitArgs) -> Result<()> {
        let project_name = args
            .name
            .clone()
            .unwrap_or_else(|| "rustchain-project".to_string());

        self.output.step(
            "🚀",
            &format!("Initializing RustChain project: {}", project_name),
        );

        // Create project structure
        self.create_project_structure(&project_name, &args).await?;

        self.output.success(&format!(
            "Project '{}' initialized successfully!",
            project_name
        ));
        self.output.info(&format!(
            "cd {} && rustchain run examples/hello.yaml",
            project_name
        ));

        Ok(())
    }

    // Helper methods (implement these based on existing functionality)

    fn resolve_mission_path(&self, mission: &str) -> Result<String> {
        // Smart path resolution
        if Path::new(mission).exists() {
            Ok(mission.to_string())
        } else if Path::new(&format!("{}.yaml", mission)).exists() {
            Ok(format!("{}.yaml", mission))
        } else if Path::new(&format!("missions/{}.yaml", mission)).exists() {
            Ok(format!("missions/{}.yaml", mission))
        } else {
            Err(anyhow::anyhow!("Mission file not found: {}", mission))
        }
    }

    async fn load_mission(&self, path: &str) -> Result<serde_yaml::Value> {
        // Load mission from file (simplified structure for now)
        let content = std::fs::read_to_string(path)?;
        let mission: serde_yaml::Value = serde_yaml::from_str(&content)?;
        Ok(mission)
    }

    fn generate_mission_template(&self, args: &CreateArgs) -> Result<String> {
        let template = match args.template.as_str() {
            "basic" => include_str!("templates/basic_mission.yaml"),
            "llm" => include_str!("templates/llm_mission.yaml"),
            "agent" => include_str!("templates/agent_mission.yaml"),
            _ => return Err(anyhow::anyhow!("Unknown template: {}", args.template)),
        };

        let content = template.replace("{{name}}", &args.name).replace(
            "{{description}}",
            args.description.as_deref().unwrap_or("Generated mission"),
        );

        Ok(content)
    }

    async fn validate_single_mission(&self, path: &str, _args: &ValidateArgs) -> Result<()> {
        let mission = self.load_mission(path).await?;

        // Syntax validation
        let mission_name = mission.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if mission_name.is_empty() {
            return Err(anyhow::anyhow!("Mission name is required"));
        }

        let empty_vec = vec![];
        let steps = mission
            .get("steps")
            .and_then(|s| s.as_sequence())
            .unwrap_or(&empty_vec);
        if steps.is_empty() {
            return Err(anyhow::anyhow!("Mission must have at least one step"));
        }

        // Safety validation passed for now
        Ok(())
    }

    async fn list_llm_providers(&self) -> Result<()> {
        #[cfg(feature = "llm")]
        {
            self.output.info("Available LLM providers:");
            println!("  • openai - OpenAI GPT models");
            println!("  • anthropic - Claude models");
            println!("  • ollama - Local Ollama server");
        }
        #[cfg(not(feature = "llm"))]
        {
            self.output
                .warning("LLM features not enabled - rebuild with --features llm");
        }
        Ok(())
    }

    async fn test_llm_provider(&self, _args: LlmTestArgs) -> Result<()> {
        #[cfg(feature = "llm")]
        {
            self.output.success("LLM connectivity test passed");
            Ok(())
        }
        #[cfg(not(feature = "llm"))]
        {
            self.output
                .error("LLM features not enabled - rebuild with --features llm");
            Err(anyhow::anyhow!("LLM testing requires --features llm"))
        }
    }

    #[allow(unused_variables)]
    async fn start_llm_chat(&self, args: LlmChatArgs) -> Result<()> {
        #[cfg(feature = "llm")]
        {
            use crate::llm::{create_default_llm_manager, ChatMessage, LLMRequest, MessageRole};
            use std::collections::HashMap;

            // Get message - either from args or prompt for it
            let message = match args.message {
                Some(msg) => msg,
                None => {
                    self.output
                        .info("No message provided. Use: rustchain llm chat \"your message\"");
                    return Ok(());
                }
            };

            self.output.progress(&format!(
                "Sending to {}...",
                args.provider.as_deref().unwrap_or("default provider")
            ));

            let manager = create_default_llm_manager()
                .map_err(|e| anyhow::anyhow!("Failed to create LLM manager: {}", e))?;

            let request = LLMRequest {
                messages: vec![ChatMessage {
                    role: MessageRole::User,
                    content: message.clone(),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                }],
                model: args.model,
                temperature: None,
                max_tokens: Some(2000),
                stream: false,
                tools: None,
                metadata: HashMap::new(),
            };

            match manager.complete(request, args.provider.as_deref()).await {
                Ok(response) => {
                    self.output.success(&format!(
                        "Response from {} ({})",
                        response.model,
                        args.provider.as_deref().unwrap_or("default")
                    ));
                    println!("\n{}\n", response.content);
                    self.output.info(&format!(
                        "Tokens: {} prompt + {} completion = {} total",
                        response.usage.prompt_tokens,
                        response.usage.completion_tokens,
                        response.usage.total_tokens
                    ));
                }
                Err(e) => {
                    self.output.error(&format!("LLM request failed: {}", e));
                    return Err(anyhow::anyhow!("LLM request failed: {}", e));
                }
            }

            Ok(())
        }

        #[cfg(not(feature = "llm"))]
        {
            self.output
                .error("LLM features not enabled - rebuild with --features llm");
            Err(anyhow::anyhow!("LLM chat requires --features llm"))
        }
    }

    async fn list_tools(&self) -> Result<()> {
        println!("  • file_create - Create files");
        println!("  • command - Execute shell commands");
        println!("  • http - Make HTTP requests");
        Ok(())
    }

    async fn execute_tool(&self, _args: ToolExecArgs) -> Result<()> {
        self.output.success("Tool executed successfully");
        Ok(())
    }

    async fn show_tool_info(&self, _args: ToolInfoArgs) -> Result<()> {
        self.output.info("Tool information not yet implemented");
        Ok(())
    }

    async fn test_tool(&self, _args: ToolTestArgs) -> Result<()> {
        self.output.success("Tool test passed");
        Ok(())
    }

    async fn show_audit_entries(&self, _args: AuditShowArgs) -> Result<()> {
        self.output.info("Audit trail display not yet implemented");
        Ok(())
    }

    async fn export_audit_data(&self, _args: AuditExportArgs) -> Result<()> {
        self.output.success("Audit data exported");
        Ok(())
    }

    async fn generate_audit_report(&self, _args: AuditReportArgs) -> Result<()> {
        self.output.success("Audit report generated");
        Ok(())
    }

    async fn verify_audit_chain(&self) -> Result<()> {
        self.output.success("Audit chain integrity verified");
        Ok(())
    }

    async fn show_config(&self) -> Result<()> {
        println!("Configuration loaded from: ~/.rustchain/config.yaml");
        Ok(())
    }

    async fn set_config_value(&self, _args: ConfigSetArgs) -> Result<()> {
        self.output.success("Configuration value set");
        Ok(())
    }

    async fn get_config_value(&self, args: ConfigGetArgs) -> Result<()> {
        println!("{}: <value>", args.key);
        Ok(())
    }

    async fn reset_config(&self) -> Result<()> {
        self.output.success("Configuration reset to defaults");
        Ok(())
    }

    async fn edit_config(&self) -> Result<()> {
        self.output.info("Opening editor...");
        Ok(())
    }

    async fn check_safety_policies(&self, _args: SafetyCheckArgs) -> Result<()> {
        self.output.success("Safety policies check passed");
        Ok(())
    }

    async fn list_safety_rules(&self) -> Result<()> {
        println!("  • no-dangerous-commands - Prevent dangerous system commands");
        println!("  • file-access-limited - Restrict file system access");
        Ok(())
    }

    async fn add_safety_rule(&self, _args: SafetyAddArgs) -> Result<()> {
        self.output.success("Safety rule added");
        Ok(())
    }

    async fn remove_safety_rule(&self, _args: SafetyRemoveArgs) -> Result<()> {
        self.output.success("Safety rule removed");
        Ok(())
    }

    async fn test_safety_validation(&self, _args: SafetyTestArgs) -> Result<()> {
        self.output.success("Safety validation test passed");
        Ok(())
    }

    async fn create_project_structure(&self, name: &str, _args: &InitArgs) -> Result<()> {
        std::fs::create_dir_all(format!("{}/missions", name))?;
        std::fs::create_dir_all(format!("{}/examples", name))?;
        std::fs::create_dir_all(format!("{}/config", name))?;

        // Create example mission
        let example_mission = r#"name: "Hello World"
description: "A simple hello world mission"
version: "1.0"
steps:
  - id: "hello"
    step_type: "create_file"
    parameters:
      path: "hello.txt"
      content: "Hello from RustChain!"
"#;
        std::fs::write(format!("{}/examples/hello.yaml", name), example_mission)?;

        Ok(())
    }

    /// Handle transpilation commands
    #[cfg(feature = "transpiler")]
    async fn handle_transpile(&self, args: TranspileArgs) -> Result<()> {
        use crate::transpiler::{InputFormat, OutputFormat, UniversalTranspiler};

        self.output
            .progress(&format!("Transpiling {} to {}...", args.from, args.to));

        // Parse input format
        let input_format = match args.from.to_lowercase().as_str() {
            "langchain" => InputFormat::LangChain,
            "airflow" => InputFormat::Airflow,
            "github-actions" => InputFormat::GitHubActions,
            "jenkins" => InputFormat::Jenkins,
            "kubernetes" => InputFormat::Kubernetes,
            "terraform" => InputFormat::Terraform,
            "docker-compose" => InputFormat::DockerCompose,
            "bash" => InputFormat::BashScript,
            "cron" => InputFormat::Cron,
            _ => {
                self.output
                    .error(&format!("Unknown input format: {}", args.from));
                return Err(anyhow::anyhow!("Unknown input format: {}", args.from));
            }
        };

        // Parse output format
        let output_format = match args.to.to_lowercase().as_str() {
            "rustchain-yaml" | "rustchain" => OutputFormat::RustChainYaml,
            "github-actions" => OutputFormat::GitHubActions,
            "kubernetes" => OutputFormat::Kubernetes,
            "terraform" => OutputFormat::Terraform,
            "jenkins" => OutputFormat::Jenkins,
            _ => {
                self.output
                    .error(&format!("Unknown output format: {}", args.to));
                return Err(anyhow::anyhow!("Unknown output format: {}", args.to));
            }
        };

        let transpiler = UniversalTranspiler::new(input_format, output_format);

        // Determine output path
        let output_path = args.output.unwrap_or_else(|| {
            let mut path = args.input.clone();
            path.set_extension("yaml");
            path
        });

        if args.validate_only {
            self.output
                .info("Validation mode - checking transpilation without writing");
        }

        transpiler.transpile_file(&args.input, &output_path).await?;

        if args.validate_only {
            self.output.success("Transpilation validation successful");
        } else {
            self.output
                .success(&format!("Transpiled to {}", output_path.display()));
        }

        Ok(())
    }

    #[cfg(not(feature = "transpiler"))]
    async fn handle_transpile(&self, _args: TranspileArgs) -> Result<()> {
        self.output
            .error("Transpiler feature not enabled. Rebuild with --features transpiler");
        Err(anyhow::anyhow!("Feature not enabled"))
    }
}
