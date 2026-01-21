use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rustchain")]
#[command(about = "RustChain - Advanced AI Agent Framework")]
#[command(
    long_about = "RustChain is a powerful AI orchestration framework built in Rust.

Execute missions, chat with AI models, manage tools, and ensure safety across
all AI operations. Designed for developers, researchers, and enterprises.

QUICK START:
    rustchain run examples/hello_world.yaml    # Run your first mission
    rustchain interactive                       # Start conversational mode
    rustchain mission list                      # List available missions
    rustchain safety validate mission.yaml     # Validate mission safety

For detailed help on any command, use: rustchain <COMMAND> --help
Documentation: https://github.com/Michael-A-Kuykendall/rustchain"
)]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start interactive conversational mode
    ///
    /// Interactive mode provides a natural conversation interface for
    /// creating missions, executing tasks, and exploring RustChain capabilities.
    /// Suitable for experimentation and learning.
    #[command(long_about = "Start an interactive session where you can:
• Have natural conversations with AI models
• Create and execute missions dynamically  
• Get real-time help and guidance
• Explore RustChain capabilities interactively

Example session:
$ rustchain interactive
> create a mission to analyze my Rust codebase
> run the generated mission  
> show me performance metrics")]
    Interactive,

    /// Execute a mission directly from a YAML file
    ///
    /// Missions define AI workflows with steps like LLM calls, tool execution,
    /// file operations, and more. Use --dry-run to validate before executing.
    #[command(long_about = "Execute a RustChain mission file with safety validation.

MISSION FILE EXAMPLE:
name: \"Hello World\"
description: \"Simple demonstration\"
version: \"1.0\"
steps:
  - id: \"greet\"
    step_type: \"llm\"
    parameters:
      provider: \"openai\"
      model: \"gpt-4\"
      prompt: \"Say hello in a creative way\"

BEST PRACTICES:
• Always validate with --dry-run first
• Review safety warnings before proceeding
• Start with simple missions and build complexity
• Keep mission files in version control")]
    Run {
        /// Path to the mission file to execute
        #[arg(help = "Path to YAML mission file (e.g., examples/hello_world.yaml)")]
        mission: String,
        /// Perform a dry run without executing tools (recommended first step)
        #[arg(
            short,
            long,
            help = "Validate and plan execution without running tools - safe to use"
        )]
        dry_run: bool,
        /// Skip safety validation (use with caution on trusted missions)
        #[arg(
            short,
            long,
            help = "Skip safety validation - only use with trusted missions"
        )]
        skip_safety: bool,
    },
    /// Mission management operations
    ///
    /// Create, validate, and manage mission files. Missions are YAML files
    /// that define AI workflows with multiple steps.
    #[command(long_about = "Mission management for RustChain workflows.

COMMON OPERATIONS:
• List example missions: rustchain mission list
• Validate mission file: rustchain mission validate mission.yaml  
• Get mission details: rustchain mission info mission.yaml

VALIDATION CHECKS:
CHECKS: YAML syntax correctness
CHECKS: Required fields present  
CHECKS: Step dependencies resolved
CHECKS: Parameter requirements met")]
    Mission {
        #[command(subcommand)]
        action: MissionAction,
    },

    /// Policy operations and security governance
    ///
    /// Configure and manage security policies that control what
    /// missions and tools can do in your environment.
    #[command(long_about = "Security policy management for safe AI operations.

POLICY TYPES:
FILE ACCESS: Control file system operations
NETWORK POLICY: Manage external connections  
COMMAND EXECUTION: Restrict system commands
LLM SAFETY: Filter AI interactions

COMMANDS:
• View active policies: rustchain policy list
• Check policy status: rustchain policy status
• Validate configuration: rustchain policy validate")]
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Safety validation and security checks
    ///
    /// Comprehensive security analysis for missions and system configuration.
    /// Always validate missions before execution in production.
    #[command(long_about = "Security validation and risk assessment.

SAFETY FEATURES:
MISSION ANALYSIS: Review all mission steps
RISK ASSESSMENT: Evaluate security implications
POLICY COMPLIANCE: Check against active policies

RISK LEVELS:
LOW: Safe to execute
MEDIUM: Review recommended  
HIGH: Caution required
CRITICAL: Do not execute

BEST PRACTICE: Always run 'rustchain safety validate' before executing missions")]
    Safety {
        #[command(subcommand)]
        action: SafetyAction,
    },
    /// Tool management and execution
    ///
    /// RustChain provides a rich ecosystem of tools for file operations,
    /// network requests, system commands, and AI interactions.
    #[cfg(feature = "tools")]
    #[command(long_about = "Tool management and direct execution.

TOOL CATEGORIES:
FILE OPERATIONS: file_create, file_read, file_write
NETWORK OPERATIONS: http_request, websocket_connect  
SYSTEM OPERATIONS: command_execute, process_info
AI OPERATIONS: llm_call, embedding_generate

EXAMPLES:
• List all tools: rustchain tools list
• Get tool info: rustchain tools info file_create
• Execute tool: rustchain tools execute file_create --params '{\"path\":\"test.txt\",\"content\":\"Hello\"}'

All tools respect security policies and run in controlled environments.")]
    Tools {
        #[command(subcommand)]
        action: ToolAction,
    },

    /// LLM operations and AI model interactions
    ///
    /// Chat with AI models, list available providers, and test connectivity.
    /// Supports OpenAI, Anthropic, Ollama and custom providers.
    #[cfg(feature = "llm")]
    #[command(long_about = "AI model interactions and management.

SUPPORTED PROVIDERS:
• OpenAI - GPT-3.5, GPT-4, GPT-4 Turbo
• Anthropic - Claude 3 family (Haiku, Sonnet, Opus)
• Ollama - Local models (Llama, Mistral, CodeLlama)
• Custom providers via API configuration

EXAMPLES:
Note: LLM commands are available when compiled with 'llm' feature flag
• Interactive mode: rustchain interactive
• Mission execution: rustchain run examples/chat_mission.yaml
• Safety validation: rustchain safety validate mission.yaml

SETUP: Configure API keys in environment variables or config file.")]
    LLM {
        #[command(subcommand)]
        action: LLMAction,
    },
    /// RAG operations
    #[cfg(feature = "rag")]
    RAG {
        #[command(subcommand)]
        action: RAGAction,
    },
    /// Sandbox operations
    #[cfg(feature = "sandbox")]
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Server operations
    #[cfg(feature = "server")]
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Audit operations
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Build dashboard and system health tracking
    Build {
        #[command(subcommand)]
        action: BuildAction,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Universal workflow transpilation - Technical Demonstration Ready
    ///
    /// Convert workflows between different platforms and formats.
    /// Supports bidirectional conversion with high fidelity.
    #[command(long_about = "Universal workflow transpilation between platforms.

SUPPORTED FORMATS:
INPUT FORMATS:
  • LangChain Python scripts (.py)
  • Airflow DAGs (.py)
  • GitHub Actions workflows (.yml)
  • Kubernetes manifests (.yaml)
  • Docker Compose files (.yml)
  • Jenkins pipelines (Jenkinsfile)
  • Terraform configurations (.tf)
  • Bash scripts (.sh)
  • Cron expressions

OUTPUT FORMATS:
  • RustChain YAML missions
  • All input formats (bidirectional)

FEATURES:
  • Workflow conversion between formats
  • Authentication configuration preservation
  • Dependency resolution

EXAMPLES:
  # Convert LangChain to RustChain
  rustchain transpile lang-chain pipeline.py --output rustchain.yaml
  
  # Convert GitHub Actions to RustChain
  rustchain transpile git-hub-actions workflow.yml

Note: Transpilation quality varies by format. Complex workflows may need manual adjustment.")]
    Transpile {
        #[command(subcommand)]
        action: TranspileAction,
    },

    /// Benchmarking suite for performance comparisons
    ///
    /// Compare RustChain performance against other workflow frameworks.
    /// Results depend on hardware and workload.
    #[command(long_about = "Performance benchmarking suite.

SUPPORTED COMPARISONS:
  • LangChain Python
  • Apache Airflow
  • GitHub Actions
  • Jenkins Pipeline

METRICS:
  • Execution time (milliseconds)
  • Memory usage (MB)
  • CPU usage (%)

Note: Benchmark results depend on hardware, configuration, and workload.
Run your own benchmarks to validate performance claims.

EXAMPLES:
  # Run benchmark suite
  rustchain benchmark showdown

  # Generate report
  rustchain benchmark report --output benchmarks.md")]
    Benchmark {
        #[command(subcommand)]
        action: BenchmarkAction,
    },
}

#[derive(Subcommand)]
pub enum MissionAction {
    /// List available missions
    List,
    /// Validate a mission file
    Validate {
        /// Path to mission file
        file: String,
    },
    /// Show mission information
    Info {
        /// Path to mission file
        file: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyAction {
    /// List active policies
    List,
    /// Validate policy configuration
    Validate,
    /// Show policy status
    Status,
}

#[derive(Subcommand)]
pub enum SafetyAction {
    /// Validate a mission file
    Validate {
        /// Path to mission file
        mission: String,
        /// Use strict mode (fail on warnings)
        #[arg(long)]
        strict: bool,
    },
    /// Run safety validation checks
    Check {
        /// Include policy validation
        #[arg(long)]
        include_policies: bool,
    },
    /// Generate safety report
    Report {
        /// Path to mission file
        mission: String,
        /// Output format (json, yaml, text)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

#[cfg(feature = "tools")]
#[derive(Subcommand)]
pub enum ToolAction {
    /// List available tools
    List,
    /// Show tool information
    Info {
        /// Tool name
        name: String,
    },
    /// Execute a tool
    Execute {
        /// Tool name
        name: String,
        /// Tool parameters as JSON
        #[arg(short, long)]
        params: Option<String>,
    },
}

#[cfg(feature = "llm")]
#[derive(Subcommand)]
pub enum LLMAction {
    /// List available models
    Models {
        /// Specific provider to list
        #[arg(short, long)]
        provider: Option<String>,
    },
    /// Chat with an LLM
    Chat {
        /// Message to send
        message: String,
        /// Model to use
        #[arg(short, long)]
        model: Option<String>,
        /// Provider to use
        #[arg(short, long)]
        provider: Option<String>,
        /// Temperature (0.0-2.0)
        #[arg(short, long)]
        temperature: Option<f32>,
    },
    /// Test LLM connectivity
    Test {
        /// Provider to test
        provider: Option<String>,
    },
}

#[cfg(feature = "rag")]
#[derive(Subcommand)]
pub enum RAGAction {
    /// Add a document to the RAG system
    Add {
        /// Document ID
        #[arg(short, long)]
        id: String,
        /// Path to document file
        #[arg(short, long)]
        file: String,
        /// Document metadata (JSON format)
        #[arg(short, long)]
        metadata: Option<String>,
    },
    /// Search documents in the RAG system
    Search {
        /// Search query
        query: String,
        /// Maximum number of results
        #[arg(short, long, default_value = "5")]
        limit: usize,
        /// Minimum similarity threshold
        #[arg(short, long)]
        threshold: Option<f32>,
    },
    /// List documents in the RAG system
    List {
        /// Number of documents to skip
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Maximum number of documents to list
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Delete a document from the RAG system
    Delete {
        /// Document ID to delete
        id: String,
    },
    /// Get context for a query
    Context {
        /// Query to get context for
        query: String,
        /// Maximum context length in characters
        #[arg(short, long, default_value = "2000")]
        max_length: usize,
    },
}

#[cfg(feature = "sandbox")]
#[derive(Subcommand)]
pub enum SandboxAction {
    /// Create a new sandbox session
    Create,
    /// Execute a command in a sandbox session
    Execute {
        /// Session ID
        #[arg(short, long)]
        session: String,
        /// Command to execute
        command: String,
        /// Command arguments
        args: Vec<String>,
    },
    /// Write a file to a sandbox session
    Write {
        /// Session ID
        #[arg(short, long)]
        session: String,
        /// File path (relative to sandbox)
        #[arg(short, long)]
        file: String,
        /// File content
        #[arg(short, long)]
        content: String,
    },
    /// Read a file from a sandbox session
    Read {
        /// Session ID
        #[arg(short, long)]
        session: String,
        /// File path (relative to sandbox)
        #[arg(short, long)]
        file: String,
    },
    /// List files in a sandbox session
    Files {
        /// Session ID
        #[arg(short, long)]
        session: String,
    },
    /// Get session information
    Info {
        /// Session ID
        #[arg(short, long)]
        session: String,
    },
    /// Destroy a sandbox session
    Destroy {
        /// Session ID
        #[arg(short, long)]
        session: String,
    },
    /// List all sandbox sessions
    List,
    /// Clean up a sandbox session
    Cleanup {
        /// Session ID
        #[arg(short, long)]
        session: String,
    },
    /// Clean up all sandbox sessions
    CleanupAll,
}

#[cfg(feature = "server")]
#[derive(Subcommand)]
pub enum ServerAction {
    /// Start the API server for Shimmy integration
    Start {
        /// Server host
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Server port
        #[arg(long, default_value = "8080")]
        port: u16,
        /// Enable CORS
        #[arg(long)]
        cors: bool,
        /// Enable agent mode for Shimmy TUI integration
        #[arg(long, help = "Enable agent mode for Shimmy TUI integration")]
        agent_mode: bool,
    },
    /// Get server configuration
    Config,
}

#[derive(Subcommand)]
pub enum AuditAction {
    /// Query audit entries
    Query {
        /// Start time (ISO 8601 format)
        #[arg(long)]
        start_time: Option<String>,
        /// End time (ISO 8601 format)
        #[arg(long)]
        end_time: Option<String>,
        /// Event types to filter by
        #[arg(long)]
        event_types: Option<Vec<String>>,
        /// Maximum number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,
        /// Number of results to skip
        #[arg(long, default_value = "0")]
        offset: usize,
    },
    /// Generate audit report
    Report {
        /// Start time (ISO 8601 format)
        #[arg(long)]
        start_time: Option<String>,
        /// End time (ISO 8601 format)
        #[arg(long)]
        end_time: Option<String>,
        /// Output format (json, yaml, csv)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    /// Verify audit chain integrity
    Verify,
    /// Export audit data
    Export {
        /// Output format (json, yaml, csv)
        #[arg(short, long, default_value = "json")]
        format: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Show audit statistics
    Stats,
}

#[derive(Subcommand, Debug)]
pub enum BuildAction {
    /// Show build dashboard with system health
    Dashboard,
    /// Generate build status report
    Status,
    /// Update build dashboard with current test results
    Update,
    /// Save dashboard to file
    Save {
        /// Output file path
        #[arg(short, long, default_value = "build_dashboard.json")]
        output: String,
    },
    /// Load dashboard from file
    Load {
        /// Input file path
        #[arg(short, long)]
        input: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    /// Validate configuration
    Validate,
    /// Initialize default configuration
    Init,
}

#[derive(Subcommand, Debug)]
pub enum AuthAction {
    /// Initialize JWT authentication
    InitJWT {
        /// JWT secret key
        #[arg(short, long)]
        secret: Option<String>,
    },
    /// Configure OAuth2 integration
    SetupOAuth2 {
        /// OAuth2 provider
        provider: String,
        /// Client ID
        #[arg(short, long)]
        client_id: String,
    },
    /// Configure RBAC system
    SetupRBAC {
        /// Path to roles configuration file
        #[arg(short, long)]
        roles_file: String,
    },
    /// Test authentication configuration
    Test,
}

/// Universal workflow transpilation actions - Technical Demonstration Ready
#[derive(Subcommand, Debug)]
pub enum TranspileAction {
    /// Convert LangChain Python script to RustChain YAML
    ///
    /// Enterprise-grade transpilation with complete feature preservation
    LangChain {
        /// Path to LangChain Python file
        input: String,
        /// Output file path (optional, defaults to input with .yaml extension)
        #[arg(short, long)]
        output: Option<String>,
        /// Optimize for performance during conversion
        #[arg(long)]
        optimize: bool,
    },

    /// Convert Airflow DAG to RustChain YAML
    ///
    /// Preserves task dependencies, operators, and scheduling configuration
    Airflow {
        /// Path to Airflow DAG Python file
        input: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        /// Include enterprise features
        #[arg(long)]
        enterprise: bool,
    },

    /// Convert GitHub Actions workflow to RustChain YAML
    ///
    /// Maintains CI/CD pipeline logic, matrix strategies, and secrets
    GitHubActions {
        /// Path to GitHub Actions YAML file
        input: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        /// Preserve enterprise CI/CD patterns
        #[arg(long)]
        preserve_enterprise: bool,
    },

    /// Convert Kubernetes manifest to RustChain YAML
    ///
    /// Translates K8s resources to equivalent RustChain steps
    Kubernetes {
        /// Path to Kubernetes YAML file
        input: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        /// Include production-grade features
        #[arg(long)]
        production: bool,
    },

    /// Convert Docker Compose to RustChain YAML
    ///
    /// Preserves service dependencies, networking, and volumes
    DockerCompose {
        /// Path to Docker Compose YAML file
        input: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        /// Enable multi-service scaling features
        #[arg(long)]
        scale: bool,
    },

    /// Convert any supported format to RustChain YAML (auto-detect)
    ///
    /// Automatically detects input format and applies appropriate transpilation
    Auto {
        /// Path to input file (any supported format)
        input: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        /// Enable all enterprise features
        #[arg(long)]
        enterprise_mode: bool,
        /// Validate compliance after transpilation
        #[arg(long)]
        validate: bool,
    },

    /// Convert to ALL supported output formats (demo showcase)
    ///
    /// Creates equivalent workflows in every supported platform
    /// Suitable for technical demonstration showing universal portability
    ShowcaseAll {
        /// Path to input file
        input: String,
        /// Output directory for all generated formats
        #[arg(short, long, default_value = "transpiled_output")]
        output_dir: String,
        /// Run performance comparison across all platforms
        #[arg(long)]
        benchmark: bool,
        /// Include enterprise compliance validation
        #[arg(long)]
        enterprise_validation: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum MonitoringAction {
    /// Start metrics collection
    StartMetrics {
        /// Metrics port
        #[arg(short, long, default_value = "9090")]
        port: u16,
    },
    /// Show performance dashboard
    Dashboard,
    /// Configure alerting rules
    SetupAlerts {
        /// Path to alerts configuration
        #[arg(short, long)]
        config: String,
    },
    /// Show current metrics
    Metrics,
}

#[derive(Subcommand, Debug)]
pub enum MultiTenantAction {
    /// Create a new tenant
    CreateTenant {
        /// Tenant ID
        id: String,
        /// Tenant name
        name: String,
    },
    /// List all tenants
    ListTenants,
    /// Configure tenant isolation
    SetupIsolation {
        /// Tenant ID
        tenant: String,
        /// Isolation level
        #[arg(short, long)]
        level: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum BenchmarkAction {
    /// Run full competitive performance showdown vs all frameworks
    Showdown {
        /// Output detailed metrics
        #[arg(long)]
        verbose: bool,
        /// Save results to file
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Start live performance dashboard
    Dashboard {
        /// Dashboard refresh interval in seconds
        #[arg(long, default_value = "1")]
        refresh: u64,
        /// Port for web dashboard
        #[arg(long, default_value = "3000")]
        port: u16,
    },
    /// Generate technical competitive analysis report
    Report {
        /// Output file path
        #[arg(short, long, default_value = "technical-competitive-analysis.md")]
        output: String,
        /// Include detailed metrics
        #[arg(long)]
        detailed: bool,
    },
    /// Benchmark vs specific framework
    Versus {
        /// Framework to benchmark against
        #[arg(value_enum)]
        framework: BenchmarkFramework,
        /// Workflow file to test
        #[arg(short, long)]
        workflow: Option<String>,
    },
    /// Show live performance metrics
    Metrics,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum BenchmarkFramework {
    LangChain,
    Airflow,
    GitHubActions,
    Jenkins,
    Kubernetes,
    DockerCompose,
    Terraform,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::collapsible_match)] // explicit nesting for readability in CLI argument assertions
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_basic_structure() {
        // Test that the CLI can be parsed
        let cli = Cli::try_parse_from(["rustchain", "config", "show"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            assert!(matches!(cli.command, Commands::Config { .. }));
        }
    }

    #[test]
    fn test_run_command_basic() {
        let cli = Cli::try_parse_from(["rustchain", "run", "test.yaml"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Run {
                mission,
                dry_run,
                skip_safety,
            } = cli.command
            {
                assert_eq!(mission, "test.yaml");
                assert!(!dry_run);
                assert!(!skip_safety);
            }
        }
    }

    #[test]
    fn test_run_command_with_flags() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "run",
            "test.yaml",
            "--dry-run",
            "--skip-safety",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Run {
                mission,
                dry_run,
                skip_safety,
            } = cli.command
            {
                assert_eq!(mission, "test.yaml");
                assert!(dry_run);
                assert!(skip_safety);
            }
        }
    }

    #[test]
    fn test_mission_list_command() {
        let cli = Cli::try_parse_from(["rustchain", "mission", "list"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Mission { action } = cli.command {
                assert!(matches!(action, MissionAction::List));
            }
        }
    }

    #[test]
    fn test_mission_validate_command() {
        let cli = Cli::try_parse_from(["rustchain", "mission", "validate", "test.yaml"]);
        assert!(cli.is_ok());

        if let Ok(Cli {
            command:
                Commands::Mission {
                    action: MissionAction::Validate { file },
                },
        }) = cli
        {
            assert_eq!(file, "test.yaml");
        }
    }

    #[test]
    fn test_mission_info_command() {
        let cli = Cli::try_parse_from(["rustchain", "mission", "info", "test.yaml"]);
        assert!(cli.is_ok());

        if let Ok(Cli {
            command:
                Commands::Mission {
                    action: MissionAction::Info { file },
                },
        }) = cli
        {
            assert_eq!(file, "test.yaml");
        }
    }

    #[test]
    fn test_policy_commands() {
        let commands = [
            (["rustchain", "policy", "list"], PolicyAction::List),
            (["rustchain", "policy", "validate"], PolicyAction::Validate),
            (["rustchain", "policy", "status"], PolicyAction::Status),
        ];

        for (args, expected) in commands {
            let cli = Cli::try_parse_from(args);
            assert!(cli.is_ok(), "Failed to parse: {:?}", args);

            if let Ok(cli) = cli {
                if let Commands::Policy { ref action } = cli.command {
                    assert!(std::mem::discriminant(action) == std::mem::discriminant(&expected));
                }
            }
        }
    }

    #[test]
    fn test_safety_validate_command() {
        let cli = Cli::try_parse_from(["rustchain", "safety", "validate", "test.yaml"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Safety { action } = cli.command {
                if let SafetyAction::Validate { mission, strict } = action {
                    assert_eq!(mission, "test.yaml");
                    assert!(!strict);
                }
            }
        }
    }

    #[test]
    fn test_safety_validate_strict() {
        let cli = Cli::try_parse_from(["rustchain", "safety", "validate", "test.yaml", "--strict"]);
        assert!(cli.is_ok());

        if let Ok(Cli {
            command:
                Commands::Safety {
                    action: SafetyAction::Validate { mission, strict },
                },
        }) = cli
        {
            assert_eq!(mission, "test.yaml");
            assert!(strict);
        }
    }

    #[test]
    fn test_safety_check_command() {
        let cli = Cli::try_parse_from(["rustchain", "safety", "check", "--include-policies"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Safety { action } = cli.command {
                if let SafetyAction::Check { include_policies } = action {
                    assert!(include_policies);
                }
            }
        }
    }

    #[test]
    fn test_safety_report_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "safety",
            "report",
            "test.yaml",
            "--format",
            "json",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Safety { action } = cli.command {
                if let SafetyAction::Report { mission, format } = action {
                    assert_eq!(mission, "test.yaml");
                    assert_eq!(format, "json");
                }
            }
        }
    }

    #[cfg(feature = "tools")]
    #[test]
    fn test_tools_list_command() {
        let cli = Cli::try_parse_from(["rustchain", "tools", "list"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Tools { action } = cli.command {
                assert!(matches!(action, ToolAction::List));
            }
        }
    }

    #[cfg(feature = "tools")]
    #[test]
    fn test_tools_info_command() {
        let cli = Cli::try_parse_from(["rustchain", "tools", "info", "file_create"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Tools { action } = cli.command {
                if let ToolAction::Info { name } = action {
                    assert_eq!(name, "file_create");
                }
            }
        }
    }

    #[cfg(feature = "tools")]
    #[test]
    fn test_tools_execute_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "tools",
            "execute",
            "file_create",
            "--params",
            "{\"path\":\"test.txt\"}",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Tools { action } = cli.command {
                if let ToolAction::Execute { name, params } = action {
                    assert_eq!(name, "file_create");
                    assert_eq!(params, Some("{\"path\":\"test.txt\"}".to_string()));
                }
            }
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn test_llm_models_command() {
        let cli = Cli::try_parse_from(["rustchain", "llm", "models"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::LLM { action } = cli.command {
                if let LLMAction::Models { provider } = action {
                    assert!(provider.is_none());
                }
            }
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn test_llm_models_with_provider() {
        let cli = Cli::try_parse_from(["rustchain", "llm", "models", "--provider", "openai"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::LLM { action } = cli.command {
                if let LLMAction::Models { provider } = action {
                    assert_eq!(provider, Some("openai".to_string()));
                }
            }
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn test_llm_chat_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "llm",
            "chat",
            "Hello world",
            "--model",
            "gpt-4",
            "--provider",
            "openai",
            "--temperature",
            "0.7",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::LLM { action } = cli.command {
                if let LLMAction::Chat {
                    message,
                    model,
                    provider,
                    temperature,
                } = action
                {
                    assert_eq!(message, "Hello world");
                    assert_eq!(model, Some("gpt-4".to_string()));
                    assert_eq!(provider, Some("openai".to_string()));
                    assert_eq!(temperature, Some(0.7));
                }
            }
        }
    }

    #[cfg(feature = "llm")]
    #[test]
    fn test_llm_test_command() {
        let cli = Cli::try_parse_from(["rustchain", "llm", "test", "openai"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::LLM { action } = cli.command {
                if let LLMAction::Test { provider } = action {
                    assert_eq!(provider, Some("openai".to_string()));
                }
            }
        }
    }

    #[cfg(feature = "rag")]
    #[test]
    fn test_rag_add_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "rag",
            "add",
            "--id",
            "doc1",
            "--file",
            "document.pdf",
            "--metadata",
            "{\"type\":\"pdf\"}",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::RAG { action } = cli.command {
                if let RAGAction::Add { id, file, metadata } = action {
                    assert_eq!(id, "doc1");
                    assert_eq!(file, "document.pdf");
                    assert_eq!(metadata, Some("{\"type\":\"pdf\"}".to_string()));
                }
            }
        }
    }

    #[cfg(feature = "rag")]
    #[test]
    fn test_rag_search_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "rag",
            "search",
            "machine learning",
            "--limit",
            "10",
            "--threshold",
            "0.8",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::RAG { action } = cli.command {
                if let RAGAction::Search {
                    query,
                    limit,
                    threshold,
                } = action
                {
                    assert_eq!(query, "machine learning");
                    assert_eq!(limit, 10);
                    assert_eq!(threshold, Some(0.8));
                }
            }
        }
    }

    #[cfg(feature = "rag")]
    #[test]
    fn test_rag_list_command() {
        let cli =
            Cli::try_parse_from(["rustchain", "rag", "list", "--offset", "5", "--limit", "20"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::RAG { action } = cli.command {
                if let RAGAction::List { offset, limit } = action {
                    assert_eq!(offset, 5);
                    assert_eq!(limit, 20);
                }
            }
        }
    }

    #[cfg(feature = "rag")]
    #[test]
    fn test_rag_delete_command() {
        let cli = Cli::try_parse_from(["rustchain", "rag", "delete", "doc1"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::RAG { action } = cli.command {
                if let RAGAction::Delete { id } = action {
                    assert_eq!(id, "doc1");
                }
            }
        }
    }

    #[cfg(feature = "rag")]
    #[test]
    fn test_rag_context_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "rag",
            "context",
            "machine learning",
            "--max-length",
            "4000",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::RAG { action } = cli.command {
                if let RAGAction::Context { query, max_length } = action {
                    assert_eq!(query, "machine learning");
                    assert_eq!(max_length, 4000);
                }
            }
        }
    }

    #[cfg(feature = "sandbox")]
    #[test]
    fn test_sandbox_create_command() {
        let cli = Cli::try_parse_from(["rustchain", "sandbox", "create"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Sandbox { action } = cli.command {
                assert!(matches!(action, SandboxAction::Create));
            }
        }
    }

    #[cfg(feature = "sandbox")]
    #[test]
    fn test_sandbox_execute_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "sandbox",
            "execute",
            "--session",
            "session1",
            "ls",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Sandbox { action } = cli.command {
                if let SandboxAction::Execute {
                    session,
                    command,
                    args,
                } = action
                {
                    assert_eq!(session, "session1");
                    assert_eq!(command, "ls");
                    assert_eq!(args, Vec::<String>::new());
                }
            }
        }
    }

    #[cfg(feature = "sandbox")]
    #[test]
    fn test_sandbox_write_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "sandbox",
            "write",
            "--session",
            "session1",
            "--file",
            "test.txt",
            "--content",
            "Hello World",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Sandbox { action } = cli.command {
                if let SandboxAction::Write {
                    session,
                    file,
                    content,
                } = action
                {
                    assert_eq!(session, "session1");
                    assert_eq!(file, "test.txt");
                    assert_eq!(content, "Hello World");
                }
            }
        }
    }

    #[cfg(feature = "server")]
    #[test]
    fn test_server_start_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "server",
            "start",
            "--host",
            "0.0.0.0",
            "--port",
            "9090",
            "--cors",
            "--agent-mode",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Server { action } = cli.command {
                if let ServerAction::Start {
                    host,
                    port,
                    cors,
                    agent_mode,
                } = action
                {
                    assert_eq!(host, "0.0.0.0");
                    assert_eq!(port, 9090);
                    assert!(cors);
                    assert!(agent_mode);
                }
            }
        }
    }

    #[cfg(feature = "server")]
    #[test]
    fn test_server_config_command() {
        let cli = Cli::try_parse_from(["rustchain", "server", "config"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Server { action } = cli.command {
                assert!(matches!(action, ServerAction::Config));
            }
        }
    }

    #[test]
    fn test_audit_query_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "audit",
            "query",
            "--start-time",
            "2024-01-01T00:00:00Z",
            "--end-time",
            "2024-12-31T23:59:59Z",
            "--limit",
            "50",
            "--offset",
            "10",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Audit { action } = cli.command {
                if let AuditAction::Query {
                    start_time,
                    end_time,
                    event_types: _,
                    limit,
                    offset,
                } = action
                {
                    assert_eq!(start_time, Some("2024-01-01T00:00:00Z".to_string()));
                    assert_eq!(end_time, Some("2024-12-31T23:59:59Z".to_string()));
                    assert_eq!(limit, 50);
                    assert_eq!(offset, 10);
                }
            }
        }
    }

    #[test]
    fn test_audit_report_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "audit",
            "report",
            "--format",
            "csv",
            "--start-time",
            "2024-01-01T00:00:00Z",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Audit { action } = cli.command {
                if let AuditAction::Report {
                    start_time,
                    end_time: _,
                    format,
                } = action
                {
                    assert_eq!(start_time, Some("2024-01-01T00:00:00Z".to_string()));
                    assert_eq!(format, "csv");
                }
            }
        }
    }

    #[test]
    fn test_audit_verify_command() {
        let cli = Cli::try_parse_from(["rustchain", "audit", "verify"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Audit { action } = cli.command {
                assert!(matches!(action, AuditAction::Verify));
            }
        }
    }

    #[test]
    fn test_audit_export_command() {
        let cli = Cli::try_parse_from([
            "rustchain",
            "audit",
            "export",
            "--format",
            "yaml",
            "--output",
            "audit.yaml",
        ]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Audit { action } = cli.command {
                if let AuditAction::Export { format, output } = action {
                    assert_eq!(format, "yaml");
                    assert_eq!(output, Some("audit.yaml".to_string()));
                }
            }
        }
    }

    #[test]
    fn test_audit_stats_command() {
        let cli = Cli::try_parse_from(["rustchain", "audit", "stats"]);
        assert!(cli.is_ok());

        if let Ok(cli) = cli {
            if let Commands::Audit { action } = cli.command {
                assert!(matches!(action, AuditAction::Stats));
            }
        }
    }

    #[test]
    fn test_config_commands() {
        let commands = [
            (["rustchain", "config", "show"], ConfigAction::Show),
            (["rustchain", "config", "validate"], ConfigAction::Validate),
            (["rustchain", "config", "init"], ConfigAction::Init),
        ];

        for (args, expected) in commands {
            let cli = Cli::try_parse_from(args);
            assert!(cli.is_ok(), "Failed to parse: {:?}", args);

            if let Ok(cli) = cli {
                if let Commands::Config { ref action } = cli.command {
                    assert!(std::mem::discriminant(action) == std::mem::discriminant(&expected));
                }
            }
        }
    }

    #[test]
    fn test_invalid_commands() {
        let invalid_args: &[&[&str]] = &[
            &["rustchain", "invalid"],
            &["rustchain", "run"],                 // Missing required argument
            &["rustchain", "mission", "validate"], // Missing required argument
            &["rustchain", "safety", "validate"],  // Missing required argument
        ];

        for args in invalid_args {
            let result = Cli::try_parse_from(*args);
            assert!(result.is_err(), "Should have failed to parse: {:?}", args);
        }
    }

    #[test]
    fn test_help_generation() {
        let result = Cli::try_parse_from(["rustchain", "--help"]);
        assert!(result.is_err()); // Help exits with error code

        let result = Cli::try_parse_from(["rustchain", "run", "--help"]);
        assert!(result.is_err()); // Help exits with error code
    }

    #[test]
    fn test_version_flag() {
        let result = Cli::try_parse_from(["rustchain", "--version"]);
        assert!(result.is_err()); // Version exits with error code
    }
}
