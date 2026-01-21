use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// RustChain - AI Agent Framework
///
/// Autonomous AI agents and mission execution.
/// Run complex AI workflows with safety validation.
#[derive(Parser)]
#[command(
    name = "rustchain",
    version = env!("CARGO_PKG_VERSION"),
    about = "🤖 AI Agent Framework",
    long_about = "RustChain is an AI agent framework for autonomous mission execution.\n\nFeatures:\n• Safe mission execution with validation\n• Audit trails and compliance\n• Multi-LLM support (OpenAI, Anthropic, Ollama)\n• Comprehensive tool ecosystem\n• Production-ready security and monitoring",
    help_template = "{before-help}{name} {version}\n{about}\n\n{usage-heading} {usage}\n\n{all-args}{after-help}"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Set configuration directory
    #[arg(long, global = true, value_name = "DIR")]
    pub config_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Execute a mission file
    #[command(alias = "r")]
    Run(RunArgs),

    /// Create a new mission from template
    #[command(alias = "new")]
    Create(CreateArgs),

    /// Validate mission safety and syntax
    #[command(alias = "check")]
    Validate(ValidateArgs),

    /// Manage LLM providers and models
    #[command(alias = "llm")]
    Llm(LlmArgs),

    /// Tool management and execution
    #[command(alias = "tool")]
    Tools(ToolsArgs),

    /// View audit trails and logs
    #[command(alias = "audit")]
    Audit(AuditArgs),

    /// Configure RustChain settings
    #[command(alias = "config")]
    Config(ConfigArgs),

    /// Safety and policy management
    #[command(alias = "safety")]
    Safety(SafetyArgs),

    /// Initialize new RustChain project
    #[command(alias = "init")]
    Init(InitArgs),

    /// Transpile workflows from other formats to RustChain
    #[command(alias = "transpile")]
    #[cfg(feature = "transpiler")]
    Transpile(TranspileArgs),
}

/// Execute a mission file
#[derive(Args)]
pub struct RunArgs {
    /// Mission file to execute
    #[arg(value_name = "MISSION")]
    pub mission: String,

    /// Dry run - validate without executing
    #[arg(short, long)]
    pub dry_run: bool,

    /// Continue on step failures
    #[arg(short, long)]
    pub continue_on_error: bool,

    /// Set mission variables (key=value)
    #[arg(short = 'D', long = "define", value_name = "KEY=VALUE")]
    pub variables: Vec<String>,

    /// Specify working directory
    #[arg(short = 'C', long = "directory", value_name = "DIR")]
    pub directory: Option<PathBuf>,

    /// Override safety validation (requires --force)
    #[arg(long)]
    pub force: bool,

    /// Watch mission file for changes and re-execute
    #[arg(short, long)]
    pub watch: bool,
}

/// Create a new mission from template
#[derive(Args)]
pub struct CreateArgs {
    /// Mission name
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Template to use
    #[arg(short, long, default_value = "basic")]
    pub template: String,

    /// Output directory
    #[arg(short, long, default_value = ".")]
    pub output: PathBuf,

    /// Mission description
    #[arg(short, long)]
    pub description: Option<String>,
}

/// Validate mission files
#[derive(Args)]
pub struct ValidateArgs {
    /// Mission files to validate
    #[arg(value_name = "MISSIONS")]
    pub missions: Vec<String>,

    /// Validate syntax only (skip safety checks)
    #[arg(long)]
    pub syntax_only: bool,

    /// Show detailed validation results
    #[arg(short, long)]
    pub detailed: bool,
}

/// LLM provider management
#[derive(Args)]
pub struct LlmArgs {
    #[command(subcommand)]
    pub command: LlmCommands,
}

#[derive(Subcommand)]
pub enum LlmCommands {
    /// List available providers and models
    #[command(alias = "ls")]
    List,

    /// Test LLM connectivity
    Test(LlmTestArgs),

    /// Add a new LLM provider
    Add(LlmAddArgs),

    /// Remove an LLM provider
    #[command(alias = "rm")]
    Remove(LlmRemoveArgs),

    /// Set default provider
    Default(LlmDefaultArgs),

    /// Interactive chat with LLM
    Chat(LlmChatArgs),
}

#[derive(Args)]
pub struct LlmTestArgs {
    /// Provider to test (default: all)
    #[arg(value_name = "PROVIDER")]
    pub provider: Option<String>,

    /// Test message
    #[arg(short, long, default_value = "Hello, world!")]
    pub message: String,
}

#[derive(Args)]
pub struct LlmAddArgs {
    /// Provider name
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Provider type (openai, anthropic, ollama)
    #[arg(short, long)]
    pub provider_type: String,

    /// API endpoint URL
    #[arg(short, long)]
    pub url: Option<String>,

    /// API key (will prompt if not provided)
    #[arg(short, long)]
    pub api_key: Option<String>,

    /// Default model for this provider
    #[arg(short, long)]
    pub model: Option<String>,
}

#[derive(Args)]
pub struct LlmRemoveArgs {
    /// Provider name to remove
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(Args)]
pub struct LlmDefaultArgs {
    /// Provider name to set as default
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(Args)]
pub struct LlmChatArgs {
    /// Message to send
    #[arg(value_name = "MESSAGE")]
    pub message: Option<String>,

    /// Provider to use
    #[arg(short, long)]
    pub provider: Option<String>,

    /// Model to use
    #[arg(short, long)]
    pub model: Option<String>,

    /// Interactive mode
    #[arg(short, long)]
    pub interactive: bool,
}

/// Tool management
#[derive(Args)]
pub struct ToolsArgs {
    #[command(subcommand)]
    pub command: ToolCommands,
}

#[derive(Subcommand)]
pub enum ToolCommands {
    /// List available tools
    #[command(alias = "ls")]
    List,

    /// Execute a tool directly
    Exec(ToolExecArgs),

    /// Show tool information
    Info(ToolInfoArgs),

    /// Test tool execution
    Test(ToolTestArgs),
}

#[derive(Args)]
pub struct ToolExecArgs {
    /// Tool name to execute
    #[arg(value_name = "TOOL")]
    pub tool: String,

    /// Tool parameters as JSON
    #[arg(short, long)]
    pub params: Option<String>,

    /// Tool parameters as key=value pairs
    #[arg(short = 'D', long = "define", value_name = "KEY=VALUE")]
    pub define: Vec<String>,
}

#[derive(Args)]
pub struct ToolInfoArgs {
    /// Tool name to show info for
    #[arg(value_name = "TOOL")]
    pub tool: String,

    /// Show detailed schema information
    #[arg(short, long)]
    pub schema: bool,
}

#[derive(Args)]
pub struct ToolTestArgs {
    /// Tool name to test
    #[arg(value_name = "TOOL")]
    pub tool: String,
}

/// Audit and logging
#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,
}

#[derive(Subcommand)]
pub enum AuditCommands {
    /// Show recent audit entries
    #[command(alias = "log")]
    Show(AuditShowArgs),

    /// Export audit data
    Export(AuditExportArgs),

    /// Generate compliance report
    Report(AuditReportArgs),

    /// Verify audit chain integrity
    Verify,
}

#[derive(Args)]
pub struct AuditShowArgs {
    /// Number of entries to show
    #[arg(short, long, default_value = "20")]
    pub limit: usize,

    /// Filter by mission ID
    #[arg(short, long)]
    pub mission: Option<String>,

    /// Filter by event type
    #[arg(short, long)]
    pub event_type: Option<String>,

    /// Show entries after this time
    #[arg(long)]
    pub since: Option<String>,
}

#[derive(Args)]
pub struct AuditExportArgs {
    /// Output file
    #[arg(short, long)]
    pub output: PathBuf,

    /// Export format (json, csv)
    #[arg(short, long, default_value = "json")]
    pub format: String,

    /// Date range filter
    #[arg(long)]
    pub since: Option<String>,

    /// Date range filter  
    #[arg(long)]
    pub until: Option<String>,
}

#[derive(Args)]
pub struct AuditReportArgs {
    /// Report type (security, performance, compliance)
    #[arg(short, long, default_value = "compliance")]
    pub report_type: String,

    /// Output file
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Date range for report
    #[arg(long)]
    pub since: Option<String>,

    /// Date range for report
    #[arg(long)]
    pub until: Option<String>,
}

/// Configuration management
#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set configuration value
    Set(ConfigSetArgs),

    /// Get configuration value
    Get(ConfigGetArgs),

    /// Reset configuration to defaults
    Reset,

    /// Edit configuration in editor
    Edit,
}

#[derive(Args)]
pub struct ConfigSetArgs {
    /// Configuration key
    #[arg(value_name = "KEY")]
    pub key: String,

    /// Configuration value
    #[arg(value_name = "VALUE")]
    pub value: String,
}

#[derive(Args)]
pub struct ConfigGetArgs {
    /// Configuration key
    #[arg(value_name = "KEY")]
    pub key: String,
}

/// Safety and policy management
#[derive(Args)]
pub struct SafetyArgs {
    #[command(subcommand)]
    pub command: SafetyCommands,
}

#[derive(Subcommand)]
pub enum SafetyCommands {
    /// Check safety policies
    Check(SafetyCheckArgs),

    /// List safety rules
    #[command(alias = "ls")]
    List,

    /// Add safety rule
    Add(SafetyAddArgs),

    /// Remove safety rule
    #[command(alias = "rm")]
    Remove(SafetyRemoveArgs),

    /// Test safety validation
    Test(SafetyTestArgs),
}

#[derive(Args)]
pub struct SafetyCheckArgs {
    /// Mission file to check
    #[arg(value_name = "MISSION")]
    pub mission: String,

    /// Show detailed safety analysis
    #[arg(short, long)]
    pub detailed: bool,
}

#[derive(Args)]
pub struct SafetyAddArgs {
    /// Rule name
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Rule pattern
    #[arg(short, long)]
    pub pattern: String,

    /// Rule description
    #[arg(short, long)]
    pub description: String,

    /// Rule severity (low, medium, high, critical)
    #[arg(short, long, default_value = "medium")]
    pub severity: String,
}

#[derive(Args)]
pub struct SafetyRemoveArgs {
    /// Rule name to remove
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(Args)]
pub struct SafetyTestArgs {
    /// Test input
    #[arg(value_name = "INPUT")]
    pub input: String,
}

/// Initialize new RustChain project
#[derive(Args)]
pub struct InitArgs {
    /// Project name
    #[arg(value_name = "NAME")]
    pub name: Option<String>,

    /// Project directory
    #[arg(short, long)]
    pub directory: Option<PathBuf>,

    /// Initialize with example missions
    #[arg(long)]
    pub with_examples: bool,

    /// Initialize with enterprise features
    #[arg(long)]
    pub enterprise: bool,
}

/// Transpile workflows from other formats to RustChain
#[cfg(feature = "transpiler")]
#[derive(Args)]
pub struct TranspileArgs {
    /// Input file to transpile
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output file for RustChain mission
    #[arg(short, long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,

    /// Input format (langchain, airflow, github-actions, etc.)
    #[arg(short = 'f', long, default_value = "langchain")]
    pub from: String,

    /// Output format (rustchain-yaml, github-actions, kubernetes, etc.)
    #[arg(short = 't', long, default_value = "rustchain-yaml")]
    pub to: String,

    /// Validate the transpiled mission without saving
    #[arg(long)]
    pub validate_only: bool,

    /// Show detailed transpilation process
    #[arg(short, long)]
    pub verbose: bool,
}
