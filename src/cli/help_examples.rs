/// Enhanced CLI help text with detailed examples and usage patterns
/// This module provides rich help content for all RustChain CLI commands
pub struct CommandExamples;

impl CommandExamples {
    /// Get detailed help for the main rustchain command
    pub fn main_help() -> &'static str {
        r#"RustChain - Advanced AI Agent Framework

USAGE:
    rustchain <COMMAND>

EXAMPLES:
    # Quick start - run your first mission
    rustchain run examples/hello_world.yaml

    # Interactive mode
    rustchain interactive

    # Validate mission before execution
    rustchain mission validate my_mission.yaml

    # Validate mission before execution
    rustchain mission validate my_mission.yaml

    # List available missions
    rustchain mission list

COMMANDS:
    interactive    Start conversational mode
    run            Execute a mission file
    mission        Mission management operations
    Note: llm and tools commands require respective feature flags to be compiled in
    safety         Security validation
    policy         Policy enforcement
    audit          Audit trail operations
    config         Configuration management
    features       Feature detection
    enterprise     Enterprise features

For detailed help on any command, use:
    rustchain <COMMAND> --help"#
    }

    /// Get detailed help for the run command
    pub fn run_help() -> &'static str {
        r#"Execute a RustChain mission file

USAGE:
    rustchain run [OPTIONS] <MISSION>

ARGUMENTS:
    <MISSION>    Path to the YAML mission file to execute

OPTIONS:
    -d, --dry-run       Validate and plan execution without running tools
    -s, --skip-safety   Skip safety validation (use with caution)
    -h, --help          Print help

EXAMPLES:
    # Basic execution
    rustchain run examples/hello_world.yaml

    # Test mission without executing (recommended first)
    rustchain run my_mission.yaml --dry-run

    # Skip safety checks (only if you trust the mission)
    rustchain run trusted_mission.yaml --skip-safety

    # Combine options
    rustchain run mission.yaml --dry-run --skip-safety

MISSION FILE FORMAT:
    name: "Mission Name"
    description: "What this mission does"
    version: "1.0"
    steps:
      - id: "step1"
        step_type: "llm"
        parameters:
          provider: "openai"
          model: "gpt-4"
          prompt: "Your prompt here"

For mission examples, see: examples/ directory
For mission validation: rustchain mission validate <file>"#
    }

    /// Get detailed help for mission commands
    pub fn mission_help() -> &'static str {
        r#"Mission management operations

USAGE:
    rustchain mission <COMMAND>

COMMANDS:
    list        List available example missions
    validate    Validate mission file syntax and structure
    info        Show detailed mission information

EXAMPLES:
    # See all available example missions
    rustchain mission list

    # Validate before running (recommended)
    rustchain mission validate my_mission.yaml

    # Get detailed mission information
    rustchain mission info examples/hello_world.yaml

VALIDATION CHECKS:
    CHECKS: YAML syntax correctness
    CHECKS: Required fields present
    CHECKS: Step type validity
    CHECKS: Parameter requirements
    CHECKS: Dependency resolution
    CHECKS: Safety assessment

For mission creation guide, see: docs/MISSION_GUIDE.md"#
    }

    /// Get detailed help for LLM commands
    pub fn llm_help() -> &'static str {
        r#"AI model interactions and management

USAGE:
    rustchain llm <COMMAND>

COMMANDS:
    models    List available models from providers
    chat      Interactive chat with AI models
    test      Test connectivity to LLM providers

EXAMPLES:
    # List all available models
    rustchain llm models

    # List models from specific provider
    rustchain llm models --provider openai
    rustchain llm models --provider anthropic

    # Chat with default model
    rustchain llm chat "What is Rust ownership?"

    # Specify model and provider
    rustchain llm chat "Explain async/await" --model gpt-4 --provider openai

    # Adjust creativity (temperature)
    rustchain llm chat "Write a story" --temperature 1.2

    # Technical discussion (low temperature)
    rustchain llm chat "Explain memory safety" --temperature 0.1

    # Test provider connectivity
    rustchain llm test
    rustchain llm test openai

SUPPORTED PROVIDERS:
    • OpenAI (GPT-3.5, GPT-4, GPT-4 Turbo)
    • Anthropic (Claude 3 family)
    • Ollama (Local models)
    • Custom providers via configuration

TEMPERATURE GUIDE:
    0.0-0.3  Factual, precise responses
    0.4-0.7  Balanced creativity and accuracy
    0.8-2.0  Creative, experimental responses

Setup: Configure API keys in environment or config file"#
    }

    /// Get detailed help for tools commands
    pub fn tools_help() -> &'static str {
        r#"Tool management and execution

USAGE:
    rustchain tools <COMMAND>

COMMANDS:
    list      List all available tools
    info      Get detailed information about a tool
    execute   Execute a tool directly with parameters

EXAMPLES:
    # List all available tools
    rustchain tools list

    # Get tool documentation
    rustchain tools info file_create
    rustchain tools info http_request

    # Execute tools directly
    rustchain tools execute file_create --params '{
        "path": "hello.txt",
        "content": "Hello, World!"
    }'

    rustchain tools execute http_request --params '{
        "url": "https://api.github.com",
        "method": "GET"
    }'

    rustchain tools execute command_execute --params '{
        "command": "ls",
        "args": ["-la", "/tmp"]
    }'

AVAILABLE TOOL CATEGORIES:
    FILE OPERATIONS:
       • file_create, file_read, file_write
       • file_delete, file_exists, directory_list

    NETWORK OPERATIONS:
       • http_request, websocket_connect
       • api_call, webhook_trigger

    SYSTEM OPERATIONS:
       • command_execute, process_info
       • environment_get, path_resolve

    AI OPERATIONS:
       • llm_call, embedding_generate
       • text_summarize, sentiment_analyze

PARAMETER FORMAT:
    Use JSON format for --params option
    Example: --params '{"key": "value", "number": 42}'

SECURITY:
    All tools run within safety policy constraints
    Use 'rustchain policy status' to see current restrictions"#
    }

    /// Get detailed help for safety commands
    pub fn safety_help() -> &'static str {
        r#"Security validation and safety checks

USAGE:
    rustchain safety <COMMAND>

COMMANDS:
    validate    Validate mission file for security risks
    check       Run comprehensive system safety checks
    report      Generate detailed safety assessment

EXAMPLES:
    # Validate a mission file
    rustchain safety validate mission.yaml

    # Strict validation (fail on warnings)
    rustchain safety validate mission.yaml --strict

    # System-wide safety check
    rustchain safety check

    # Include policy validation
    rustchain safety check --include-policies

    # Generate safety report
    rustchain safety report mission.yaml
    rustchain safety report mission.yaml --format json

SAFETY CHECKS:
    MISSION ANALYSIS:
       • Step type validation
       • Parameter safety review
       • Dependency security

    RISK ASSESSMENT:
       • File system access patterns
       • Network communication review
       • Command execution analysis

    POLICY COMPLIANCE:
       • Corporate policy adherence
       • Security standard compliance
       • Access control validation

RISK LEVELS:
    LOW: Safe to execute
    MEDIUM: Review recommended
    HIGH: Caution required
    CRITICAL: Do not execute

REPORT FORMATS:
    • text (human-readable, default)
    • json (machine-readable)
    • yaml (structured format)

Best Practice: Always validate missions before execution"#
    }

    /// Get detailed help for policy commands
    pub fn policy_help() -> &'static str {
        r#"Policy enforcement and compliance management

USAGE:
    rustchain policy <COMMAND>

COMMANDS:
    list        List all active security policies
    validate    Validate policy configuration
    status      Show policy enforcement status

EXAMPLES:
    # Show all active policies
    rustchain policy list

    # Validate policy configuration
    rustchain policy validate

    # Check enforcement status
    rustchain policy status

POLICY CATEGORIES:
    FILE ACCESS POLICY:
       • Allowed/blocked directories
       • File operation restrictions
       • Permission requirements

    NETWORK POLICY:
       • Allowed domains and IPs
       • Port restrictions
       • Protocol limitations

    COMMAND EXECUTION POLICY:
       • Allowed/blocked commands
       • Parameter validation
       • Privilege restrictions

    LLM SAFETY POLICY:
       • Content filtering
       • Prompt injection detection
       • Response validation

POLICY STATUS INDICATORS:
    ENFORCED: Policy active and blocking violations
    WARNING: Policy active but only logging violations
    DISABLED: Policy not enforced
    CONFIGURING: Policy being set up

CONFIGURATION:
    Policies are configured in:
    • System config: /etc/rustchain/policies/
    • User config: ~/.rustchain/policies/
    • Project config: ./rustchain/policies/"#
    }

    /// Get detailed help for interactive mode
    pub fn interactive_help() -> &'static str {
        r#"Start interactive conversational mode

USAGE:
    rustchain interactive

DESCRIPTION:
    Interactive mode provides a conversational interface that
    allows you to:

    • Have natural conversations with AI models
    • Create and execute missions dynamically
    • Get real-time help and guidance
    • Explore RustChain capabilities interactively

EXAMPLES:
    $ rustchain interactive
    RustChain Interactive Mode - Type 'help' or 'exit'

    > create a mission to analyze my Rust codebase
    > run the generated mission
    > show me performance metrics
    > help with optimizing the analysis
    > exit

INTERACTIVE COMMANDS:
    help           Show available commands
    exit, quit     Exit interactive mode
    clear          Clear screen
    history        Show command history
    save <file>    Save session to file
    load <file>    Load previous session

FEATURES:
    • Intelligent conversation flow
    • Context-aware suggestions
    • Mission generation assistance
    • Real-time execution feedback
    • Error explanation and fixes
    • Best practice recommendations

Note: Interactive mode requires LLM provider configuration"#
    }

    /// Get detailed help for enterprise commands
    pub fn enterprise_help() -> &'static str {
        r#"Enterprise features and advanced capabilities

USAGE:
    rustchain enterprise <COMMAND>

COMMANDS:
    auth           Authentication and authorization
    compliance     Compliance and auditing features
    monitoring     Performance monitoring and metrics
    multi-tenant   Multi-tenancy management

ENTERPRISE FEATURES:
    AUTHENTICATION & RBAC:
       • JWT token management
       • OAuth2 integration
       • Role-based access control
       • Multi-factor authentication

    COMPLIANCE & AUDITING:
       • GDPR compliance checking
       • HIPAA compliance validation
       • SOX audit trail requirements
       • Custom compliance standards

    MONITORING & PERFORMANCE:
       • Real-time metrics collection
       • Performance dashboards
       • Alerting and notifications
       • Resource usage tracking

    MULTI-TENANCY:
       • Tenant isolation
       • Resource quotas
       • Billing integration
       • Custom branding

EXAMPLES:
    # Setup authentication
    rustchain enterprise auth init-jwt
    rustchain enterprise auth setup-oauth2 google --client-id <id>

    # Compliance checking
    rustchain enterprise compliance verify mission.yaml --standard GDPR
    rustchain enterprise compliance audit

    # Performance monitoring
    rustchain enterprise monitoring dashboard
    rustchain enterprise monitoring start-metrics

    # Multi-tenancy
    rustchain enterprise multi-tenant create-tenant acme "ACME Corp"

LICENSING:
    Enterprise features require RustChain Enterprise license
    Contact: enterprise@rustchain.dev"#
    }

    /// Get comprehensive feature help
    pub fn features_help() -> &'static str {
        r#"Feature detection and capability management

USAGE:
    rustchain features <COMMAND>

COMMANDS:
    list      List all features and their availability
    check     Check if a specific feature is available
    summary   Show comprehensive feature overview
    upgrade   Show upgrade recommendations

EXAMPLES:
    # List all features
    rustchain features list

    # Filter by category
    rustchain features list --category llm
    rustchain features list --category enterprise

    # Show only available features
    rustchain features list --available-only

    # Check specific feature
    rustchain features check agent
    rustchain features check compliance

    # Get feature summary
    rustchain features summary

    # See upgrade options
    rustchain features upgrade

FEATURE CATEGORIES:
    CORE FEATURES (Always Available):
       • Mission execution
       • Safety validation
       • Basic tool support

    AI FEATURES (Require Configuration):
       • LLM integration
       • Agent reasoning
       • RAG capabilities

    ENTERPRISE FEATURES (License Required):
       • RBAC authentication
       • Compliance checking
       • Multi-tenancy

    OPTIONAL FEATURES (Compile-time):
       • Server mode
       • Sandbox isolation
       • Advanced monitoring

FEATURE STATUS:
    AVAILABLE: Feature ready to use
    CONFIGURABLE: Requires setup (API keys, etc.)
    LICENSED: Requires enterprise license
    UNAVAILABLE: Not compiled or not supported

UPGRADE PATHS:
    Community → Professional → Enterprise

For licensing information: https://rustchain.dev/pricing"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_examples_content() {
        // Test that all help content is non-empty and contains expected keywords
        assert!(CommandExamples::main_help().contains("RustChain"));
        assert!(CommandExamples::run_help().contains("Execute"));
        assert!(CommandExamples::mission_help().contains("Mission"));
        assert!(CommandExamples::llm_help().contains("AI model"));
        assert!(CommandExamples::tools_help().contains("Tool management"));
        assert!(CommandExamples::safety_help().contains("Security"));
        assert!(CommandExamples::policy_help().contains("Policy"));
        assert!(CommandExamples::interactive_help().contains("conversational"));
        assert!(CommandExamples::enterprise_help().contains("Enterprise"));
        assert!(CommandExamples::features_help().contains("Feature"));
    }

    #[test]
    fn test_help_examples_structure() {
        // Test that help content follows expected structure
        let main_help = CommandExamples::main_help();
        assert!(main_help.contains("USAGE:"));
        assert!(main_help.contains("EXAMPLES:"));
        assert!(main_help.contains("COMMANDS:"));

        let run_help = CommandExamples::run_help();
        assert!(run_help.contains("USAGE:"));
        assert!(run_help.contains("ARGUMENTS:"));
        assert!(run_help.contains("OPTIONS:"));
        assert!(run_help.contains("EXAMPLES:"));
    }

    #[test]
    fn test_help_examples_formatting() {
        // Test that help content is properly formatted
        for help_text in [
            CommandExamples::main_help(),
            CommandExamples::run_help(),
            CommandExamples::mission_help(),
            CommandExamples::llm_help(),
            CommandExamples::tools_help(),
            CommandExamples::safety_help(),
        ] {
            // Should not be empty
            assert!(!help_text.is_empty());

            // Should contain proper formatting
            assert!(help_text.contains("USAGE:") || help_text.contains("DESCRIPTION:"));

            // Should not have excessive trailing whitespace on lines
            for line in help_text.lines() {
                // Allow single trailing space for formatting, but not multiple
                let trimmed = line.trim_end();
                if line.len() > trimmed.len() + 1 {
                    panic!("Line has excessive trailing whitespace: '{}'", line);
                }
            }
        }
    }
}
