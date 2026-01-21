/// User-friendly error formatting and helpful suggestions
/// This module provides enhanced error messages with context, solutions, and actionable steps
use crate::core::error::*;
use is_terminal::IsTerminal;
use std::fmt;

/// Enhanced error formatter that provides user-friendly messages
pub struct ErrorFormatter;

impl ErrorFormatter {
    /// Format an error with enhanced user-friendly messages and suggestions
    pub fn format_user_friendly(error: &RustChainError) -> FormattedError {
        match error {
            RustChainError::Config(config_error) => Self::format_config_error(config_error),
            RustChainError::Llm(llm_error) => Self::format_llm_error(llm_error),
            RustChainError::Memory(memory_error) => Self::format_memory_error(memory_error),
            RustChainError::Tool(tool_error) => Self::format_tool_error(tool_error),
            RustChainError::Execution(execution_error) => {
                Self::format_execution_error(execution_error)
            }
            RustChainError::Schema(schema_error) => Self::format_schema_error(schema_error),
            RustChainError::Security(message) => Self::format_security_error(message),
            RustChainError::Io(io_error) => Self::format_io_error(io_error),
            RustChainError::Json(json_error) => Self::format_json_error(json_error),
            RustChainError::Yaml(yaml_error) => Self::format_yaml_error(yaml_error),
            RustChainError::Transpiler(message) => Self::format_transpiler_error(message),
            RustChainError::Unknown { message } => Self::format_unknown_error(message),
            RustChainError::Exec(message) => Self::format_exec_error(message),
        }
    }

    fn format_config_error(error: &ConfigError) -> FormattedError {
        match error {
            ConfigError::MissingKey { key } => FormattedError {
                title: "🔧 Configuration Missing".to_string(),
                message: format!("Required configuration key '{}' is not set.", key),
                context: Some(
                    "RustChain needs this configuration to operate properly.".to_string(),
                ),
                suggestions: vec![
                    format!("Add '{}' to your configuration file", key),
                    format!(
                        "Set environment variable: export RUSTCHAIN_{}",
                        key.to_uppercase()
                    ),
                    "Run 'rustchain config init' to create default configuration".to_string(),
                    "Check documentation: docs/CONFIGURATION.md".to_string(),
                ],
                help_command: Some(format!("rustchain config show | grep {}", key)),
                severity: ErrorSeverity::Warning,
            },
            ConfigError::InvalidValue {
                key,
                expected,
                actual,
            } => FormattedError {
                title: "⚠️ Configuration Invalid".to_string(),
                message: format!("Configuration key '{}' has invalid value.", key),
                context: Some(format!("Expected: {}, but got: {}", expected, actual)),
                suggestions: vec![
                    format!("Update '{}' to a valid {} value", key, expected),
                    "Check configuration file syntax".to_string(),
                    "Refer to configuration documentation for valid values".to_string(),
                    "Use 'rustchain config validate' to check all settings".to_string(),
                ],
                help_command: Some("rustchain config validate".to_string()),
                severity: ErrorSeverity::Error,
            },
            ConfigError::FileNotFound { path } => FormattedError {
                title: "Configuration File Missing".to_string(),
                message: format!("Configuration file not found: {}", path),
                context: Some(
                    "RustChain looked for configuration in the expected locations.".to_string(),
                ),
                suggestions: vec![
                    "Create configuration file with 'rustchain config init'".to_string(),
                    format!("Create file manually at: {}", path),
                    "Check if path is correct and accessible".to_string(),
                    "Verify file permissions (should be readable)".to_string(),
                ],
                help_command: Some("rustchain config init".to_string()),
                severity: ErrorSeverity::Error,
            },
            ConfigError::ParseError { reason } => FormattedError {
                title: "📝 Configuration Parse Error".to_string(),
                message: "Configuration file has syntax errors.".to_string(),
                context: Some(format!("Parse error: {}", reason)),
                suggestions: vec![
                    "Check YAML/JSON syntax in configuration file".to_string(),
                    "Validate with online YAML/JSON validator".to_string(),
                    "Look for missing quotes, brackets, or indentation issues".to_string(),
                    "Backup and recreate with 'rustchain config init'".to_string(),
                ],
                help_command: Some("rustchain config validate".to_string()),
                severity: ErrorSeverity::Error,
            },
            ConfigError::PluginError { message } => FormattedError {
                title: "🔌 Plugin Configuration Error".to_string(),
                message: "Plugin configuration has issues.".to_string(),
                context: Some(message.clone()),
                suggestions: vec![
                    "Check plugin configuration syntax".to_string(),
                    "Verify plugin dependencies are installed".to_string(),
                    "Review plugin documentation".to_string(),
                    "Try disabling the plugin temporarily".to_string(),
                ],
                help_command: Some("rustchain features list".to_string()),
                severity: ErrorSeverity::Warning,
            },
        }
    }

    fn format_llm_error(error: &LlmError) -> FormattedError {
        match error {
            LlmError::ServiceUnavailable { provider } => FormattedError {
                title: "🤖 AI Service Unavailable".to_string(),
                message: format!("{} service is currently unavailable.", provider),
                context: Some(
                    "The AI provider might be experiencing downtime or connectivity issues."
                        .to_string(),
                ),
                suggestions: vec![
                    "Check your internet connection".to_string(),
                    format!("Verify {} service status page", provider),
                    "Try a different AI provider if configured".to_string(),
                    "Wait a few minutes and retry".to_string(),
                    format!("Test connectivity: rustchain llm test {}", provider),
                ],
                help_command: Some(format!("rustchain llm test {}", provider)),
                severity: ErrorSeverity::Error,
            },
            LlmError::AuthenticationFailed { provider, reason } => FormattedError {
                title: "🔐 AI Authentication Failed".to_string(),
                message: format!("{} authentication failed.", provider),
                context: Some(format!("Reason: {}", reason)),
                suggestions: vec![
                    format!("Check your {} API key", provider),
                    format!(
                        "Set environment variable: export {}_API_KEY=your-key",
                        provider.to_uppercase()
                    ),
                    "Verify API key has correct permissions".to_string(),
                    "Check if API key has expired".to_string(),
                    "Generate new API key from provider dashboard".to_string(),
                ],
                help_command: Some(format!("rustchain llm test {}", provider)),
                severity: ErrorSeverity::Error,
            },
            LlmError::Timeout { timeout_ms } => FormattedError {
                title: "⏱️ AI Request Timeout".to_string(),
                message: format!("Request timed out after {} seconds.", timeout_ms / 1000),
                context: Some("The AI provider took too long to respond.".to_string()),
                suggestions: vec![
                    "Try a simpler prompt or break it into smaller parts".to_string(),
                    "Increase timeout in configuration".to_string(),
                    "Check network connection speed".to_string(),
                    "Try different AI model (some are faster)".to_string(),
                    "Retry the operation - it might be temporary".to_string(),
                ],
                help_command: Some("rustchain config show | grep timeout".to_string()),
                severity: ErrorSeverity::Warning,
            },
            LlmError::InvalidPrompt { reason } => FormattedError {
                title: "💬 Invalid Prompt".to_string(),
                message: "The prompt contains invalid content.".to_string(),
                context: Some(format!("Issue: {}", reason)),
                suggestions: vec![
                    "Review prompt content for inappropriate material".to_string(),
                    "Simplify or rephrase the prompt".to_string(),
                    "Check prompt length limits".to_string(),
                    "Remove any potentially sensitive information".to_string(),
                    "Use safety validation: rustchain safety validate".to_string(),
                ],
                help_command: Some("rustchain safety validate mission.yaml".to_string()),
                severity: ErrorSeverity::Warning,
            },
            LlmError::RateLimitExceeded {
                provider,
                retry_after_seconds,
            } => FormattedError {
                title: "🚦 Rate Limit Exceeded".to_string(),
                message: format!("{} rate limit exceeded.", provider),
                context: Some(format!("Retry after {} seconds.", retry_after_seconds)),
                suggestions: vec![
                    format!("Wait {} seconds before retrying", retry_after_seconds),
                    "Consider upgrading your API plan for higher limits".to_string(),
                    "Batch requests to reduce API calls".to_string(),
                    "Use a different AI provider if available".to_string(),
                    "Add delays between requests in missions".to_string(),
                ],
                help_command: Some("rustchain llm models --provider all".to_string()),
                severity: ErrorSeverity::Warning,
            },
            LlmError::ResponseError { message } => FormattedError {
                title: "🤖 AI Response Error".to_string(),
                message: "AI provider returned an error.".to_string(),
                context: Some(message.clone()),
                suggestions: vec![
                    "Try rephrasing your prompt".to_string(),
                    "Check if prompt violates provider policies".to_string(),
                    "Try a different AI model".to_string(),
                    "Reduce prompt complexity or length".to_string(),
                    "Contact provider support if error persists".to_string(),
                ],
                help_command: Some("rustchain llm models".to_string()),
                severity: ErrorSeverity::Error,
            },
        }
    }

    fn format_memory_error(error: &MemoryError) -> FormattedError {
        match error {
            MemoryError::StoreNotFound { store_id } => FormattedError {
                title: "🧠 Memory Store Missing".to_string(),
                message: format!("Memory store '{}' not found.", store_id),
                context: Some(
                    "The requested memory store hasn't been created or was removed.".to_string(),
                ),
                suggestions: vec![
                    "Check if the store name is spelled correctly".to_string(),
                    "Initialize the memory store before using it".to_string(),
                    "Verify memory configuration in settings".to_string(),
                    "List available stores to see what's available".to_string(),
                ],
                help_command: Some("rustchain config show | grep memory".to_string()),
                severity: ErrorSeverity::Error,
            },
            MemoryError::KeyNotFound { key, store_id } => FormattedError {
                title: "🔑 Memory Key Missing".to_string(),
                message: format!("Key '{}' not found in memory store '{}'.", key, store_id),
                context: Some(
                    "The requested data hasn't been stored or may have expired.".to_string(),
                ),
                suggestions: vec![
                    "Check if the key name is correct".to_string(),
                    "Verify data was stored successfully before retrieval".to_string(),
                    "Check if data expired (TTL timeout)".to_string(),
                    "Initialize data before accessing it".to_string(),
                ],
                help_command: Some("rustchain audit query --event-types memory".to_string()),
                severity: ErrorSeverity::Warning,
            },
            MemoryError::CapacityExceeded { current, max } => FormattedError {
                title: "💾 Memory Capacity Full".to_string(),
                message: format!("Memory capacity exceeded: {}/{} entries.", current, max),
                context: Some("Memory store has reached its maximum capacity limit.".to_string()),
                suggestions: vec![
                    "Increase memory capacity in configuration".to_string(),
                    "Clear old data to make space".to_string(),
                    "Implement data cleanup policies".to_string(),
                    "Use external storage for large datasets".to_string(),
                    "Configure TTL to auto-expire old data".to_string(),
                ],
                help_command: Some("rustchain config show | grep memory".to_string()),
                severity: ErrorSeverity::Warning,
            },
            MemoryError::InvalidOperation {
                operation,
                store_type,
            } => FormattedError {
                title: "🚫 Invalid Memory Operation".to_string(),
                message: format!(
                    "Operation '{}' not supported on {} store.",
                    operation, store_type
                ),
                context: Some("The memory store type doesn't support this operation.".to_string()),
                suggestions: vec![
                    "Check memory store documentation for supported operations".to_string(),
                    "Use appropriate operations for this store type".to_string(),
                    "Consider using a different memory store type".to_string(),
                    "Verify operation syntax and parameters".to_string(),
                ],
                help_command: Some("rustchain features check memory".to_string()),
                severity: ErrorSeverity::Error,
            },
            MemoryError::SerializationFailed { reason } => FormattedError {
                title: "📦 Memory Serialization Failed".to_string(),
                message: "Failed to serialize/deserialize memory data.".to_string(),
                context: Some(format!("Error: {}", reason)),
                suggestions: vec![
                    "Check data format compatibility".to_string(),
                    "Verify data doesn't contain unsupported types".to_string(),
                    "Clear corrupted memory store".to_string(),
                    "Recreate data with correct format".to_string(),
                ],
                help_command: Some("rustchain audit query --event-types memory".to_string()),
                severity: ErrorSeverity::Error,
            },
            MemoryError::Corrupted { details } => FormattedError {
                title: "💥 Memory Store Corrupted".to_string(),
                message: "Memory store data is corrupted.".to_string(),
                context: Some(format!("Details: {}", details)),
                suggestions: vec![
                    "⚠️ Backup important data immediately".to_string(),
                    "Clear the corrupted memory store".to_string(),
                    "Reinitialize memory store from backup".to_string(),
                    "Check system storage health".to_string(),
                    "Report corruption if it happens frequently".to_string(),
                ],
                help_command: Some("rustchain audit verify".to_string()),
                severity: ErrorSeverity::Critical,
            },
        }
    }

    fn format_tool_error(error: &ToolError) -> FormattedError {
        match error {
            ToolError::NotFound { tool_name } => FormattedError {
                title: "🔧 Tool Not Found".to_string(),
                message: format!("Tool '{}' is not available.", tool_name),
                context: Some("The requested tool hasn't been installed or enabled.".to_string()),
                suggestions: vec![
                    "Check tool name spelling".to_string(),
                    "List available tools: rustchain tools list".to_string(),
                    "Enable required features for this tool".to_string(),
                    "Install missing tool dependencies".to_string(),
                    "Check if tool is available in your RustChain edition".to_string(),
                ],
                help_command: Some("rustchain tools list".to_string()),
                severity: ErrorSeverity::Error,
            },
            ToolError::ExecutionFailed { tool_name, reason } => FormattedError {
                title: "Tool Execution Failed".to_string(),
                message: format!("Tool '{}' execution failed.", tool_name),
                context: Some(format!("Reason: {}", reason)),
                suggestions: vec![
                    "Check tool parameters are correct".to_string(),
                    format!("Get tool info: rustchain tools info {}", tool_name),
                    "Verify required permissions".to_string(),
                    "Check if dependencies are available".to_string(),
                    "Try with simpler parameters first".to_string(),
                ],
                help_command: Some(format!("rustchain tools info {}", tool_name)),
                severity: ErrorSeverity::Error,
            },
            ToolError::InvalidParameters { tool_name, details } => FormattedError {
                title: "📝 Invalid Tool Parameters".to_string(),
                message: format!("Tool '{}' received invalid parameters.", tool_name),
                context: Some(format!("Issue: {}", details)),
                suggestions: vec![
                    format!(
                        "Check tool documentation: rustchain tools info {}",
                        tool_name
                    ),
                    "Verify parameter names and types".to_string(),
                    "Ensure required parameters are provided".to_string(),
                    "Check JSON parameter format".to_string(),
                    "Try with minimal required parameters first".to_string(),
                ],
                help_command: Some(format!("rustchain tools info {}", tool_name)),
                severity: ErrorSeverity::Error,
            },
            ToolError::Timeout {
                tool_name,
                timeout_ms,
            } => FormattedError {
                title: "⏰ Tool Execution Timeout".to_string(),
                message: format!(
                    "Tool '{}' timed out after {} seconds.",
                    tool_name,
                    timeout_ms / 1000
                ),
                context: Some("Tool took too long to complete.".to_string()),
                suggestions: vec![
                    "Increase timeout in configuration".to_string(),
                    "Try with smaller input data".to_string(),
                    "Check if system resources are sufficient".to_string(),
                    "Verify tool isn't stuck waiting for input".to_string(),
                    "Consider breaking task into smaller parts".to_string(),
                ],
                help_command: Some("rustchain config show | grep timeout".to_string()),
                severity: ErrorSeverity::Warning,
            },
            ToolError::PermissionDenied { tool_name, reason } => FormattedError {
                title: "🚫 Tool Permission Denied".to_string(),
                message: format!("Tool '{}' access denied.", tool_name),
                context: Some(format!("Reason: {}", reason)),
                suggestions: vec![
                    "Check file/directory permissions".to_string(),
                    "Run with appropriate user privileges".to_string(),
                    "Verify security policies allow this operation".to_string(),
                    "Check sandbox restrictions".to_string(),
                    format!("Review policies: rustchain policy status"),
                ],
                help_command: Some("rustchain policy status".to_string()),
                severity: ErrorSeverity::Error,
            },
            ToolError::DependencyMissing {
                tool_name,
                dependency,
            } => FormattedError {
                title: "📦 Tool Dependency Missing".to_string(),
                message: format!(
                    "Tool '{}' requires missing dependency '{}'.",
                    tool_name, dependency
                ),
                context: Some("Required tool or system component is not available.".to_string()),
                suggestions: vec![
                    format!("Install required dependency: {}", dependency),
                    "Check system package manager for installation".to_string(),
                    "Verify PATH includes dependency location".to_string(),
                    "Install RustChain features that include this dependency".to_string(),
                    "Check deployment documentation for requirements".to_string(),
                ],
                help_command: Some("rustchain features list --category tools".to_string()),
                severity: ErrorSeverity::Error,
            },
        }
    }

    fn format_execution_error(error: &ExecutionError) -> FormattedError {
        match error {
            ExecutionError::MissionNotFound { mission_id } => FormattedError {
                title: "Mission Not Found".to_string(),
                message: format!("Mission '{}' not found.", mission_id),
                context: Some(
                    "The requested mission file doesn't exist or isn't accessible.".to_string(),
                ),
                suggestions: vec![
                    "Check mission file path is correct".to_string(),
                    "Verify file exists and is readable".to_string(),
                    "List available missions: rustchain mission list".to_string(),
                    "Check spelling of mission name".to_string(),
                    "Ensure you're in the correct directory".to_string(),
                ],
                help_command: Some("rustchain mission list".to_string()),
                severity: ErrorSeverity::Error,
            },
            ExecutionError::StepFailed {
                step_id,
                mission_id,
                reason,
            } => FormattedError {
                title: "❌ Mission Step Failed".to_string(),
                message: format!("Step '{}' failed in mission '{}'.", step_id, mission_id),
                context: Some(format!("Error: {}", reason)),
                suggestions: vec![
                    "Check step configuration and parameters".to_string(),
                    "Verify step dependencies are satisfied".to_string(),
                    "Run mission in dry-run mode first".to_string(),
                    "Validate mission: rustchain mission validate".to_string(),
                    "Check logs for detailed error information".to_string(),
                ],
                help_command: Some(format!("rustchain mission validate {}.yaml", mission_id)),
                severity: ErrorSeverity::Error,
            },
            ExecutionError::DependencyCycle { mission_id, cycle } => FormattedError {
                title: "🔄 Dependency Cycle Detected".to_string(),
                message: format!("Circular dependency in mission '{}'.", mission_id),
                context: Some(format!("Cycle: {}", cycle)),
                suggestions: vec![
                    "Review step dependencies in mission file".to_string(),
                    "Remove circular dependencies".to_string(),
                    "Reorganize steps to have linear dependencies".to_string(),
                    "Check 'depends_on' fields in mission steps".to_string(),
                    "Use mission validation before execution".to_string(),
                ],
                help_command: Some(format!("rustchain mission validate {}.yaml", mission_id)),
                severity: ErrorSeverity::Error,
            },
            ExecutionError::ResourceExhausted { resource, details } => FormattedError {
                title: "💻 System Resources Exhausted".to_string(),
                message: format!("System resource '{}' exhausted.", resource),
                context: Some(format!("Details: {}", details)),
                suggestions: vec![
                    "Free up system resources (memory, disk, CPU)".to_string(),
                    "Reduce mission complexity or size".to_string(),
                    "Increase system resource limits".to_string(),
                    "Run missions with fewer concurrent steps".to_string(),
                    "Consider upgrading system hardware".to_string(),
                ],
                help_command: Some("rustchain config show | grep resources".to_string()),
                severity: ErrorSeverity::Critical,
            },
            ExecutionError::Timeout {
                mission_id,
                timeout_ms,
            } => FormattedError {
                title: "⏱️ Mission Execution Timeout".to_string(),
                message: format!(
                    "Mission '{}' timed out after {} seconds.",
                    mission_id,
                    timeout_ms / 1000
                ),
                context: Some("Mission took longer than the configured timeout.".to_string()),
                suggestions: vec![
                    "Increase mission timeout in configuration".to_string(),
                    "Optimize mission steps for better performance".to_string(),
                    "Break large mission into smaller parts".to_string(),
                    "Check if any steps are blocking".to_string(),
                    "Review system performance and resources".to_string(),
                ],
                help_command: Some("rustchain config show | grep timeout".to_string()),
                severity: ErrorSeverity::Warning,
            },
            ExecutionError::InvalidState { state, operation } => FormattedError {
                title: "🚦 Invalid Mission State".to_string(),
                message: format!(
                    "Cannot perform '{}' operation in '{}' state.",
                    operation, state
                ),
                context: Some(
                    "Mission is in an incompatible state for this operation.".to_string(),
                ),
                suggestions: vec![
                    "Check mission current state before operation".to_string(),
                    "Wait for mission to reach compatible state".to_string(),
                    "Cancel current mission if stuck".to_string(),
                    "Restart mission execution if needed".to_string(),
                    "Check mission documentation for state transitions".to_string(),
                ],
                help_command: Some("rustchain audit query --event-types execution".to_string()),
                severity: ErrorSeverity::Warning,
            },
        }
    }

    fn format_schema_error(error: &SchemaError) -> FormattedError {
        match error {
            SchemaError::ValidationFailed {
                schema_name,
                errors,
            } => FormattedError {
                title: "📋 Validation Failed".to_string(),
                message: format!("Schema validation failed for '{}'.", schema_name),
                context: Some(format!("Errors found:\n• {}", errors.join("\n• "))),
                suggestions: vec![
                    "Fix validation errors listed above".to_string(),
                    "Check required fields are present".to_string(),
                    "Verify data types match schema requirements".to_string(),
                    "Review schema documentation".to_string(),
                    "Use schema validation tools".to_string(),
                ],
                help_command: Some("rustchain mission validate mission.yaml".to_string()),
                severity: ErrorSeverity::Error,
            },
            SchemaError::SchemaNotFound { schema_name } => FormattedError {
                title: "Schema Not Found".to_string(),
                message: format!("Schema '{}' not found.", schema_name),
                context: Some("The requested schema definition is missing.".to_string()),
                suggestions: vec![
                    "Check schema name spelling".to_string(),
                    "Verify schema files are in correct location".to_string(),
                    "Install missing schema packages".to_string(),
                    "Check schema file permissions".to_string(),
                ],
                help_command: Some(
                    "find . -name '*.schema.json' -o -name '*.schema.yaml'".to_string(),
                ),
                severity: ErrorSeverity::Error,
            },
            SchemaError::InvalidDefinition {
                schema_name,
                reason,
            } => FormattedError {
                title: "⚠️ Invalid Schema Definition".to_string(),
                message: format!("Schema '{}' has invalid definition.", schema_name),
                context: Some(format!("Issue: {}", reason)),
                suggestions: vec![
                    "Fix schema definition syntax".to_string(),
                    "Validate schema file format".to_string(),
                    "Check for circular references".to_string(),
                    "Verify schema follows JSON Schema standard".to_string(),
                ],
                help_command: Some("jsonschema --check schema.json".to_string()),
                severity: ErrorSeverity::Error,
            },
            SchemaError::VersionMismatch { expected, actual } => FormattedError {
                title: "🔄 Schema Version Mismatch".to_string(),
                message: "Schema version incompatibility detected.".to_string(),
                context: Some(format!("Expected: {}, Found: {}", expected, actual)),
                suggestions: vec![
                    format!("Update schema to version {}", expected),
                    "Migrate data to match new schema version".to_string(),
                    "Check for schema upgrade documentation".to_string(),
                    "Use schema versioning tools".to_string(),
                ],
                help_command: Some("rustchain features check schema".to_string()),
                severity: ErrorSeverity::Warning,
            },
        }
    }

    fn format_security_error(message: &str) -> FormattedError {
        FormattedError {
            title: "Security Violation".to_string(),
            message: "Security policy violation detected.".to_string(),
            context: Some(message.to_string()),
            suggestions: vec![
                "Review security policies: rustchain policy status".to_string(),
                "Check if operation is allowed by current policies".to_string(),
                "Request policy exception if operation is legitimate".to_string(),
                "Run safety validation: rustchain safety validate".to_string(),
                "Contact security team if needed".to_string(),
            ],
            help_command: Some("rustchain policy status".to_string()),
            severity: ErrorSeverity::Critical,
        }
    }

    fn format_io_error(error: &std::io::Error) -> FormattedError {
        use std::io::ErrorKind;

        let (title, suggestions) = match error.kind() {
            ErrorKind::NotFound => (
                "File Not Found".to_string(),
                vec![
                    "Check if file path is correct".to_string(),
                    "Verify file exists at specified location".to_string(),
                    "Check spelling of file name".to_string(),
                    "Ensure you have correct working directory".to_string(),
                ],
            ),
            ErrorKind::PermissionDenied => (
                "🚫 Permission Denied".to_string(),
                vec![
                    "Check file/directory permissions".to_string(),
                    "Run with appropriate user privileges".to_string(),
                    "Verify ownership of files".to_string(),
                    "Use sudo if administrative access is needed".to_string(),
                ],
            ),
            ErrorKind::AlreadyExists => (
                "📁 File Already Exists".to_string(),
                vec![
                    "Choose different file name".to_string(),
                    "Delete existing file first".to_string(),
                    "Use overwrite option if available".to_string(),
                    "Rename existing file for backup".to_string(),
                ],
            ),
            _ => (
                "💾 File System Error".to_string(),
                vec![
                    "Check available disk space".to_string(),
                    "Verify file system is healthy".to_string(),
                    "Try again after a moment".to_string(),
                    "Check system logs for issues".to_string(),
                ],
            ),
        };

        FormattedError {
            title,
            message: "File system operation failed.".to_string(),
            context: Some(error.to_string()),
            suggestions,
            help_command: Some("ls -la".to_string()),
            severity: ErrorSeverity::Error,
        }
    }

    fn format_json_error(error: &serde_json::Error) -> FormattedError {
        FormattedError {
            title: "📝 JSON Format Error".to_string(),
            message: "JSON parsing or formatting failed.".to_string(),
            context: Some(error.to_string()),
            suggestions: vec![
                "Check JSON syntax (missing commas, brackets, quotes)".to_string(),
                "Validate JSON with online JSON validator".to_string(),
                "Ensure proper UTF-8 encoding".to_string(),
                "Check for trailing commas (not allowed in JSON)".to_string(),
                "Verify string values are properly quoted".to_string(),
            ],
            help_command: Some("jq . < file.json".to_string()),
            severity: ErrorSeverity::Error,
        }
    }

    fn format_yaml_error(error: &serde_yaml::Error) -> FormattedError {
        FormattedError {
            title: "📝 YAML Format Error".to_string(),
            message: "YAML parsing or formatting failed.".to_string(),
            context: Some(error.to_string()),
            suggestions: vec![
                "Check YAML indentation (use spaces, not tabs)".to_string(),
                "Validate YAML with online YAML validator".to_string(),
                "Ensure proper key-value syntax".to_string(),
                "Check for special characters that need quoting".to_string(),
                "Verify list and dictionary structures".to_string(),
            ],
            help_command: Some(
                "python -c 'import yaml; yaml.safe_load(open(\"file.yaml\"))'".to_string(),
            ),
            severity: ErrorSeverity::Error,
        }
    }

    fn format_transpiler_error(message: &str) -> FormattedError {
        FormattedError {
            title: "🔄 Transpiler Error".to_string(),
            message: "Code transpilation failed.".to_string(),
            context: Some(message.to_string()),
            suggestions: vec![
                "Check the source code syntax".to_string(),
                "Verify supported language features".to_string(),
                "Review transpiler configuration".to_string(),
                "Check for unsupported constructs".to_string(),
            ],
            help_command: None,
            severity: ErrorSeverity::Error,
        }
    }

    fn format_unknown_error(message: &str) -> FormattedError {
        FormattedError {
            title: "❓ Unknown Error".to_string(),
            message: "An unexpected error occurred.".to_string(),
            context: Some(message.to_string()),
            suggestions: vec![
                "Try the operation again".to_string(),
                "Check system logs for more details".to_string(),
                "Ensure all dependencies are installed".to_string(),
                "Report this issue if it persists".to_string(),
                "Include error details when reporting".to_string(),
            ],
            help_command: Some("rustchain --version".to_string()),
            severity: ErrorSeverity::Error,
        }
    }

    fn format_exec_error(message: &str) -> FormattedError {
        FormattedError {
            title: "Execution Error".to_string(),
            message: "Command execution failed.".to_string(),
            context: Some(message.to_string()),
            suggestions: vec![
                "Check command syntax and parameters".to_string(),
                "Verify required permissions".to_string(),
                "Ensure all dependencies are available".to_string(),
                "Check system resources".to_string(),
                "Try with simpler parameters first".to_string(),
            ],
            help_command: Some("rustchain tools list".to_string()),
            severity: ErrorSeverity::Error,
        }
    }
}

/// Formatted error with user-friendly information
#[derive(Debug, Clone)]
pub struct FormattedError {
    pub title: String,
    pub message: String,
    pub context: Option<String>,
    pub suggestions: Vec<String>,
    pub help_command: Option<String>,
    pub severity: ErrorSeverity,
}

/// Error severity levels for user interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for FormattedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.title)?;
        writeln!(f, "{}", self.message)?;

        if let Some(context) = &self.context {
            writeln!(f, "\n📋 Context:")?;
            writeln!(f, "{}", context)?;
        }

        if !self.suggestions.is_empty() {
            writeln!(f, "\nSuggestions:")?;
            for suggestion in &self.suggestions {
                writeln!(f, "  • {}", suggestion)?;
            }
        }

        if let Some(help_command) = &self.help_command {
            writeln!(f, "\n🔧 Try this command:")?;
            writeln!(f, "  {}", help_command)?;
        }

        Ok(())
    }
}

impl ErrorSeverity {
    pub fn icon(&self) -> &'static str {
        match self {
            ErrorSeverity::Info => "ℹ️",
            ErrorSeverity::Warning => "⚠️",
            ErrorSeverity::Error => "❌",
            ErrorSeverity::Critical => "🚨",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            ErrorSeverity::Info => "\x1b[36m",     // Cyan
            ErrorSeverity::Warning => "\x1b[33m",  // Yellow
            ErrorSeverity::Error => "\x1b[31m",    // Red
            ErrorSeverity::Critical => "\x1b[35m", // Magenta
        }
    }
}

/// Pretty print an error with colors and formatting
pub fn print_formatted_error(error: &RustChainError) {
    let formatted = ErrorFormatter::format_user_friendly(error);

    // Print with color support if available
    if std::io::stderr().is_terminal() {
        print_colored_error(&formatted);
    } else {
        eprintln!("{}", formatted);
    }
}

fn print_colored_error(formatted: &FormattedError) {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let color = formatted.severity.color_code();

    // Title with color and icon
    eprintln!(
        "{}{}{} {}{}",
        color,
        bold,
        formatted.severity.icon(),
        formatted.title,
        reset
    );
    eprintln!("{}", formatted.message);

    // Context
    if let Some(context) = &formatted.context {
        eprintln!("\n{}📋 Context:{}", bold, reset);
        eprintln!("{}", context);
    }

    // Suggestions
    if !formatted.suggestions.is_empty() {
        eprintln!("\n{}Suggestions:{}", bold, reset);
        for suggestion in &formatted.suggestions {
            eprintln!("  • {}", suggestion);
        }
    }

    // Help command
    if let Some(help_command) = &formatted.help_command {
        eprintln!("\n{}🔧 Try this command:{}", bold, reset);
        eprintln!("  \x1b[32m{}{}", help_command, reset); // Green for commands
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error_formatting() {
        let error = ConfigError::missing_key("api_key");
        let formatted = ErrorFormatter::format_user_friendly(&RustChainError::Config(error));

        assert_eq!(formatted.title, "🔧 Configuration Missing");
        assert!(formatted.message.contains("api_key"));
        assert!(!formatted.suggestions.is_empty());
        assert!(formatted.help_command.is_some());
    }

    #[test]
    fn test_llm_error_formatting() {
        let error = LlmError::authentication_failed("openai", "invalid key");
        let formatted = ErrorFormatter::format_user_friendly(&RustChainError::Llm(error));

        assert_eq!(formatted.title, "🔐 AI Authentication Failed");
        assert!(formatted.message.contains("openai"));
        assert!(formatted.context.is_some());
        assert!(!formatted.suggestions.is_empty());
    }

    #[test]
    fn test_tool_error_formatting() {
        let error = ToolError::not_found("missing_tool");
        let formatted = ErrorFormatter::format_user_friendly(&RustChainError::Tool(error));

        assert_eq!(formatted.title, "🔧 Tool Not Found");
        assert!(formatted.message.contains("missing_tool"));
        assert_eq!(formatted.severity, ErrorSeverity::Error);
    }

    #[test]
    fn test_formatted_error_display() {
        let formatted = FormattedError {
            title: "Test Error".to_string(),
            message: "Test message".to_string(),
            context: Some("Test context".to_string()),
            suggestions: vec!["Suggestion 1".to_string(), "Suggestion 2".to_string()],
            help_command: Some("test command".to_string()),
            severity: ErrorSeverity::Warning,
        };

        let display_text = formatted.to_string();
        assert!(display_text.contains("Test Error"));
        assert!(display_text.contains("Test message"));
        assert!(display_text.contains("Test context"));
        assert!(display_text.contains("Suggestion 1"));
        assert!(display_text.contains("test command"));
    }

    #[test]
    fn test_severity_properties() {
        assert_eq!(ErrorSeverity::Info.icon(), "ℹ️");
        assert_eq!(ErrorSeverity::Warning.icon(), "⚠️");
        assert_eq!(ErrorSeverity::Error.icon(), "❌");
        assert_eq!(ErrorSeverity::Critical.icon(), "🚨");

        assert_eq!(ErrorSeverity::Info.color_code(), "\x1b[36m");
        assert_eq!(ErrorSeverity::Warning.color_code(), "\x1b[33m");
        assert_eq!(ErrorSeverity::Error.color_code(), "\x1b[31m");
        assert_eq!(ErrorSeverity::Critical.color_code(), "\x1b[35m");
    }

    #[test]
    fn test_all_error_types_formatting() {
        // Test that all RustChainError variants can be formatted
        let errors = vec![
            RustChainError::Config(ConfigError::missing_key("test")),
            RustChainError::Llm(LlmError::timeout(1000)),
            RustChainError::Memory(MemoryError::store_not_found("test")),
            RustChainError::Tool(ToolError::not_found("test")),
            RustChainError::Execution(ExecutionError::mission_not_found("test")),
            RustChainError::Schema(SchemaError::schema_not_found("test")),
            RustChainError::Security("test security error".to_string()),
            RustChainError::Unknown {
                message: "test unknown".to_string(),
            },
            RustChainError::Exec("test exec".to_string()),
        ];

        for error in errors {
            let formatted = ErrorFormatter::format_user_friendly(&error);
            assert!(!formatted.title.is_empty());
            assert!(!formatted.message.is_empty());
            assert!(!formatted.suggestions.is_empty());
        }
    }
}
