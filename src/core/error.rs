use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Structured configuration error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("Missing required configuration key: {key}")]
    MissingKey { key: String },
    #[error("Invalid configuration value for {key}: expected {expected}, got {actual}")]
    InvalidValue {
        key: String,
        expected: String,
        actual: String,
    },
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: String },
    #[error("Failed to parse configuration: {reason}")]
    ParseError { reason: String },
    #[error("Plugin error: {message}")]
    PluginError { message: String },
}

/// Structured LLM error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LlmError {
    #[error("LLM service unavailable: {provider}")]
    ServiceUnavailable { provider: String },
    #[error("Authentication failed for {provider}: {reason}")]
    AuthenticationFailed { provider: String, reason: String },
    #[error("Request timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("Invalid prompt: {reason}")]
    InvalidPrompt { reason: String },
    #[error("Rate limit exceeded for {provider}: retry after {retry_after_seconds}s")]
    RateLimitExceeded {
        provider: String,
        retry_after_seconds: u64,
    },
    #[error("LLM responded with error: {message}")]
    ResponseError { message: String },
}

/// Structured memory error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MemoryError {
    #[error("Memory store not found: {store_id}")]
    StoreNotFound { store_id: String },
    #[error("Memory key not found: {key} in store {store_id}")]
    KeyNotFound { key: String, store_id: String },
    #[error("Memory store capacity exceeded: {current}/{max}")]
    CapacityExceeded { current: usize, max: usize },
    #[error("Invalid memory operation: {operation} on {store_type}")]
    InvalidOperation {
        operation: String,
        store_type: String,
    },
    #[error("Memory serialization failed: {reason}")]
    SerializationFailed { reason: String },
    #[error("Memory store corrupted: {details}")]
    Corrupted { details: String },
}

/// Structured tool error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ToolError {
    #[error("Tool not found: {tool_name}")]
    NotFound { tool_name: String },
    #[error("Tool execution failed: {tool_name} - {reason}")]
    ExecutionFailed { tool_name: String, reason: String },
    #[error("Invalid tool parameters for {tool_name}: {details}")]
    InvalidParameters { tool_name: String, details: String },
    #[error("Tool timeout: {tool_name} exceeded {timeout_ms}ms")]
    Timeout { tool_name: String, timeout_ms: u64 },
    #[error("Tool permission denied: {tool_name} - {reason}")]
    PermissionDenied { tool_name: String, reason: String },
    #[error("Tool dependency missing: {tool_name} requires {dependency}")]
    DependencyMissing {
        tool_name: String,
        dependency: String,
    },
}

/// Structured execution error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExecutionError {
    #[error("Mission not found: {mission_id}")]
    MissionNotFound { mission_id: String },
    #[error("Step failed: {step_id} in mission {mission_id} - {reason}")]
    StepFailed {
        step_id: String,
        mission_id: String,
        reason: String,
    },
    #[error("Dependency cycle detected in mission {mission_id}: {cycle}")]
    DependencyCycle { mission_id: String, cycle: String },
    #[error("Resource exhausted: {resource} - {details}")]
    ResourceExhausted { resource: String, details: String },
    #[error("Execution timeout: mission {mission_id} exceeded {timeout_ms}ms")]
    Timeout { mission_id: String, timeout_ms: u64 },
    #[error("Invalid mission state: {state} for operation {operation}")]
    InvalidState { state: String, operation: String },
}

/// Structured schema validation error types
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SchemaError {
    #[error("Schema validation failed for {schema_name}: {}", errors.join(", "))]
    ValidationFailed {
        schema_name: String,
        errors: Vec<String>,
    },
    #[error("Schema not found: {schema_name}")]
    SchemaNotFound { schema_name: String },
    #[error("Invalid schema definition: {schema_name} - {reason}")]
    InvalidDefinition { schema_name: String, reason: String },
    #[error("Schema version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },
}

/// Main RustChain error enum with structured error types
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RustChainError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("LLM error: {0}")]
    Llm(#[from] LlmError),

    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),

    #[error("Tool error: {0}")]
    Tool(#[from] ToolError),

    #[error("Execution error: {0}")]
    Execution(#[from] ExecutionError),

    #[error("Schema validation error: {0}")]
    Schema(#[from] SchemaError),

    // TODO: Reintroduce EngineError if needed
    // #[error("Engine error: {0}")]
    // Engine(#[from] crate::engine::EngineError),
    #[error("Security error: {0}")]
    Security(String),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Transpiler error: {0}")]
    Transpiler(String),

    #[error("Unknown error: {message}")]
    Unknown { message: String },

    #[error("Execution error: {0}")]
    Exec(String),
}

pub type Result<T> = std::result::Result<T, RustChainError>;

// Implementations for structured error constructors
impl ConfigError {
    /// Creates a new MissingKey error for a required configuration key
    pub fn missing_key(key: impl Into<String>) -> Self {
        Self::MissingKey { key: key.into() }
    }

    /// Creates a new InvalidValue error for a configuration key with invalid value
    pub fn invalid_value(
        key: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::InvalidValue {
            key: key.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    pub fn file_not_found(path: impl Into<String>) -> Self {
        Self::FileNotFound { path: path.into() }
    }

    pub fn parse_error(reason: impl Into<String>) -> Self {
        Self::ParseError {
            reason: reason.into(),
        }
    }
}

impl LlmError {
    pub fn service_unavailable(provider: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            provider: provider.into(),
        }
    }

    pub fn authentication_failed(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::AuthenticationFailed {
            provider: provider.into(),
            reason: reason.into(),
        }
    }

    pub fn timeout(timeout_ms: u64) -> Self {
        Self::Timeout { timeout_ms }
    }

    pub fn invalid_prompt(reason: impl Into<String>) -> Self {
        Self::InvalidPrompt {
            reason: reason.into(),
        }
    }

    pub fn rate_limit_exceeded(provider: impl Into<String>, retry_after_seconds: u64) -> Self {
        Self::RateLimitExceeded {
            provider: provider.into(),
            retry_after_seconds,
        }
    }

    pub fn response_error(message: impl Into<String>) -> Self {
        Self::ResponseError {
            message: message.into(),
        }
    }
}

impl MemoryError {
    pub fn store_not_found(store_id: impl Into<String>) -> Self {
        Self::StoreNotFound {
            store_id: store_id.into(),
        }
    }

    pub fn key_not_found(key: impl Into<String>, store_id: impl Into<String>) -> Self {
        Self::KeyNotFound {
            key: key.into(),
            store_id: store_id.into(),
        }
    }

    pub fn capacity_exceeded(current: usize, max: usize) -> Self {
        Self::CapacityExceeded { current, max }
    }

    pub fn invalid_operation(operation: impl Into<String>, store_type: impl Into<String>) -> Self {
        Self::InvalidOperation {
            operation: operation.into(),
            store_type: store_type.into(),
        }
    }

    pub fn serialization_failed(reason: impl Into<String>) -> Self {
        Self::SerializationFailed {
            reason: reason.into(),
        }
    }

    pub fn corrupted(details: impl Into<String>) -> Self {
        Self::Corrupted {
            details: details.into(),
        }
    }
}

impl ToolError {
    pub fn not_found(tool_name: impl Into<String>) -> Self {
        Self::NotFound {
            tool_name: tool_name.into(),
        }
    }

    pub fn execution_failed(tool_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ExecutionFailed {
            tool_name: tool_name.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_parameters(tool_name: impl Into<String>, details: impl Into<String>) -> Self {
        Self::InvalidParameters {
            tool_name: tool_name.into(),
            details: details.into(),
        }
    }

    pub fn timeout(tool_name: impl Into<String>, timeout_ms: u64) -> Self {
        Self::Timeout {
            tool_name: tool_name.into(),
            timeout_ms,
        }
    }

    pub fn permission_denied(tool_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::PermissionDenied {
            tool_name: tool_name.into(),
            reason: reason.into(),
        }
    }

    pub fn dependency_missing(tool_name: impl Into<String>, dependency: impl Into<String>) -> Self {
        Self::DependencyMissing {
            tool_name: tool_name.into(),
            dependency: dependency.into(),
        }
    }
}

impl ExecutionError {
    pub fn mission_not_found(mission_id: impl Into<String>) -> Self {
        Self::MissionNotFound {
            mission_id: mission_id.into(),
        }
    }

    pub fn step_failed(
        step_id: impl Into<String>,
        mission_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::StepFailed {
            step_id: step_id.into(),
            mission_id: mission_id.into(),
            reason: reason.into(),
        }
    }

    pub fn dependency_cycle(mission_id: impl Into<String>, cycle: impl Into<String>) -> Self {
        Self::DependencyCycle {
            mission_id: mission_id.into(),
            cycle: cycle.into(),
        }
    }

    pub fn resource_exhausted(resource: impl Into<String>, details: impl Into<String>) -> Self {
        Self::ResourceExhausted {
            resource: resource.into(),
            details: details.into(),
        }
    }

    pub fn timeout(mission_id: impl Into<String>, timeout_ms: u64) -> Self {
        Self::Timeout {
            mission_id: mission_id.into(),
            timeout_ms,
        }
    }

    pub fn invalid_state(state: impl Into<String>, operation: impl Into<String>) -> Self {
        Self::InvalidState {
            state: state.into(),
            operation: operation.into(),
        }
    }
}

impl SchemaError {
    pub fn validation_failed(schema_name: impl Into<String>, errors: Vec<String>) -> Self {
        Self::ValidationFailed {
            schema_name: schema_name.into(),
            errors,
        }
    }

    pub fn schema_not_found(schema_name: impl Into<String>) -> Self {
        Self::SchemaNotFound {
            schema_name: schema_name.into(),
        }
    }

    pub fn invalid_definition(schema_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidDefinition {
            schema_name: schema_name.into(),
            reason: reason.into(),
        }
    }

    pub fn version_mismatch(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::VersionMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

// Keep compatibility for external crates that depend on anyhow
impl From<anyhow::Error> for RustChainError {
    fn from(e: anyhow::Error) -> Self {
        RustChainError::Unknown {
            message: e.to_string(),
        }
    }
}

// For backward compatibility during migration - these should be removed eventually
impl From<String> for RustChainError {
    fn from(e: String) -> Self {
        RustChainError::Unknown { message: e }
    }
}

impl From<&str> for RustChainError {
    fn from(e: &str) -> Self {
        RustChainError::Unknown {
            message: e.to_string(),
        }
    }
}

impl From<std::fmt::Error> for RustChainError {
    fn from(e: std::fmt::Error) -> Self {
        RustChainError::Unknown {
            message: format!("Format error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_config_error_variants() {
        let missing = ConfigError::missing_key("api_key");
        assert!(missing
            .to_string()
            .contains("Missing required configuration key: api_key"));

        let invalid = ConfigError::invalid_value("timeout", "number", "string");
        assert!(invalid
            .to_string()
            .contains("Invalid configuration value for timeout"));
        assert!(invalid.to_string().contains("expected number, got string"));

        let not_found = ConfigError::file_not_found("/path/to/config.toml");
        assert!(not_found
            .to_string()
            .contains("Configuration file not found: /path/to/config.toml"));

        let parse = ConfigError::parse_error("invalid TOML syntax");
        assert!(parse
            .to_string()
            .contains("Failed to parse configuration: invalid TOML syntax"));
    }

    #[test]
    fn test_config_error_serialization() {
        let error = ConfigError::missing_key("test_key");

        // Test serialization
        let serialized = serde_json::to_string(&error).unwrap();
        assert!(serialized.contains("MissingKey"));
        assert!(serialized.contains("test_key"));

        // Test deserialization
        let deserialized: ConfigError = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            ConfigError::MissingKey { key } => assert_eq!(key, "test_key"),
            _ => panic!("Deserialization failed"),
        }
    }

    #[test]
    fn test_llm_error_variants() {
        let unavailable = LlmError::service_unavailable("openai");
        assert!(unavailable
            .to_string()
            .contains("LLM service unavailable: openai"));

        let auth_failed = LlmError::authentication_failed("anthropic", "invalid API key");
        assert!(auth_failed
            .to_string()
            .contains("Authentication failed for anthropic"));
        assert!(auth_failed.to_string().contains("invalid API key"));

        let timeout = LlmError::timeout(30000);
        assert!(timeout
            .to_string()
            .contains("Request timeout after 30000ms"));

        let invalid_prompt = LlmError::invalid_prompt("empty prompt");
        assert!(invalid_prompt
            .to_string()
            .contains("Invalid prompt: empty prompt"));

        let rate_limit = LlmError::rate_limit_exceeded("openai", 60);
        assert!(rate_limit
            .to_string()
            .contains("Rate limit exceeded for openai"));
        assert!(rate_limit.to_string().contains("retry after 60s"));

        let response_error = LlmError::response_error("model returned error");
        assert!(response_error
            .to_string()
            .contains("LLM responded with error: model returned error"));
    }

    #[test]
    fn test_llm_error_serialization() {
        let error = LlmError::timeout(5000);

        let serialized = serde_json::to_string(&error).unwrap();
        assert!(serialized.contains("Timeout"));
        assert!(serialized.contains("5000"));

        let deserialized: LlmError = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            LlmError::Timeout { timeout_ms } => assert_eq!(timeout_ms, 5000),
            _ => panic!("Deserialization failed"),
        }
    }

    #[test]
    fn test_memory_error_variants() {
        let store_not_found = MemoryError::store_not_found("main_store");
        assert!(store_not_found
            .to_string()
            .contains("Memory store not found: main_store"));

        let key_not_found = MemoryError::key_not_found("user_data", "session_store");
        assert!(key_not_found
            .to_string()
            .contains("Memory key not found: user_data in store session_store"));

        let capacity = MemoryError::capacity_exceeded(150, 100);
        assert!(capacity
            .to_string()
            .contains("Memory store capacity exceeded: 150/100"));

        let invalid_op = MemoryError::invalid_operation("delete", "read_only");
        assert!(invalid_op
            .to_string()
            .contains("Invalid memory operation: delete on read_only"));

        let serialization = MemoryError::serialization_failed("invalid JSON");
        assert!(serialization
            .to_string()
            .contains("Memory serialization failed: invalid JSON"));

        let corrupted = MemoryError::corrupted("checksum mismatch");
        assert!(corrupted
            .to_string()
            .contains("Memory store corrupted: checksum mismatch"));
    }

    #[test]
    fn test_memory_error_serialization() {
        let error = MemoryError::capacity_exceeded(200, 100);

        let serialized = serde_json::to_string(&error).unwrap();
        assert!(serialized.contains("CapacityExceeded"));
        assert!(serialized.contains("200"));
        assert!(serialized.contains("100"));

        let deserialized: MemoryError = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            MemoryError::CapacityExceeded { current, max } => {
                assert_eq!(current, 200);
                assert_eq!(max, 100);
            }
            _ => panic!("Deserialization failed"),
        }
    }

    #[test]
    fn test_tool_error_variants() {
        let not_found = ToolError::not_found("missing_tool");
        assert!(not_found
            .to_string()
            .contains("Tool not found: missing_tool"));

        let execution_failed = ToolError::execution_failed("file_reader", "permission denied");
        assert!(execution_failed
            .to_string()
            .contains("Tool execution failed: file_reader - permission denied"));

        let invalid_params = ToolError::invalid_parameters("calculator", "missing operands");
        assert!(invalid_params
            .to_string()
            .contains("Invalid tool parameters for calculator: missing operands"));

        let timeout = ToolError::timeout("slow_tool", 10000);
        assert!(timeout
            .to_string()
            .contains("Tool timeout: slow_tool exceeded 10000ms"));

        let permission = ToolError::permission_denied("system_tool", "insufficient privileges");
        assert!(permission
            .to_string()
            .contains("Tool permission denied: system_tool - insufficient privileges"));

        let dependency = ToolError::dependency_missing("advanced_tool", "basic_tool");
        assert!(dependency
            .to_string()
            .contains("Tool dependency missing: advanced_tool requires basic_tool"));
    }

    #[test]
    fn test_tool_error_serialization() {
        let error = ToolError::timeout("test_tool", 5000);

        let serialized = serde_json::to_string(&error).unwrap();
        assert!(serialized.contains("Timeout"));
        assert!(serialized.contains("test_tool"));
        assert!(serialized.contains("5000"));

        let deserialized: ToolError = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            ToolError::Timeout {
                tool_name,
                timeout_ms,
            } => {
                assert_eq!(tool_name, "test_tool");
                assert_eq!(timeout_ms, 5000);
            }
            _ => panic!("Deserialization failed"),
        }
    }

    #[test]
    fn test_execution_error_variants() {
        let mission_not_found = ExecutionError::mission_not_found("mission_123");
        assert!(mission_not_found
            .to_string()
            .contains("Mission not found: mission_123"));

        let step_failed = ExecutionError::step_failed("step_1", "mission_456", "validation error");
        assert!(step_failed
            .to_string()
            .contains("Step failed: step_1 in mission mission_456 - validation error"));

        let cycle = ExecutionError::dependency_cycle("mission_789", "A -> B -> C -> A");
        assert!(cycle
            .to_string()
            .contains("Dependency cycle detected in mission mission_789: A -> B -> C -> A"));

        let resource = ExecutionError::resource_exhausted("memory", "8GB limit reached");
        assert!(resource
            .to_string()
            .contains("Resource exhausted: memory - 8GB limit reached"));

        let timeout = ExecutionError::timeout("mission_abc", 60000);
        assert!(timeout
            .to_string()
            .contains("Execution timeout: mission mission_abc exceeded 60000ms"));

        let invalid_state = ExecutionError::invalid_state("running", "pause");
        assert!(invalid_state
            .to_string()
            .contains("Invalid mission state: running for operation pause"));
    }

    #[test]
    fn test_execution_error_serialization() {
        let error = ExecutionError::step_failed("test_step", "test_mission", "test_reason");

        let serialized = serde_json::to_string(&error).unwrap();
        assert!(serialized.contains("StepFailed"));
        assert!(serialized.contains("test_step"));
        assert!(serialized.contains("test_mission"));
        assert!(serialized.contains("test_reason"));

        let deserialized: ExecutionError = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            ExecutionError::StepFailed {
                step_id,
                mission_id,
                reason,
            } => {
                assert_eq!(step_id, "test_step");
                assert_eq!(mission_id, "test_mission");
                assert_eq!(reason, "test_reason");
            }
            _ => panic!("Deserialization failed"),
        }
    }

    #[test]
    fn test_schema_error_variants() {
        let validation_failed = SchemaError::validation_failed(
            "user_schema",
            vec![
                "missing field 'name'".to_string(),
                "invalid email format".to_string(),
            ],
        );
        assert!(validation_failed
            .to_string()
            .contains("Schema validation failed for user_schema"));
        assert!(validation_failed
            .to_string()
            .contains("missing field 'name'"));
        assert!(validation_failed
            .to_string()
            .contains("invalid email format"));

        let not_found = SchemaError::schema_not_found("unknown_schema");
        assert!(not_found
            .to_string()
            .contains("Schema not found: unknown_schema"));

        let invalid_def = SchemaError::invalid_definition("bad_schema", "circular reference");
        assert!(invalid_def
            .to_string()
            .contains("Invalid schema definition: bad_schema - circular reference"));

        let version_mismatch = SchemaError::version_mismatch("2.0", "1.5");
        assert!(version_mismatch
            .to_string()
            .contains("Schema version mismatch: expected 2.0, got 1.5"));
    }

    #[test]
    fn test_schema_error_serialization() {
        let error = SchemaError::validation_failed(
            "test_schema",
            vec!["error1".to_string(), "error2".to_string()],
        );

        let serialized = serde_json::to_string(&error).unwrap();
        assert!(serialized.contains("ValidationFailed"));
        assert!(serialized.contains("test_schema"));
        assert!(serialized.contains("error1"));
        assert!(serialized.contains("error2"));

        let deserialized: SchemaError = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            SchemaError::ValidationFailed {
                schema_name,
                errors,
            } => {
                assert_eq!(schema_name, "test_schema");
                assert_eq!(errors, vec!["error1", "error2"]);
            }
            _ => panic!("Deserialization failed"),
        }
    }

    #[test]
    fn test_rustchain_error_variants() {
        // Test IO error conversion
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let rustchain_io: RustChainError = io_error.into();
        assert!(rustchain_io.to_string().contains("IO error"));

        // Test structured error conversions
        let config_error = ConfigError::missing_key("test");
        let rustchain_config: RustChainError = config_error.into();
        assert!(rustchain_config.to_string().contains("Configuration error"));

        let llm_error = LlmError::timeout(1000);
        let rustchain_llm: RustChainError = llm_error.into();
        assert!(rustchain_llm.to_string().contains("LLM error"));

        let memory_error = MemoryError::store_not_found("test");
        let rustchain_memory: RustChainError = memory_error.into();
        assert!(rustchain_memory.to_string().contains("Memory error"));

        let tool_error = ToolError::not_found("test");
        let rustchain_tool: RustChainError = tool_error.into();
        assert!(rustchain_tool.to_string().contains("Tool error"));

        let execution_error = ExecutionError::mission_not_found("test");
        let rustchain_execution: RustChainError = execution_error.into();
        assert!(rustchain_execution.to_string().contains("Execution error"));

        let schema_error = SchemaError::schema_not_found("test");
        let rustchain_schema: RustChainError = schema_error.into();
        assert!(rustchain_schema
            .to_string()
            .contains("Schema validation error"));
    }

    #[test]
    fn test_rustchain_error_json_yaml() {
        // Test JSON error conversion
        let json_error = serde_json::from_str::<serde_json::Value>("invalid json");
        assert!(json_error.is_err());
        let rustchain_json: RustChainError = json_error.unwrap_err().into();
        assert!(rustchain_json
            .to_string()
            .contains("JSON serialization error"));

        // Test YAML error conversion - create a YAML error by deserializing invalid YAML
        let yaml_error = serde_yaml::from_str::<serde_yaml::Value>("invalid: yaml: structure");
        assert!(yaml_error.is_err());
        let rustchain_yaml: RustChainError = yaml_error.unwrap_err().into();
        assert!(rustchain_yaml
            .to_string()
            .contains("YAML serialization error"));
    }

    #[test]
    fn test_rustchain_error_unknown() {
        let unknown = RustChainError::Unknown {
            message: "test unknown error".to_string(),
        };
        assert!(unknown
            .to_string()
            .contains("Unknown error: test unknown error"));
    }

    #[test]
    fn test_rustchain_error_exec() {
        let exec = RustChainError::Exec("execution failed".to_string());
        assert!(exec
            .to_string()
            .contains("Execution error: execution failed"));
    }

    #[test]
    fn test_anyhow_conversion() {
        let anyhow_error = anyhow::anyhow!("test anyhow error");
        let rustchain_error: RustChainError = anyhow_error.into();

        match rustchain_error {
            RustChainError::Unknown { message } => {
                assert_eq!(message, "test anyhow error");
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_string_conversions() {
        // Test String conversion
        let string_error = "string error".to_string();
        let rustchain_string: RustChainError = string_error.into();

        match rustchain_string {
            RustChainError::Unknown { message } => {
                assert_eq!(message, "string error");
            }
            _ => panic!("Expected Unknown variant"),
        }

        // Test &str conversion
        let str_error = "str error";
        let rustchain_str: RustChainError = str_error.into();

        match rustchain_str {
            RustChainError::Unknown { message } => {
                assert_eq!(message, "str error");
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_error_cloning() {
        // Test that all structured errors can be cloned
        let config = ConfigError::missing_key("test");
        let _config_clone = config.clone();

        let llm = LlmError::timeout(1000);
        let _llm_clone = llm.clone();

        let memory = MemoryError::store_not_found("test");
        let _memory_clone = memory.clone();

        let tool = ToolError::not_found("test");
        let _tool_clone = tool.clone();

        let execution = ExecutionError::mission_not_found("test");
        let _execution_clone = execution.clone();

        let schema = SchemaError::schema_not_found("test");
        let _schema_clone = schema.clone();
    }

    #[test]
    fn test_error_debug_formatting() {
        let config_error = ConfigError::missing_key("api_key");
        let debug_string = format!("{:?}", config_error);
        assert!(debug_string.contains("MissingKey"));
        assert!(debug_string.contains("api_key"));

        let llm_error = LlmError::timeout(5000);
        let debug_string = format!("{:?}", llm_error);
        assert!(debug_string.contains("Timeout"));
        assert!(debug_string.contains("5000"));
    }

    #[test]
    fn test_result_type_alias() {
        // Test that the Result type alias works correctly
        fn test_function() -> Result<String> {
            Ok("success".to_string())
        }

        fn test_error_function() -> Result<String> {
            Err(ConfigError::missing_key("test").into())
        }

        let success = test_function();
        assert!(success.is_ok());
        assert_eq!(success.unwrap(), "success");

        let error = test_error_function();
        assert!(error.is_err());

        match error.unwrap_err() {
            RustChainError::Config(ConfigError::MissingKey { key }) => {
                assert_eq!(key, "test");
            }
            _ => panic!("Expected Config error"),
        }
    }

    #[test]
    fn test_complex_error_scenarios() {
        // Test nested error scenarios that might occur in real usage

        // Complex validation error with multiple issues
        let validation_errors = vec![
            "field 'name' is required".to_string(),
            "field 'email' must be valid email address".to_string(),
            "field 'age' must be between 0 and 150".to_string(),
        ];
        let schema_error = SchemaError::validation_failed("user_registration", validation_errors);
        let rustchain_error: RustChainError = schema_error.into();

        let error_string = rustchain_error.to_string();
        assert!(error_string.contains("field 'name' is required"));
        assert!(error_string.contains("field 'email' must be valid"));
        assert!(error_string.contains("field 'age' must be between"));

        // Complex execution error with detailed context
        let execution_error = ExecutionError::step_failed(
            "data_validation_step",
            "user_onboarding_mission",
            "Schema validation failed: multiple field errors",
        );

        let error_string = execution_error.to_string();
        assert!(error_string.contains("data_validation_step"));
        assert!(error_string.contains("user_onboarding_mission"));
        assert!(error_string.contains("Schema validation failed"));
    }

    #[test]
    fn test_error_constructor_functions() {
        // Test that all constructor functions work correctly with various input types

        // Test with &str inputs
        let config1 = ConfigError::missing_key("test_key");
        let config2 = ConfigError::invalid_value("timeout", "u64", "string");
        assert!(config1.to_string().contains("test_key"));
        assert!(config2.to_string().contains("timeout"));

        // Test with String inputs
        let config3 = ConfigError::missing_key("test_key".to_string());
        let config4 = ConfigError::file_not_found("/path/to/file".to_string());
        assert!(config3.to_string().contains("test_key"));
        assert!(config4.to_string().contains("/path/to/file"));

        // Test LLM constructors
        let llm1 = LlmError::service_unavailable("openai");
        let llm2 =
            LlmError::authentication_failed("anthropic".to_string(), "invalid key".to_string());
        assert!(llm1.to_string().contains("openai"));
        assert!(llm2.to_string().contains("anthropic"));
        assert!(llm2.to_string().contains("invalid key"));

        // Test Memory constructors
        let mem1 = MemoryError::key_not_found("user_data", "session_store");
        let mem2 = MemoryError::invalid_operation("delete".to_string(), "readonly".to_string());
        assert!(mem1.to_string().contains("user_data"));
        assert!(mem1.to_string().contains("session_store"));
        assert!(mem2.to_string().contains("delete"));
        assert!(mem2.to_string().contains("readonly"));

        // Test Tool constructors
        let tool1 = ToolError::execution_failed("file_tool", "permission denied");
        let tool2 =
            ToolError::dependency_missing("advanced_tool".to_string(), "basic_tool".to_string());
        assert!(tool1.to_string().contains("file_tool"));
        assert!(tool1.to_string().contains("permission denied"));
        assert!(tool2.to_string().contains("advanced_tool"));
        assert!(tool2.to_string().contains("basic_tool"));

        // Test Execution constructors
        let exec1 = ExecutionError::step_failed("step1", "mission1", "failed");
        let exec2 = ExecutionError::dependency_cycle("mission2".to_string(), "A->B->A".to_string());
        assert!(exec1.to_string().contains("step1"));
        assert!(exec1.to_string().contains("mission1"));
        assert!(exec1.to_string().contains("failed"));
        assert!(exec2.to_string().contains("mission2"));
        assert!(exec2.to_string().contains("A->B->A"));

        // Test Schema constructors
        let schema1 = SchemaError::schema_not_found("missing_schema");
        let schema2 = SchemaError::version_mismatch("2.0".to_string(), "1.0".to_string());
        assert!(schema1.to_string().contains("missing_schema"));
        assert!(schema2.to_string().contains("expected 2.0, got 1.0"));
    }

    #[test]
    fn test_edge_cases() {
        // Test with empty strings
        let config_empty = ConfigError::missing_key("");
        assert!(config_empty
            .to_string()
            .contains("Missing required configuration key: "));

        let llm_empty = LlmError::service_unavailable("");
        assert!(llm_empty.to_string().contains("LLM service unavailable: "));

        // Test with very long strings
        let long_string = "a".repeat(1000);
        let config_long = ConfigError::parse_error(&long_string);
        assert!(config_long.to_string().contains(&long_string));

        // Test with special characters
        let special_chars = "test@#$%^&*()_+-=[]{}|;':\",./<>?";
        let memory_special = MemoryError::store_not_found(special_chars);
        assert!(memory_special.to_string().contains(special_chars));

        // Test zero values
        let timeout_zero = LlmError::timeout(0);
        assert!(timeout_zero.to_string().contains("timeout after 0ms"));

        let capacity_zero = MemoryError::capacity_exceeded(0, 0);
        assert!(capacity_zero.to_string().contains("0/0"));

        // Test very large values
        let timeout_large = ToolError::timeout("tool", u64::MAX);
        assert!(timeout_large.to_string().contains(&u64::MAX.to_string()));
    }
}
