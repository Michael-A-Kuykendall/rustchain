//! Central configuration constants for RustChain
//!
//! All magic numbers and default values should be defined here for easy auditing
//! and configuration. These values are used throughout the codebase.

// =============================================================================
// HTTP Client Configuration
// =============================================================================

/// Default HTTP request timeout in seconds
pub const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

/// Default HTTP connection timeout in seconds
pub const DEFAULT_HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Maximum size for error response bodies (64KB)
pub const MAX_ERROR_BODY_SIZE: usize = 64 * 1024;

/// Maximum size for general response bodies (10MB)
pub const MAX_RESPONSE_BODY_SIZE: usize = 10 * 1024 * 1024;

// =============================================================================
// Command Execution
// =============================================================================

/// Default command execution timeout in seconds (5 minutes)
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 300;

/// Default pip command timeout in seconds
pub const PIP_COMMAND_TIMEOUT_SECS: u64 = 60;

// =============================================================================
// Archive/Compression Limits
// =============================================================================

/// Maximum individual file size for archiving (100MB)
pub const ARCHIVE_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum total archive size (1GB)
pub const ARCHIVE_MAX_TOTAL_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum number of files in an archive
pub const ARCHIVE_MAX_FILE_COUNT: usize = 10000;

// =============================================================================
// Tool Configuration
// =============================================================================

/// Default tool execution timeout in milliseconds
pub const DEFAULT_TOOL_TIMEOUT_MS: u64 = 30000;

// =============================================================================
// Validation Limits
// =============================================================================

/// Maximum input length for validation
pub const VALIDATION_MAX_INPUT_LENGTH: usize = 10000;

/// Maximum name/label length
pub const VALIDATION_MAX_NAME_LENGTH: usize = 1000;

// =============================================================================
// Rate Limiting
// =============================================================================

/// Default requests per hour for rate limiting
pub const DEFAULT_REQUESTS_PER_HOUR: u32 = 1000;

// =============================================================================
// RAG/Chunking
// =============================================================================

/// Default chunk size for document processing
pub const DEFAULT_CHUNK_SIZE: usize = 1000;

// =============================================================================
// Security/Threat Detection
// =============================================================================

/// Geographic anomaly threshold in kilometers
pub const GEO_ANOMALY_THRESHOLD_KM: f64 = 1000.0;

// =============================================================================
// LLM Configuration  
// =============================================================================

/// Default LLM request timeout in seconds
pub const LLM_REQUEST_TIMEOUT_SECS: u64 = 120;

/// Default LLM connection timeout in seconds  
pub const LLM_CONNECT_TIMEOUT_SECS: u64 = 30;

// =============================================================================
// Mission Engine
// =============================================================================

/// Default step timeout in seconds
pub const DEFAULT_STEP_TIMEOUT_SECS: u64 = 60;

/// Maximum mission steps allowed
pub const MAX_MISSION_STEPS: usize = 1000;

/// Maximum variable substitution depth (prevent infinite loops)
pub const MAX_VARIABLE_SUBSTITUTION_DEPTH: usize = 10;
