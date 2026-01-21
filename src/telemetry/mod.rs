use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "rustchain".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            log_level: "info".to_string(),
        }
    }
}

pub struct TelemetryManager {
    config: TelemetryConfig,
}

impl TelemetryManager {
    pub fn new(config: TelemetryConfig) -> Self {
        Self { config }
    }

    pub fn init(&self) -> Result<(), TelemetryError> {
        if !self.config.enabled {
            tracing::info!("Telemetry disabled by configuration");
            return Ok(());
        }

        self.init_logging()?;

        tracing::info!(
            "Telemetry initialized for service {} v{} in {} environment",
            self.config.service_name,
            self.config.service_version,
            self.config.environment
        );

        Ok(())
    }

    fn init_logging(&self) -> Result<(), TelemetryError> {
        Registry::default()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}={}", self.config.service_name, self.config.log_level).into()
            }))
            .with(fmt::layer())
            .try_init()
            .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;

        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), TelemetryError> {
        tracing::info!("Telemetry shutdown completed");
        Ok(())
    }
}

impl Drop for TelemetryManager {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            tracing::error!("Error shutting down telemetry: {}", e);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("Failed to initialize logging: {0}")]
    LoggingInit(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Convenience macros for instrumentation
pub use tracing::{debug, error, info, trace, warn};

/// Custom span creation with common attributes
#[macro_export]
macro_rules! span_with_context {
    ($level:expr, $name:expr, $($key:expr => $value:expr),*) => {
        tracing::span!(
            $level,
            $name,
            $($key = $value,)*
            otel.kind = "internal",
            service.name = "rustchain"
        )
    };
}

/// Mission execution instrumentation
#[macro_export]
macro_rules! instrument_mission {
    ($mission_id:expr, $mission_name:expr) => {
        $crate::span_with_context!(
            tracing::Level::INFO,
            "mission_execution",
            mission.id = $mission_id,
            mission.name = $mission_name,
            mission.type = "execution"
        )
    };
}

/// Tool execution instrumentation
#[macro_export]
macro_rules! instrument_tool {
    ($tool_name:expr, $tool_action:expr) => {
        $crate::span_with_context!(
            tracing::Level::DEBUG,
            "tool_execution",
            tool.name = $tool_name,
            tool.action = $tool_action,
            component = "tools"
        )
    };
}

/// LLM request instrumentation
#[macro_export]
macro_rules! instrument_llm {
    ($provider:expr, $model:expr) => {
        $crate::span_with_context!(
            tracing::Level::DEBUG,
            "llm_request",
            llm.provider = $provider,
            llm.model = $model,
            component = "llm"
        )
    };
}

/// Database operation instrumentation
#[macro_export]
macro_rules! instrument_db {
    ($operation:expr, $table:expr) => {
        $crate::span_with_context!(
            tracing::Level::DEBUG,
            "database_operation",
            db.operation = $operation,
            db.table = $table,
            component = "database"
        )
    };
}

/// HTTP request instrumentation (automatic with tracing layer)
pub fn instrument_http_request(method: &str, uri: &str, status_code: u16, duration_ms: u64) {
    tracing::info!(
        method = method,
        uri = uri,
        status_code = status_code,
        duration_ms = duration_ms,
        component = "http",
        "HTTP request completed"
    );
}

/// Simple metrics for business logic (without OpenTelemetry dependency)
pub struct RustChainMetrics {
    mission_count: std::sync::atomic::AtomicU64,
    tool_count: std::sync::atomic::AtomicU64,
    llm_count: std::sync::atomic::AtomicU64,
    error_count: std::sync::atomic::AtomicU64,
}

impl RustChainMetrics {
    pub fn new() -> Self {
        Self {
            mission_count: std::sync::atomic::AtomicU64::new(0),
            tool_count: std::sync::atomic::AtomicU64::new(0),
            llm_count: std::sync::atomic::AtomicU64::new(0),
            error_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_mission(&self, status: &str, duration_seconds: f64) {
        self.mission_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            status = status,
            duration_seconds = duration_seconds,
            "Mission completed"
        );
    }

    pub fn record_tool_execution(&self, tool_name: &str, success: bool) {
        self.tool_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(tool = tool_name, success = success, "Tool executed");
    }

    pub fn record_llm_request(&self, provider: &str, model: &str, success: bool) {
        self.llm_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            provider = provider,
            model = model,
            success = success,
            "LLM request completed"
        );
    }

    pub fn record_error(&self, error_type: &str, component: &str) {
        self.error_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::error!(
            error_type = error_type,
            component = component,
            "Error recorded"
        );
    }

    pub fn get_mission_count(&self) -> u64 {
        self.mission_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_tool_count(&self) -> u64 {
        self.tool_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_llm_count(&self) -> u64 {
        self.llm_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_error_count(&self) -> u64 {
        self.error_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for RustChainMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.service_name, "rustchain");
        assert!(config.enabled);
    }

    #[test]
    fn test_telemetry_manager_creation() {
        let config = TelemetryConfig::default();
        let manager = TelemetryManager::new(config);
        assert!(manager.config.enabled);
    }

    #[tokio::test]
    async fn test_metrics_creation() {
        let metrics = RustChainMetrics::new();

        // Test recording metrics
        metrics.record_mission("success", 1.5);
        metrics.record_tool_execution("test_tool", true);
        metrics.record_llm_request("openai", "gpt-4", true);
        metrics.record_error("validation", "core");

        // Check counters
        assert_eq!(metrics.get_mission_count(), 1);
        assert_eq!(metrics.get_tool_count(), 1);
        assert_eq!(metrics.get_llm_count(), 1);
        assert_eq!(metrics.get_error_count(), 1);
    }
}
