use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod access_control;
pub mod audit;
pub mod auth;
pub mod encryption;
pub mod threat_detection;

pub use access_control::*;
pub use audit::*;
pub use auth::*;
pub use encryption::*;
pub use threat_detection::*;

/// Core security context for all security operations
#[derive(Clone, Debug)]
pub struct SecurityContext {
    pub session_id: Uuid,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub permissions: Vec<String>,
    pub security_level: SecurityLevel,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

/// Security event types for auditing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SecurityEvent {
    Authentication {
        user_id: String,
        method: String,
        success: bool,
        ip_address: Option<String>,
    },
    Authorization {
        user_id: String,
        resource: String,
        action: String,
        granted: bool,
    },
    DataAccess {
        user_id: String,
        resource: String,
        operation: String,
        classification: SecurityLevel,
    },
    ThreatDetected {
        threat_type: String,
        severity: ThreatSeverity,
        source: String,
        details: HashMap<String, String>,
    },
    PolicyViolation {
        user_id: String,
        policy: String,
        violation_type: String,
        severity: ViolationSeverity,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Minor,
    Major,
    Critical,
}

/// Security configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: Option<String>,
    pub session_timeout_minutes: u32,
    pub max_login_attempts: u32,
    pub encryption_algorithm: String,
    pub compliance_frameworks: Vec<String>,
    pub threat_detection_enabled: bool,
    pub audit_retention_days: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: None,
            session_timeout_minutes: 60,
            max_login_attempts: 3,
            encryption_algorithm: "AES-256-GCM".to_string(),
            compliance_frameworks: vec!["GDPR".to_string(), "HIPAA".to_string()],
            threat_detection_enabled: true,
            audit_retention_days: 2555, // 7 years
        }
    }
}

/// Session tracking for active security contexts
#[derive(Clone, Debug)]
pub struct SessionTracker {
    active_sessions: Arc<RwLock<HashMap<Uuid, SecurityContext>>>,
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a new session to tracking
    pub async fn add_session(&self, context: SecurityContext) {
        let session_id = context.session_id;
        self.active_sessions
            .write()
            .await
            .insert(session_id, context);
    }

    /// Remove a session from tracking
    pub async fn remove_session(&self, session_id: &Uuid) -> bool {
        self.active_sessions
            .write()
            .await
            .remove(session_id)
            .is_some()
    }

    /// Get session if it exists and hasn't expired
    pub async fn get_session(&self, session_id: &Uuid) -> Option<SecurityContext> {
        let sessions = self.active_sessions.read().await;
        if let Some(context) = sessions.get(session_id) {
            // Check if session has expired
            if let Some(expires_at) = context.expires_at {
                if Utc::now() > expires_at {
                    return None; // Session expired
                }
            }
            Some(context.clone())
        } else {
            None
        }
    }

    /// Count active sessions (non-expired)
    pub async fn count_active_sessions(&self) -> u64 {
        let now = Utc::now();
        let sessions = self.active_sessions.read().await;
        sessions
            .values()
            .filter(|context| {
                if let Some(expires_at) = context.expires_at {
                    now <= expires_at
                } else {
                    true // No expiration means it's active
                }
            })
            .count() as u64
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> u64 {
        let now = Utc::now();
        let mut sessions = self.active_sessions.write().await;
        let initial_count = sessions.len();

        sessions.retain(|_, context| {
            if let Some(expires_at) = context.expires_at {
                now <= expires_at
            } else {
                true // No expiration means keep it
            }
        });

        (initial_count - sessions.len()) as u64
    }

    /// Get all active session IDs
    pub async fn get_active_session_ids(&self) -> Vec<Uuid> {
        let now = Utc::now();
        let sessions = self.active_sessions.read().await;
        sessions
            .iter()
            .filter(|(_, context)| {
                if let Some(expires_at) = context.expires_at {
                    now <= expires_at
                } else {
                    true
                }
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Main security manager
#[derive(Clone)]
pub struct SecurityManager {
    config: Arc<SecurityConfig>,
    auth_service: Arc<dyn AuthenticationService>,
    authz_service: Arc<dyn AuthorizationService>,
    encryption_service: Arc<dyn EncryptionService>,
    audit_service: Arc<dyn AuditService>,
    threat_detector: Arc<dyn ThreatDetectionService>,
    session_tracker: SessionTracker,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> crate::core::error::Result<Self> {
        let config = Arc::new(config);

        let auth_service: Arc<dyn AuthenticationService> =
            Arc::new(JwtAuthenticationService::new(config.clone())?);
        let authz_service: Arc<dyn AuthorizationService> =
            Arc::new(RbacAuthorizationService::new());
        let encryption_service: Arc<dyn EncryptionService> = Arc::new(AesEncryptionService::new()?);
        let audit_service: Arc<dyn AuditService> = Arc::new(DatabaseAuditService::new()?);
        let threat_detector: Arc<dyn ThreatDetectionService> =
            Arc::new(RuleBasedThreatDetector::new());

        Ok(Self {
            config,
            auth_service,
            authz_service,
            encryption_service,
            audit_service,
            threat_detector,
            session_tracker: SessionTracker::new(),
        })
    }

    /// Authenticate a user and create security context
    pub async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> crate::core::error::Result<SecurityContext> {
        // Log authentication attempt
        self.audit_service
            .log_event(SecurityEvent::Authentication {
                user_id: credentials.user_id().to_string(),
                method: credentials.auth_method().to_string(),
                success: false, // Will be updated if successful
                ip_address: credentials.ip_address(),
            })
            .await?;

        // Check for threats
        if let Some(threat) = self
            .threat_detector
            .detect_authentication_threat(credentials)
            .await?
        {
            self.audit_service
                .log_event(SecurityEvent::ThreatDetected {
                    threat_type: "Authentication".to_string(),
                    severity: threat.severity,
                    source: credentials.user_id().to_string(),
                    details: threat.details,
                })
                .await?;

            return Err(crate::core::error::RustChainError::Security(
                "Authentication threat detected".to_string(),
            ));
        }

        // Perform authentication
        let auth_result = self.auth_service.authenticate(credentials).await?;

        // Create security context
        let context = SecurityContext {
            session_id: Uuid::new_v4(),
            user_id: Some(auth_result.user_id.clone()),
            tenant_id: auth_result.tenant_id,
            permissions: auth_result.permissions,
            security_level: SecurityLevel::Internal,
            created_at: Utc::now(),
            expires_at: Some(
                Utc::now() + chrono::Duration::minutes(self.config.session_timeout_minutes as i64),
            ),
        };

        // Log successful authentication
        self.audit_service
            .log_event(SecurityEvent::Authentication {
                user_id: auth_result.user_id,
                method: credentials.auth_method().to_string(),
                success: true,
                ip_address: credentials.ip_address(),
            })
            .await?;

        // Add session to tracking
        self.session_tracker.add_session(context.clone()).await;

        Ok(context)
    }

    /// Authorize an action for a security context
    pub async fn authorize(
        &self,
        context: &SecurityContext,
        resource: &str,
        action: &str,
    ) -> crate::core::error::Result<bool> {
        let authorized = self
            .authz_service
            .authorize(context, resource, action)
            .await?;

        // Log authorization attempt
        self.audit_service
            .log_event(SecurityEvent::Authorization {
                user_id: context
                    .user_id
                    .as_deref()
                    .unwrap_or("anonymous")
                    .to_string(),
                resource: resource.to_string(),
                action: action.to_string(),
                granted: authorized,
            })
            .await?;

        Ok(authorized)
    }

    /// Encrypt data with security context
    pub async fn encrypt(
        &self,
        context: &SecurityContext,
        data: &[u8],
    ) -> crate::core::error::Result<Vec<u8>> {
        let encrypted = self.encryption_service.encrypt(data, context).await?;

        // Log data access
        self.audit_service
            .log_event(SecurityEvent::DataAccess {
                user_id: context.user_id.as_deref().unwrap_or("system").to_string(),
                resource: "encrypted_data".to_string(),
                operation: "encrypt".to_string(),
                classification: context.security_level.clone(),
            })
            .await?;

        Ok(encrypted)
    }

    /// Decrypt data with security context
    pub async fn decrypt(
        &self,
        context: &SecurityContext,
        data: &[u8],
    ) -> crate::core::error::Result<Vec<u8>> {
        let decrypted = self.encryption_service.decrypt(data, context).await?;

        // Log data access
        self.audit_service
            .log_event(SecurityEvent::DataAccess {
                user_id: context.user_id.as_deref().unwrap_or("system").to_string(),
                resource: "encrypted_data".to_string(),
                operation: "decrypt".to_string(),
                classification: context.security_level.clone(),
            })
            .await?;

        Ok(decrypted)
    }

    /// Get security metrics
    pub async fn get_security_metrics(&self) -> crate::core::error::Result<SecurityMetrics> {
        let auth_events = self
            .audit_service
            .count_events_by_type("authentication", chrono::Duration::hours(24))
            .await?;
        let threat_events = self
            .audit_service
            .count_events_by_type("threat", chrono::Duration::hours(24))
            .await?;
        let violations = self
            .audit_service
            .count_events_by_type("violation", chrono::Duration::hours(24))
            .await?;

        // Clean up expired sessions before counting
        self.session_tracker.cleanup_expired_sessions().await;
        let active_sessions = self.session_tracker.count_active_sessions().await;

        Ok(SecurityMetrics {
            authentication_events_24h: auth_events,
            threats_detected_24h: threat_events,
            policy_violations_24h: violations,
            active_sessions,
        })
    }

    /// Logout a user session
    pub async fn logout(&self, session_id: &Uuid) -> crate::core::error::Result<bool> {
        // Get user_id from session before removing it
        let user_id = self
            .session_tracker
            .get_session(session_id)
            .await
            .and_then(|ctx| ctx.user_id)
            .unwrap_or_else(|| "unknown".to_string());

        let removed = self.session_tracker.remove_session(session_id).await;

        if removed {
            // Log logout event with actual user_id
            self.audit_service
                .log_event(SecurityEvent::Authentication {
                    user_id,
                    method: "logout".to_string(),
                    success: true,
                    ip_address: None,
                })
                .await?;
        }

        Ok(removed)
    }

    /// Get session information
    pub async fn get_session(&self, session_id: &Uuid) -> Option<SecurityContext> {
        self.session_tracker.get_session(session_id).await
    }

    /// Get all active session IDs (for administrative purposes)
    pub async fn get_active_session_ids(&self) -> Vec<Uuid> {
        self.session_tracker.get_active_session_ids().await
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SecurityMetrics {
    pub authentication_events_24h: u64,
    pub threats_detected_24h: u64,
    pub policy_violations_24h: u64,
    pub active_sessions: u64,
}

/// Security error types
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),

    #[error("Security threat detected: {0}")]
    ThreatDetected(String),

    #[error("Audit failed: {0}")]
    AuditFailed(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl From<SecurityError> for crate::core::error::RustChainError {
    fn from(err: SecurityError) -> Self {
        crate::core::error::RustChainError::Security(err.to_string())
    }
}
