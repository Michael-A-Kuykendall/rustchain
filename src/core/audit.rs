use anyhow::{anyhow, Result};
#[cfg(feature = "enterprise")]
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

// Re-export for use in trait bounds
#[cfg(feature = "enterprise")]
use crate::security::EncryptionService;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: HashMap<String, serde_json::Value>,
    pub risk_level: RiskLevel,
    pub chain_hash: String,
    pub previous_hash: Option<String>,
    pub metadata: AuditMetadata,
}

impl AuditEntry {
    /// Validate that this entry doesn't contain test/mock data in production
    pub fn validate_production_data(&self) -> Result<(), String> {
        // Only validate in non-test builds
        if cfg!(not(test)) {
            let suspicious_patterns = [
                "test_",
                "mock_",
                "fake_",
                "dummy_",
                "sample_",
                "example_",
                "demo_",
                "placeholder_",
                "temp_test",
            ];

            for pattern in &suspicious_patterns {
                if self.actor.contains(pattern)
                    || self.resource.contains(pattern)
                    || self.action.contains(pattern)
                {
                    return Err(format!(
                        "Suspicious test pattern '{}' found in production audit entry: actor={}, resource={}, action={}",
                        pattern, self.actor, self.resource, self.action
                    ));
                }
            }

            // Check for sequentially numbered test data (agent1, agent2, etc.)
            if self.actor.starts_with("agent") && self.actor.len() <= 7 {
                if let Some(suffix) = self.actor.strip_prefix("agent") {
                    if suffix.parse::<u32>().is_ok() {
                        return Err(format!(
                            "Sequential test actor name '{}' detected in production",
                            self.actor
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Calculate the chain hash for this entry
    pub fn calculate_chain_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.id);
        hasher.update(self.timestamp.to_rfc3339());
        hasher.update(self.actor.as_bytes());
        hasher.update(self.resource.as_bytes());
        hasher.update(self.action.as_bytes());
        if let Some(prev_hash) = &self.previous_hash {
            hasher.update(prev_hash.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    SystemAccess,
    PolicyViolation,
    SecurityEvent,
    MissionExecution,
    ToolExecution,
    FileOperation,
    NetworkAccess,
    ConfigChange,
    UserAction,
    SystemError,
    Performance,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    Success,
    Failure,
    Warning,
    Blocked,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditMetadata {
    pub session_id: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub correlation_id: Option<String>,
    pub trace_id: Option<String>,
    pub mission_id: Option<String>,
    pub tool_name: Option<String>,
    pub execution_time_ms: Option<u64>,
    pub memory_usage_mb: Option<u64>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub event_types: Option<Vec<AuditEventType>>,
    pub outcomes: Option<Vec<AuditOutcome>>,
    pub risk_levels: Option<Vec<RiskLevel>>,
    pub actors: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub actions: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub mission_id: Option<String>,
    pub correlation_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub id: String,
    pub generated_at: DateTime<Utc>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_events: usize,
    pub events_by_type: HashMap<String, usize>,
    pub events_by_outcome: HashMap<String, usize>,
    pub events_by_risk_level: HashMap<String, usize>,
    pub top_actors: Vec<(String, usize)>,
    pub top_resources: Vec<(String, usize)>,
    pub security_highlights: Vec<SecurityHighlight>,
    pub performance_metrics: PerformanceMetrics,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHighlight {
    pub severity: RiskLevel,
    pub event_type: AuditEventType,
    pub description: String,
    pub count: usize,
    pub first_occurrence: DateTime<Utc>,
    pub last_occurrence: DateTime<Utc>,
    pub affected_resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub avg_execution_time_ms: f64,
    pub max_execution_time_ms: u64,
    pub total_operations: usize,
    pub avg_memory_usage_mb: f64,
    pub peak_memory_usage_mb: u64,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub compliance_score: f64,
    pub violations: Vec<ComplianceViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub rule: String,
    pub description: String,
    pub severity: RiskLevel,
    pub count: usize,
    pub last_occurrence: DateTime<Utc>,
}

/// Enhanced audit sink with blockchain-like integrity
pub struct EnhancedAuditSink {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    storage_path: Option<PathBuf>,
    chain_integrity: bool,
    last_hash: Arc<RwLock<Option<String>>>,
    encryption_enabled: bool,
    retention_days: u32,
    entries_loaded: Arc<AtomicBool>,
    #[cfg(feature = "enterprise")]
    encryption_service: Option<Arc<dyn EncryptionService>>,
}

impl EnhancedAuditSink {
    pub fn new(storage_path: Option<PathBuf>) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            storage_path,
            chain_integrity: true,
            last_hash: Arc::new(RwLock::new(None)),
            encryption_enabled: false,
            retention_days: 365,
            entries_loaded: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "enterprise")]
            encryption_service: None,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn with_encryption_service(mut self, service: Arc<dyn EncryptionService>) -> Self {
        self.encryption_service = Some(service);
        self.encryption_enabled = true;
        self
    }

    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.encryption_enabled = enabled;
        self
    }

    pub fn with_retention_days(mut self, days: u32) -> Self {
        self.retention_days = days;
        self
    }

    /// Load existing audit entries from storage file
    pub async fn load_entries(&self) -> Result<()> {
        if let Some(ref storage_path) = self.storage_path {
            if storage_path.exists() {
                let content = fs::read_to_string(storage_path).await?;
                let mut entries = self.entries.write().await;

                for line in content.lines() {
                    if !line.trim().is_empty() {
                        let entry_json = if self.encryption_enabled {
                            #[cfg(feature = "enterprise")]
                            if let Some(service) = &self.encryption_service {
                                // Decrypt the entry if encryption service is available
                                let encrypted_data = general_purpose::STANDARD.decode(line)?;
                                let context = crate::security::SecurityContext {
                                    session_id: uuid::Uuid::new_v4(),
                                    user_id: Some("system".to_string()),
                                    tenant_id: None,
                                    permissions: vec!["audit:read".to_string()],
                                    security_level: crate::security::SecurityLevel::Confidential,
                                    created_at: chrono::Utc::now(),
                                    expires_at: None,
                                };
                                String::from_utf8(
                                    service.decrypt(&encrypted_data, &context).await?,
                                )?
                            } else {
                                line.to_string()
                            }
                            #[cfg(not(feature = "enterprise"))]
                            line.to_string()
                        } else {
                            line.to_string()
                        };

                        let entry: AuditEntry = serde_json::from_str(&entry_json)?;
                        entries.push(entry);
                    }
                }

                info!(
                    "Loaded {} existing audit entries from {}",
                    entries.len(),
                    storage_path.display()
                );
            }
        }
        Ok(())
    }

    /// Log an audit entry
    pub async fn log(&self, mut entry: AuditEntry) -> Result<()> {
        // Load existing entries on first log operation if storage path is set
        if self.storage_path.is_some()
            && !self
                .entries_loaded
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            self.load_entries().await?;
            self.entries_loaded
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // Validate production data integrity
        if let Err(validation_error) = entry.validate_production_data() {
            warn!("Production data validation failed: {}", validation_error);
            // In production, we could choose to reject the entry or sanitize it
            // Log warning and continue processing
        }

        // Calculate chain hash for integrity
        if self.chain_integrity {
            let previous_hash = self.last_hash.read().await.clone();
            entry.previous_hash = previous_hash.clone();
            entry.chain_hash = self.calculate_chain_hash(&entry)?;

            // Update last hash
            *self.last_hash.write().await = Some(entry.chain_hash.clone());
        }

        // Add to in-memory storage
        self.entries.write().await.push(entry.clone());

        // Persist to disk if storage path is configured
        if let Some(ref storage_path) = self.storage_path {
            self.persist_entry(&entry, storage_path).await?;
        }

        debug!("Audit entry logged: {} - {}", entry.id, entry.action);

        // Clean up old entries if needed
        self.cleanup_old_entries().await?;

        Ok(())
    }

    /// Query audit entries
    pub async fn query(&self, query: AuditQuery) -> Result<Vec<AuditEntry>> {
        let entries = self.entries.read().await;
        let mut results = Vec::new();

        for entry in entries.iter() {
            if self.matches_query(entry, &query) {
                results.push(entry.clone());
            }
        }

        // Sort by timestamp (newest first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply pagination
        let start = query.offset.unwrap_or(0);
        let end = if let Some(limit) = query.limit {
            std::cmp::min(start + limit, results.len())
        } else {
            results.len()
        };

        if start >= results.len() {
            return Ok(Vec::new());
        }

        Ok(results[start..end].to_vec())
    }

    /// Generate audit report
    pub async fn generate_report(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<AuditReport> {
        let query = AuditQuery {
            start_time: Some(start_time),
            end_time: Some(end_time),
            ..Default::default()
        };

        let entries = self.query(query).await?;

        let mut events_by_type = HashMap::new();
        let mut events_by_outcome = HashMap::new();
        let mut events_by_risk_level = HashMap::new();
        let mut actor_counts = HashMap::new();
        let mut resource_counts = HashMap::new();
        let mut security_events = Vec::new();

        let mut total_execution_time = 0u64;
        let mut max_execution_time = 0u64;
        let mut total_memory_usage = 0u64;
        let mut peak_memory_usage = 0u64;
        let mut operation_count = 0usize;
        let mut error_count = 0usize;

        for entry in &entries {
            // Count by type
            let type_key = format!("{:?}", entry.event_type);
            *events_by_type.entry(type_key).or_insert(0) += 1;

            // Count by outcome
            let outcome_key = format!("{:?}", entry.outcome);
            *events_by_outcome.entry(outcome_key).or_insert(0) += 1;

            // Count by risk level
            let risk_key = format!("{:?}", entry.risk_level);
            *events_by_risk_level.entry(risk_key).or_insert(0) += 1;

            // Count actors and resources
            *actor_counts.entry(entry.actor.clone()).or_insert(0) += 1;
            *resource_counts.entry(entry.resource.clone()).or_insert(0) += 1;

            // Collect security events
            if matches!(entry.risk_level, RiskLevel::High | RiskLevel::Critical) {
                security_events.push(entry.clone());
            }

            // Performance metrics
            if let Some(exec_time) = entry.metadata.execution_time_ms {
                total_execution_time += exec_time;
                max_execution_time = max_execution_time.max(exec_time);
                operation_count += 1;
            }

            if let Some(memory) = entry.metadata.memory_usage_mb {
                total_memory_usage += memory;
                peak_memory_usage = peak_memory_usage.max(memory);
            }

            if matches!(entry.outcome, AuditOutcome::Failure) {
                error_count += 1;
            }
        }

        // Generate top actors and resources
        let mut top_actors: Vec<_> = actor_counts.into_iter().collect();
        top_actors.sort_by(|a, b| b.1.cmp(&a.1));
        top_actors.truncate(10);

        let mut top_resources: Vec<_> = resource_counts.into_iter().collect();
        top_resources.sort_by(|a, b| b.1.cmp(&a.1));
        top_resources.truncate(10);

        // Generate security highlights
        let security_highlights = self.generate_security_highlights(&security_events)?;

        // Performance metrics
        let performance_metrics = PerformanceMetrics {
            avg_execution_time_ms: if operation_count > 0 {
                total_execution_time as f64 / operation_count as f64
            } else {
                0.0
            },
            max_execution_time_ms: max_execution_time,
            total_operations: operation_count,
            avg_memory_usage_mb: if !entries.is_empty() {
                total_memory_usage as f64 / entries.len() as f64
            } else {
                0.0
            },
            peak_memory_usage_mb: peak_memory_usage,
            error_rate: if !entries.is_empty() {
                error_count as f64 / entries.len() as f64
            } else {
                0.0
            },
        };

        // Generate compliance violations based on audit entries
        let violations = self.check_compliance_violations(&entries)?;

        // Compliance status with real violation checking
        let compliance_status = ComplianceStatus {
            total_checks: entries.len(),
            passed_checks: entries.len() - error_count,
            failed_checks: error_count,
            compliance_score: if !entries.is_empty() {
                let base_score =
                    (entries.len() - error_count) as f64 / entries.len() as f64 * 100.0;
                // Reduce score based on severity of violations
                let violation_penalty = violations
                    .iter()
                    .map(|v| match v.severity {
                        RiskLevel::Critical => 5.0,
                        RiskLevel::High => 3.0,
                        RiskLevel::Medium => 1.5,
                        RiskLevel::Low => 0.5,
                    })
                    .sum::<f64>();
                (base_score - violation_penalty).max(0.0)
            } else {
                100.0
            },
            violations,
        };

        Ok(AuditReport {
            id: Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            period_start: start_time,
            period_end: end_time,
            total_events: entries.len(),
            events_by_type,
            events_by_outcome,
            events_by_risk_level,
            top_actors,
            top_resources,
            security_highlights,
            performance_metrics,
            compliance_status,
        })
    }

    /// Verify audit chain integrity
    pub async fn verify_integrity(&self) -> Result<bool> {
        let entries = self.entries.read().await;
        let mut previous_hash: Option<String> = None;

        for entry in entries.iter() {
            // Check if previous hash matches
            if entry.previous_hash != previous_hash {
                warn!(
                    "Audit chain integrity violation: entry {} has incorrect previous hash",
                    entry.id
                );
                return Ok(false);
            }

            // Verify chain hash
            let calculated_hash = self.calculate_chain_hash(entry)?;
            if calculated_hash != entry.chain_hash {
                warn!(
                    "Audit chain integrity violation: entry {} has incorrect chain hash",
                    entry.id
                );
                return Ok(false);
            }

            previous_hash = Some(entry.chain_hash.clone());
        }

        info!("Audit chain integrity verified: {} entries", entries.len());
        Ok(true)
    }

    /// Export audit data
    pub async fn export(&self, format: &str, query: Option<AuditQuery>) -> Result<String> {
        let entries = if let Some(q) = query {
            self.query(q).await?
        } else {
            self.entries.read().await.clone()
        };

        match format.to_lowercase().as_str() {
            "json" => Ok(serde_json::to_string_pretty(&entries)?),
            "yaml" => Ok(serde_yaml::to_string(&entries)?),
            "csv" => self.export_csv(&entries),
            _ => Err(anyhow!("Unsupported export format: {}", format)),
        }
    }

    // Helper methods

    fn calculate_chain_hash(&self, entry: &AuditEntry) -> Result<String> {
        let mut hasher = Sha256::new();

        // Hash entry data (excluding the chain_hash field itself)
        hasher.update(entry.id.as_bytes());
        hasher.update(entry.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", entry.event_type).as_bytes());
        hasher.update(entry.actor.as_bytes());
        hasher.update(entry.resource.as_bytes());
        hasher.update(entry.action.as_bytes());
        hasher.update(format!("{:?}", entry.outcome).as_bytes());
        hasher.update(format!("{:?}", entry.risk_level).as_bytes());

        if let Some(ref prev_hash) = entry.previous_hash {
            hasher.update(prev_hash.as_bytes());
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    fn matches_query(&self, entry: &AuditEntry, query: &AuditQuery) -> bool {
        // Time range check
        if let Some(start) = query.start_time {
            if entry.timestamp < start {
                return false;
            }
        }

        if let Some(end) = query.end_time {
            if entry.timestamp >= end {
                return false;
            }
        }

        // Event type check
        if let Some(ref types) = query.event_types {
            if !types.contains(&entry.event_type) {
                return false;
            }
        }

        // Outcome check
        if let Some(ref outcomes) = query.outcomes {
            if !outcomes.contains(&entry.outcome) {
                return false;
            }
        }

        // Risk level check
        if let Some(ref levels) = query.risk_levels {
            if !levels.contains(&entry.risk_level) {
                return false;
            }
        }

        // Actor check
        if let Some(ref actors) = query.actors {
            if !actors.contains(&entry.actor) {
                return false;
            }
        }

        // Resource check
        if let Some(ref resources) = query.resources {
            if !resources.contains(&entry.resource) {
                return false;
            }
        }

        // Action check
        if let Some(ref actions) = query.actions {
            if !actions.contains(&entry.action) {
                return false;
            }
        }

        // Tag check
        if let Some(ref tags) = query.tags {
            for tag in tags {
                if !entry.metadata.tags.contains(tag) {
                    return false;
                }
            }
        }

        // Mission ID check
        if let Some(ref mission_id) = query.mission_id {
            if entry.metadata.mission_id.as_ref() != Some(mission_id) {
                return false;
            }
        }

        // Correlation ID check
        if let Some(ref correlation_id) = query.correlation_id {
            if entry.metadata.correlation_id.as_ref() != Some(correlation_id) {
                return false;
            }
        }

        true
    }

    async fn persist_entry(&self, entry: &AuditEntry, storage_path: &PathBuf) -> Result<()> {
        // Create storage directory if it doesn't exist
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Serialize entry
        let entry_json = serde_json::to_string(entry)?;
        let log_line = if self.encryption_enabled {
            #[cfg(feature = "enterprise")]
            if let Some(service) = &self.encryption_service {
                // Encrypt the entry if encryption service is available
                let context = crate::security::SecurityContext {
                    session_id: uuid::Uuid::new_v4(),
                    user_id: Some("system".to_string()),
                    tenant_id: None,
                    permissions: vec!["audit:write".to_string()],
                    security_level: crate::security::SecurityLevel::Confidential,
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                };
                let encrypted = service.encrypt(entry_json.as_bytes(), &context).await?;
                format!("{}\n", general_purpose::STANDARD.encode(encrypted))
            } else {
                format!("{}\n", entry_json)
            }
            #[cfg(not(feature = "enterprise"))]
            format!("{}\n", entry_json)
        } else {
            format!("{}\n", entry_json)
        };

        // Use OpenOptions to append instead of overwrite
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(storage_path)
            .await?;
        file.write_all(log_line.as_bytes()).await?;
        file.flush().await?;

        Ok(())
    }

    async fn cleanup_old_entries(&self) -> Result<()> {
        let cutoff_date = Utc::now() - chrono::Duration::days(self.retention_days as i64);

        let mut entries = self.entries.write().await;
        let original_count = entries.len();

        entries.retain(|entry| entry.timestamp > cutoff_date);

        let removed_count = original_count - entries.len();
        if removed_count > 0 {
            info!("Cleaned up {} old audit entries", removed_count);
        }

        Ok(())
    }

    fn generate_security_highlights(
        &self,
        security_events: &[AuditEntry],
    ) -> Result<Vec<SecurityHighlight>> {
        let mut highlights = HashMap::new();

        for event in security_events {
            let key = (event.event_type.clone(), event.action.clone());
            let highlight = highlights.entry(key).or_insert_with(|| SecurityHighlight {
                severity: event.risk_level.clone(),
                event_type: event.event_type.clone(),
                description: format!("{:?} - {}", event.event_type, event.action),
                count: 0,
                first_occurrence: event.timestamp,
                last_occurrence: event.timestamp,
                affected_resources: Vec::new(),
            });

            highlight.count += 1;
            highlight.first_occurrence = highlight.first_occurrence.min(event.timestamp);
            highlight.last_occurrence = highlight.last_occurrence.max(event.timestamp);

            if !highlight.affected_resources.contains(&event.resource) {
                highlight.affected_resources.push(event.resource.clone());
            }
        }

        let mut result: Vec<_> = highlights.into_values().collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));

        Ok(result)
    }

    fn export_csv(&self, entries: &[AuditEntry]) -> Result<String> {
        let mut csv = String::new();

        // Header
        csv.push_str(
            "id,timestamp,event_type,actor,resource,action,outcome,risk_level,chain_hash\n",
        );

        // Data rows
        for entry in entries {
            csv.push_str(&format!(
                "{},{},{:?},{},{},{},{:?},{:?},{}\n",
                entry.id,
                entry.timestamp.to_rfc3339(),
                entry.event_type,
                entry.actor,
                entry.resource,
                entry.action,
                entry.outcome,
                entry.risk_level,
                entry.chain_hash
            ));
        }

        Ok(csv)
    }

    /// Check for compliance violations in audit entries
    fn check_compliance_violations(
        &self,
        entries: &[AuditEntry],
    ) -> Result<Vec<ComplianceViolation>> {
        let mut violations = HashMap::new();

        for entry in entries {
            // Rule 1: Check for excessive failed attempts (security compliance)
            if matches!(entry.outcome, AuditOutcome::Failure) {
                if let Some(attempts_value) = entry.details.get("failed_attempts") {
                    if let Some(attempts) = attempts_value.as_u64() {
                        if attempts > 3 {
                            self.record_violation(
                                &mut violations,
                                "excessive_failed_attempts",
                                "Excessive failed authentication attempts detected",
                                RiskLevel::High,
                                entry.timestamp,
                            );
                        }
                    }
                }
            }

            // Rule 2: Check for privileged operations without proper authorization (audit compliance)
            if (entry.action.contains("delete")
                || entry.action.contains("admin")
                || entry.action.contains("root"))
                && !entry.details.contains_key("authorization_token")
                && !entry.details.contains_key("admin_approval")
            {
                self.record_violation(
                    &mut violations,
                    "unauthorized_privileged_operation",
                    "Privileged operation performed without proper authorization",
                    RiskLevel::Critical,
                    entry.timestamp,
                );
            }

            // Rule 3: Check for data access outside business hours (data protection compliance)
            if matches!(entry.event_type, AuditEventType::DataAccess) {
                let hour = entry.timestamp.hour();
                if !(6..=22).contains(&hour) {
                    // Outside 6 AM - 10 PM
                    self.record_violation(
                        &mut violations,
                        "off_hours_data_access",
                        "Data access attempted outside approved business hours",
                        RiskLevel::Medium,
                        entry.timestamp,
                    );
                }
            }

            // Rule 4: Check for high-risk operations without supervisor approval (operational compliance)
            if matches!(entry.risk_level, RiskLevel::Critical | RiskLevel::High)
                && !entry.details.contains_key("supervisor_approval")
                && !entry.details.contains_key("emergency_override")
            {
                self.record_violation(
                    &mut violations,
                    "high_risk_without_approval",
                    "High-risk operation performed without supervisor approval",
                    RiskLevel::High,
                    entry.timestamp,
                );
            }

            // Rule 5: Check for suspicious geographic access patterns (fraud compliance)
            if let Some(ip_geo_value) = entry.details.get("geo_location") {
                if let Some(ip_geo) = ip_geo_value.as_str() {
                    if ip_geo.contains("suspicious")
                        || ip_geo.contains("tor")
                        || ip_geo.contains("proxy")
                    {
                        self.record_violation(
                            &mut violations,
                            "suspicious_geographic_access",
                            "Access from suspicious geographic location or anonymization service",
                            RiskLevel::High,
                            entry.timestamp,
                        );
                    }
                }
            }

            // Rule 6: Check for rapid consecutive operations (automated attack compliance)
            if let Some(prev_timestamp_value) = entry.details.get("previous_action_timestamp") {
                if let Some(prev_timestamp_str) = prev_timestamp_value.as_str() {
                    if let Ok(prev_time) = DateTime::parse_from_rfc3339(prev_timestamp_str) {
                        let time_diff = entry
                            .timestamp
                            .signed_duration_since(prev_time.with_timezone(&Utc));
                        if time_diff.num_seconds() < 1 {
                            // Less than 1 second between operations
                            self.record_violation(
                                &mut violations,
                                "rapid_consecutive_operations",
                                "Rapid consecutive operations detected (possible automated attack)",
                                RiskLevel::Medium,
                                entry.timestamp,
                            );
                        }
                    }
                }
            }

            // Rule 7: Check for missing audit trail elements (audit integrity compliance)
            if entry.chain_hash.is_empty() || entry.previous_hash.is_none() {
                self.record_violation(
                    &mut violations,
                    "incomplete_audit_trail",
                    "Audit entry missing required integrity elements",
                    RiskLevel::Critical,
                    entry.timestamp,
                );
            }

            // Rule 8: Check for policy violations (regulatory compliance)
            if matches!(entry.outcome, AuditOutcome::Blocked)
                && entry.details.contains_key("policy_violation")
            {
                self.record_violation(
                    &mut violations,
                    "policy_violation",
                    "Operation blocked due to policy violation",
                    RiskLevel::High,
                    entry.timestamp,
                );
            }

            // Rule 9: Check for session-related compliance issues
            if entry.metadata.session_id.is_none()
                && matches!(
                    entry.event_type,
                    AuditEventType::Authentication | AuditEventType::Authorization
                )
            {
                self.record_violation(
                    &mut violations,
                    "missing_session_tracking",
                    "Security-sensitive operation performed without session tracking",
                    RiskLevel::Medium,
                    entry.timestamp,
                );
            }

            // Rule 10: Check for tool execution without proper context
            if matches!(entry.event_type, AuditEventType::ToolExecution)
                && entry.metadata.tool_name.is_none()
            {
                self.record_violation(
                    &mut violations,
                    "untracked_tool_execution",
                    "Tool execution without proper identification",
                    RiskLevel::Low,
                    entry.timestamp,
                );
            }
        }

        Ok(violations.into_values().collect())
    }

    /// Helper method to record compliance violations
    fn record_violation(
        &self,
        violations: &mut HashMap<String, ComplianceViolation>,
        rule: &str,
        description: &str,
        severity: RiskLevel,
        timestamp: DateTime<Utc>,
    ) {
        let violation = violations
            .entry(rule.to_string())
            .or_insert_with(|| ComplianceViolation {
                rule: rule.to_string(),
                description: description.to_string(),
                severity: severity.clone(),
                count: 0,
                last_occurrence: timestamp,
            });

        violation.count += 1;
        if timestamp > violation.last_occurrence {
            violation.last_occurrence = timestamp;
        }

        // Update severity to highest encountered
        match (&violation.severity, &severity) {
            (RiskLevel::Low, RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical)
            | (RiskLevel::Medium, RiskLevel::High | RiskLevel::Critical)
            | (RiskLevel::High, RiskLevel::Critical) => {
                violation.severity = severity;
            }
            _ => {} // Keep existing severity
        }
    }
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            event_types: None,
            outcomes: None,
            risk_levels: None,
            actors: None,
            resources: None,
            actions: None,
            tags: None,
            mission_id: None,
            correlation_id: None,
            limit: Some(100),
            offset: Some(0),
        }
    }
}

/// Create an audit entry builder for convenience
pub struct AuditEntryBuilder {
    entry: AuditEntry,
}

impl AuditEntryBuilder {
    pub fn new(
        event_type: AuditEventType,
        actor: String,
        resource: String,
        action: String,
    ) -> Self {
        Self {
            entry: AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type,
                actor,
                resource,
                action,
                outcome: AuditOutcome::Success,
                details: HashMap::new(),
                risk_level: RiskLevel::Low,
                chain_hash: String::new(),
                previous_hash: None,
                metadata: AuditMetadata::default(),
            },
        }
    }

    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.entry.outcome = outcome;
        self
    }

    pub fn risk_level(mut self, risk_level: RiskLevel) -> Self {
        self.entry.risk_level = risk_level;
        self
    }

    pub fn detail(mut self, key: String, value: serde_json::Value) -> Self {
        self.entry.details.insert(key, value);
        self
    }

    pub fn mission_id(mut self, mission_id: String) -> Self {
        self.entry.metadata.mission_id = Some(mission_id);
        self
    }

    pub fn correlation_id(mut self, correlation_id: String) -> Self {
        self.entry.metadata.correlation_id = Some(correlation_id);
        self
    }

    pub fn tag(mut self, tag: String) -> Self {
        self.entry.metadata.tags.push(tag);
        self
    }

    pub fn execution_time(mut self, ms: u64) -> Self {
        self.entry.metadata.execution_time_ms = Some(ms);
        self
    }

    pub fn memory_usage(mut self, mb: u64) -> Self {
        self.entry.metadata.memory_usage_mb = Some(mb);
        self
    }

    pub fn tool_name(mut self, tool_name: String) -> Self {
        self.entry.metadata.tool_name = Some(tool_name);
        self
    }

    pub fn build(self) -> AuditEntry {
        self.entry
    }
}

// Legacy AuditSink for backward compatibility
pub struct AuditSink {
    enhanced: EnhancedAuditSink,
}

impl AuditSink {
    pub fn new() -> Self {
        Self {
            enhanced: EnhancedAuditSink::new(None),
        }
    }

    pub async fn log(&self, entry: AuditEntry) -> Result<()> {
        self.enhanced.log(entry).await
    }

    pub async fn get_entries(&self) -> Vec<AuditEntry> {
        self.enhanced.entries.read().await.clone()
    }

    pub async fn verify_chain_integrity(&self) -> bool {
        self.enhanced.verify_integrity().await.unwrap_or(false)
    }
}

impl Default for AuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use serde_json::json;
    use tempfile::tempdir;

    fn create_test_entry() -> AuditEntry {
        // Generate realistic test data using proper UUIDs and realistic values
        let _session_id = format!("sess_{}", Uuid::new_v4().simple());
        let user_id = "test_agent".to_string();
        let _mission_id = format!("msn_{}", Uuid::new_v4().simple());

        AuditEntryBuilder::new(
            AuditEventType::ToolExecution,
            user_id,
            "test_resource".to_string(),
            "test_action".to_string(),
        )
        .outcome(AuditOutcome::Success)
        .risk_level(RiskLevel::Medium)
        .detail("test_key".to_string(), json!("test_value"))
        .mission_id("mission_123".to_string())
        .tag("test_tag".to_string())
        .execution_time(150)
        .memory_usage(64)
        .build()
    }

    #[test]
    fn test_audit_entry_builder() {
        let entry = create_test_entry();

        assert_eq!(entry.event_type, AuditEventType::ToolExecution);
        assert_eq!(entry.actor, "test_agent");
        assert_eq!(entry.resource, "test_resource");
        assert_eq!(entry.action, "test_action");
        assert_eq!(entry.outcome, AuditOutcome::Success);
        assert_eq!(entry.risk_level, RiskLevel::Medium);
        assert_eq!(entry.details.get("test_key"), Some(&json!("test_value")));
        assert_eq!(entry.metadata.mission_id, Some("mission_123".to_string()));
        assert!(entry.metadata.tags.contains(&"test_tag".to_string()));
        assert_eq!(entry.metadata.execution_time_ms, Some(150));
        assert_eq!(entry.metadata.memory_usage_mb, Some(64));
    }

    #[test]
    fn test_audit_metadata_default() {
        let metadata = AuditMetadata::default();

        assert!(metadata.session_id.is_none());
        assert!(metadata.user_agent.is_none());
        assert!(metadata.ip_address.is_none());
        assert!(metadata.correlation_id.is_none());
        assert!(metadata.trace_id.is_none());
        assert!(metadata.mission_id.is_none());
        assert!(metadata.tool_name.is_none());
        assert!(metadata.execution_time_ms.is_none());
        assert!(metadata.memory_usage_mb.is_none());
        assert!(metadata.tags.is_empty());
    }

    #[test]
    fn test_audit_query_default() {
        let query = AuditQuery::default();

        assert!(query.start_time.is_none());
        assert!(query.end_time.is_none());
        assert!(query.event_types.is_none());
        assert!(query.outcomes.is_none());
        assert!(query.risk_levels.is_none());
        assert!(query.actors.is_none());
        assert!(query.resources.is_none());
        assert!(query.actions.is_none());
        assert!(query.tags.is_none());
        assert!(query.mission_id.is_none());
        assert!(query.correlation_id.is_none());
        assert_eq!(query.limit, Some(100));
        assert_eq!(query.offset, Some(0));
    }

    #[tokio::test]
    async fn test_enhanced_audit_sink_creation() {
        let sink = EnhancedAuditSink::new(None);
        assert!(sink.entries.read().await.is_empty());
        assert!(sink.storage_path.is_none());
        assert!(sink.chain_integrity);
        assert_eq!(sink.retention_days, 365);
        assert!(!sink.encryption_enabled);
    }

    #[tokio::test]
    async fn test_enhanced_audit_sink_with_options() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("audit.log");

        let sink = EnhancedAuditSink::new(Some(storage_path.clone()))
            .with_encryption(true)
            .with_retention_days(90);

        assert_eq!(sink.storage_path, Some(storage_path));
        assert!(sink.encryption_enabled);
        assert_eq!(sink.retention_days, 90);
    }

    #[tokio::test]
    async fn test_audit_entry_logging() {
        let sink = EnhancedAuditSink::new(None);
        let entry = create_test_entry();
        let entry_id = entry.id.clone();

        let result = sink.log(entry).await;
        assert!(result.is_ok());

        let entries = sink.entries.read().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, entry_id);
    }

    #[tokio::test]
    async fn test_audit_chain_integrity() {
        let sink = EnhancedAuditSink::new(None);

        // Log multiple entries
        for i in 0..5 {
            let entry = AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent".to_string(),
                format!("resource_{}", i),
                format!("action_{}", i),
            )
            .build();

            sink.log(entry).await.unwrap();
        }

        // Verify chain integrity
        let is_valid = sink.verify_integrity().await.unwrap();
        assert!(is_valid);

        // Check that each entry has the correct previous hash
        let entries = sink.entries.read().await;
        assert_eq!(entries.len(), 5);

        // First entry should have no previous hash
        assert!(entries[0].previous_hash.is_none());

        // Subsequent entries should have previous hashes
        for i in 1..5 {
            assert!(entries[i].previous_hash.is_some());
            assert_eq!(
                entries[i].previous_hash,
                Some(entries[i - 1].chain_hash.clone())
            );
        }
    }

    #[tokio::test]
    async fn test_audit_query_time_range() {
        let sink = EnhancedAuditSink::new(None).with_retention_days(9999); // Don't cleanup old entries during test
        let base_time = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();

        // Create entries at different times - build them directly with the timestamp
        for i in 0..5 {
            let entry = AuditEntry {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: base_time + Duration::hours(i),
                event_type: AuditEventType::ToolExecution,
                actor: "test_agent".to_string(),
                resource: format!("resource_{}", i),
                action: "test_action".to_string(),
                outcome: AuditOutcome::Success,
                details: std::collections::HashMap::new(),
                risk_level: RiskLevel::Low,
                chain_hash: String::new(),
                previous_hash: None,
                metadata: AuditMetadata::default(),
            };
            sink.log(entry).await.unwrap();
        }

        // Query for entries between hour 1 and hour 3 (inclusive)
        let query = AuditQuery {
            start_time: Some(base_time + Duration::hours(1)),
            end_time: Some(base_time + Duration::hours(4)), // End time is exclusive, so use hour 4 to include hour 3
            ..Default::default()
        };

        let results = sink.query(query).await.unwrap();
        assert_eq!(results.len(), 3); // Hours 1, 2, 3
    }

    #[tokio::test]
    async fn test_audit_query_event_type_filter() {
        let sink = EnhancedAuditSink::new(None);

        // Create entries with different event types
        let event_types = vec![
            AuditEventType::ToolExecution,
            AuditEventType::Authentication,
            AuditEventType::DataAccess,
            AuditEventType::ToolExecution,
        ];

        for event_type in event_types {
            let entry = AuditEntryBuilder::new(
                event_type,
                "agent".to_string(),
                "resource".to_string(),
                "action".to_string(),
            )
            .build();
            sink.log(entry).await.unwrap();
        }

        // Query for only ToolExecution events
        let query = AuditQuery {
            event_types: Some(vec![AuditEventType::ToolExecution]),
            ..Default::default()
        };

        let results = sink.query(query).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|r| r.event_type == AuditEventType::ToolExecution));
    }

    #[tokio::test]
    async fn test_audit_query_multiple_filters() {
        let sink = EnhancedAuditSink::new(None);

        // Create entries with different attributes
        let entries = vec![
            AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent1".to_string(),
                "resource1".to_string(),
                "action1".to_string(),
            )
            .outcome(AuditOutcome::Success)
            .risk_level(RiskLevel::Low)
            .build(),
            AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent2".to_string(),
                "resource2".to_string(),
                "action2".to_string(),
            )
            .outcome(AuditOutcome::Failure)
            .risk_level(RiskLevel::High)
            .build(),
            AuditEntryBuilder::new(
                AuditEventType::Authentication,
                "agent1".to_string(),
                "resource1".to_string(),
                "action1".to_string(),
            )
            .outcome(AuditOutcome::Success)
            .risk_level(RiskLevel::Medium)
            .build(),
        ];

        for entry in entries {
            sink.log(entry).await.unwrap();
        }

        // Query with multiple filters
        let query = AuditQuery {
            event_types: Some(vec![AuditEventType::ToolExecution]),
            actors: Some(vec!["agent1".to_string()]),
            outcomes: Some(vec![AuditOutcome::Success]),
            ..Default::default()
        };

        let results = sink.query(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor, "agent1");
        assert_eq!(results[0].event_type, AuditEventType::ToolExecution);
        assert_eq!(results[0].outcome, AuditOutcome::Success);
    }

    #[tokio::test]
    async fn test_audit_query_pagination() {
        let sink = EnhancedAuditSink::new(None);

        // Create 10 entries
        for i in 0..10 {
            let entry = AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent".to_string(),
                format!("resource_{}", i),
                format!("action_{}", i),
            )
            .build();
            sink.log(entry).await.unwrap();
        }

        // Query with pagination
        let query = AuditQuery {
            limit: Some(3),
            offset: Some(2),
            ..Default::default()
        };

        let results = sink.query(query).await.unwrap();
        assert_eq!(results.len(), 3);

        // Query beyond available entries
        let query = AuditQuery {
            limit: Some(5),
            offset: Some(15),
            ..Default::default()
        };

        let results = sink.query(query).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_audit_query_mission_id_filter() {
        let sink = EnhancedAuditSink::new(None);

        // Create entries with different mission IDs
        for i in 0..3 {
            let entry = AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent".to_string(),
                "resource".to_string(),
                "action".to_string(),
            )
            .mission_id(format!("mission_{}", i))
            .build();
            sink.log(entry).await.unwrap();
        }

        // Query for specific mission
        let query = AuditQuery {
            mission_id: Some("mission_1".to_string()),
            ..Default::default()
        };

        let results = sink.query(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].metadata.mission_id,
            Some("mission_1".to_string())
        );
    }

    #[tokio::test]
    async fn test_audit_query_tags_filter() {
        let sink = EnhancedAuditSink::new(None);

        // Create entries with different tags
        let entry1 = AuditEntryBuilder::new(
            AuditEventType::ToolExecution,
            "agent".to_string(),
            "resource1".to_string(),
            "action".to_string(),
        )
        .tag("production".to_string())
        .tag("critical".to_string())
        .build();

        let entry2 = AuditEntryBuilder::new(
            AuditEventType::ToolExecution,
            "agent".to_string(),
            "resource2".to_string(),
            "action".to_string(),
        )
        .tag("development".to_string())
        .build();

        sink.log(entry1).await.unwrap();
        sink.log(entry2).await.unwrap();

        // Query for entries with specific tag
        let query = AuditQuery {
            tags: Some(vec!["production".to_string()]),
            ..Default::default()
        };

        let results = sink.query(query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].resource, "resource1");
    }

    #[tokio::test]
    async fn test_audit_report_generation() {
        let sink = EnhancedAuditSink::new(None);
        let base_time = Utc::now();

        // Create diverse audit entries
        let entries = vec![
            AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent1".to_string(),
                format!("file:/workspace/project_{}.rs", Uuid::new_v4().simple()),
                "create_file".to_string(),
            )
            .outcome(AuditOutcome::Success)
            .risk_level(RiskLevel::Low)
            .execution_time(100)
            .memory_usage(32)
            .build(),
            AuditEntryBuilder::new(
                AuditEventType::Authentication,
                "agent2".to_string(),
                "auth_service".to_string(),
                "oauth_login".to_string(),
            )
            .outcome(AuditOutcome::Success)
            .risk_level(RiskLevel::Medium)
            .execution_time(50)
            .memory_usage(16)
            .build(),
            AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent1".to_string(),
                format!("file:/tmp/temp_{}.log", Uuid::new_v4().simple()),
                "delete_file".to_string(),
            )
            .outcome(AuditOutcome::Failure)
            .risk_level(RiskLevel::High)
            .execution_time(200)
            .memory_usage(48)
            .build(),
        ];

        for entry in entries {
            sink.log(entry).await.unwrap();
        }

        let report = sink
            .generate_report(
                base_time - Duration::hours(1),
                base_time + Duration::hours(1),
            )
            .await
            .unwrap();

        assert_eq!(report.total_events, 3);
        assert!(report.events_by_type.contains_key("ToolExecution"));
        assert!(report.events_by_outcome.contains_key("Success"));
        assert!(report.events_by_risk_level.contains_key("Low"));

        // Check top actors
        assert!(!report.top_actors.is_empty());
        assert!(report.top_actors.iter().any(|(actor, _)| actor == "agent1"));

        // Check performance metrics
        assert!(report.performance_metrics.total_operations > 0);
        assert!(report.performance_metrics.avg_execution_time_ms > 0.0);

        // Check compliance status
        assert!(report.compliance_status.total_checks > 0);
    }

    #[tokio::test]
    async fn test_audit_export_json() {
        let sink = EnhancedAuditSink::new(None);
        let entry = create_test_entry();
        sink.log(entry).await.unwrap();

        let exported = sink.export("json", None).await.unwrap();
        assert!(exported.contains("test_agent"));
        assert!(exported.contains("test_resource"));

        // Verify it's valid JSON
        let parsed: Vec<AuditEntry> = serde_json::from_str(&exported).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[tokio::test]
    async fn test_audit_export_csv() {
        let sink = EnhancedAuditSink::new(None);
        let entry = create_test_entry();
        sink.log(entry).await.unwrap();

        let exported = sink.export("csv", None).await.unwrap();
        assert!(exported.contains("id,timestamp,event_type"));
        assert!(exported.contains("test_agent"));
        assert!(exported.contains("test_resource"));
        assert!(exported.contains("ToolExecution"));
    }

    #[tokio::test]
    async fn test_audit_export_unsupported_format() {
        let sink = EnhancedAuditSink::new(None);
        let result = sink.export("xml", None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported export format"));
    }

    #[tokio::test]
    async fn test_audit_export_with_query() {
        let sink = EnhancedAuditSink::new(None);

        // Create multiple entries
        for i in 0..3 {
            let entry = AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                format!("agent_{}", i),
                "resource".to_string(),
                "action".to_string(),
            )
            .build();
            sink.log(entry).await.unwrap();
        }

        // Export with filter
        let query = AuditQuery {
            actors: Some(vec!["agent_1".to_string()]),
            ..Default::default()
        };

        let exported = sink.export("json", Some(query)).await.unwrap();
        let parsed: Vec<AuditEntry> = serde_json::from_str(&exported).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].actor, "agent_1");
    }

    #[tokio::test]
    async fn test_security_highlights_generation() {
        let sink = EnhancedAuditSink::new(None);
        let base_time = Utc::now();

        // Create high-risk security events
        for i in 0..3 {
            let entry = AuditEntryBuilder::new(
                AuditEventType::SecurityEvent,
                "attacker".to_string(),
                format!("sensitive_resource_{}", i),
                "unauthorized_access".to_string(),
            )
            .outcome(AuditOutcome::Blocked)
            .risk_level(RiskLevel::Critical)
            .build();

            sink.log(entry).await.unwrap();
        }

        let report = sink
            .generate_report(
                base_time - Duration::hours(1),
                base_time + Duration::hours(1),
            )
            .await
            .unwrap();

        assert!(!report.security_highlights.is_empty());
        let highlight = &report.security_highlights[0];
        assert_eq!(highlight.severity, RiskLevel::Critical);
        assert_eq!(highlight.event_type, AuditEventType::SecurityEvent);
        assert_eq!(highlight.count, 3);
        assert_eq!(highlight.affected_resources.len(), 3);
    }

    #[tokio::test]
    async fn test_audit_chain_integrity_violation() {
        let sink = EnhancedAuditSink::new(None);

        // Log an entry normally
        let entry1 = create_test_entry();
        sink.log(entry1).await.unwrap();

        // Manually corrupt the chain by adding an entry with wrong previous hash
        let mut entry2 = create_test_entry();
        entry2.previous_hash = Some("corrupted_hash".to_string());
        entry2.chain_hash = "also_corrupted".to_string();

        sink.entries.write().await.push(entry2);

        // Verify integrity should fail
        let is_valid = sink.verify_integrity().await.unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_audit_retention_cleanup() {
        let sink = EnhancedAuditSink::new(None).with_retention_days(1);

        // Create old entries
        let old_time = Utc::now() - Duration::days(2);
        let mut old_entry = create_test_entry();
        old_entry.timestamp = old_time;

        // Create recent entries
        let recent_entry = create_test_entry();

        sink.entries.write().await.push(old_entry);
        sink.log(recent_entry).await.unwrap(); // This should trigger cleanup

        // Should only have the recent entry
        let entries = sink.entries.read().await;
        assert_eq!(entries.len(), 1);
        assert!(entries[0].timestamp > Utc::now() - Duration::hours(1));
    }

    #[tokio::test]
    async fn test_legacy_audit_sink_compatibility() {
        let sink = AuditSink::new();
        let entry = create_test_entry();

        sink.log(entry)
            .await
            .expect("Audit logging should succeed in test");

        let entries = sink.get_entries().await;
        assert_eq!(entries.len(), 1);

        let is_valid = sink.verify_chain_integrity().await;
        assert!(is_valid);
    }

    #[test]
    fn test_audit_event_type_serialization() {
        let event_type = AuditEventType::ToolExecution;
        let serialized = serde_json::to_string(&event_type).unwrap();
        let deserialized: AuditEventType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event_type, deserialized);
    }

    #[test]
    fn test_audit_outcome_serialization() {
        let outcome = AuditOutcome::Success;
        let serialized = serde_json::to_string(&outcome).unwrap();
        let deserialized: AuditOutcome = serde_json::from_str(&serialized).unwrap();
        assert_eq!(outcome, deserialized);
    }

    #[test]
    fn test_risk_level_serialization() {
        let risk_level = RiskLevel::High;
        let serialized = serde_json::to_string(&risk_level).unwrap();
        let deserialized: RiskLevel = serde_json::from_str(&serialized).unwrap();
        assert_eq!(risk_level, deserialized);
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = create_test_entry();
        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(entry.id, deserialized.id);
        assert_eq!(entry.event_type, deserialized.event_type);
        assert_eq!(entry.actor, deserialized.actor);
        assert_eq!(entry.resource, deserialized.resource);
        assert_eq!(entry.action, deserialized.action);
        assert_eq!(entry.outcome, deserialized.outcome);
        assert_eq!(entry.risk_level, deserialized.risk_level);
    }

    #[tokio::test]
    async fn test_performance_metrics_calculation() {
        let sink = EnhancedAuditSink::new(None);
        let base_time = Utc::now();

        // Create entries with performance data
        let entries = vec![
            AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent".to_string(),
                "resource".to_string(),
                "action".to_string(),
            )
            .execution_time(100)
            .memory_usage(50)
            .outcome(AuditOutcome::Success)
            .build(),
            AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent".to_string(),
                "resource".to_string(),
                "action".to_string(),
            )
            .execution_time(200)
            .memory_usage(75)
            .outcome(AuditOutcome::Failure)
            .build(),
            AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent".to_string(),
                "resource".to_string(),
                "action".to_string(),
            )
            .execution_time(150)
            .memory_usage(60)
            .outcome(AuditOutcome::Success)
            .build(),
        ];

        for entry in entries {
            sink.log(entry).await.unwrap();
        }

        let report = sink
            .generate_report(
                base_time - Duration::hours(1),
                base_time + Duration::hours(1),
            )
            .await
            .unwrap();

        let metrics = &report.performance_metrics;
        assert_eq!(metrics.avg_execution_time_ms, 150.0); // (100 + 200 + 150) / 3
        assert_eq!(metrics.max_execution_time_ms, 200);
        assert_eq!(metrics.total_operations, 3);
        assert_eq!(metrics.avg_memory_usage_mb, 61.666666666666664); // (50 + 75 + 60) / 3
        assert_eq!(metrics.peak_memory_usage_mb, 75);
        assert_eq!(metrics.error_rate, 1.0 / 3.0); // 1 failure out of 3 total
    }

    #[tokio::test]
    async fn test_compliance_status_calculation() {
        let sink = EnhancedAuditSink::new(None);
        let base_time = Utc::now();

        // Create entries with mixed outcomes
        for i in 0..10 {
            let outcome = if i < 7 {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            };
            let entry = AuditEntryBuilder::new(
                AuditEventType::ToolExecution,
                "agent".to_string(),
                "resource".to_string(),
                "action".to_string(),
            )
            .outcome(outcome)
            .tool_name("test_tool".to_string())
            .build();

            sink.log(entry).await.unwrap();
        }

        let report = sink
            .generate_report(
                base_time - Duration::hours(1),
                base_time + Duration::hours(1),
            )
            .await
            .unwrap();

        let compliance = &report.compliance_status;
        assert_eq!(compliance.total_checks, 10);
        assert_eq!(compliance.passed_checks, 7);
        assert_eq!(compliance.failed_checks, 3);

        // The score will be 65.0 instead of 70.0 due to compliance violations:
        // Base score: 70.0 (7 out of 10 passed)
        // Penalty: 5.0 (Critical violation for incomplete audit trail - missing chain_hash)
        // Final score: 65.0 (70.0 - 5.0)
        assert_eq!(compliance.compliance_score, 65.0);

        // Verify that the violation was detected
        assert_eq!(compliance.violations.len(), 1);
        assert_eq!(compliance.violations[0].rule, "incomplete_audit_trail");
        assert_eq!(compliance.violations[0].severity, RiskLevel::Critical);
    }

    #[test]
    fn test_audit_entry_builder_chaining() {
        let entry = AuditEntryBuilder::new(
            AuditEventType::SecurityEvent,
            "security_agent".to_string(),
            "protected_resource".to_string(),
            "access_attempt".to_string(),
        )
        .outcome(AuditOutcome::Blocked)
        .risk_level(RiskLevel::Critical)
        .detail("ip_address".to_string(), json!("192.168.1.100"))
        .detail("user_agent".to_string(), json!("Mozilla/5.0"))
        .mission_id("security_scan_001".to_string())
        .correlation_id("corr_123".to_string())
        .tag("security".to_string())
        .tag("blocked".to_string())
        .execution_time(25)
        .memory_usage(8)
        .build();

        assert_eq!(entry.event_type, AuditEventType::SecurityEvent);
        assert_eq!(entry.actor, "security_agent");
        assert_eq!(entry.outcome, AuditOutcome::Blocked);
        assert_eq!(entry.risk_level, RiskLevel::Critical);
        assert_eq!(entry.details.len(), 2);
        assert_eq!(
            entry.metadata.mission_id,
            Some("security_scan_001".to_string())
        );
        assert_eq!(entry.metadata.correlation_id, Some("corr_123".to_string()));
        assert_eq!(entry.metadata.tags.len(), 2);
        assert_eq!(entry.metadata.execution_time_ms, Some(25));
        assert_eq!(entry.metadata.memory_usage_mb, Some(8));
    }
}
