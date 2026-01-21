use crate::security::SecurityEvent;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::Mutex;

type ContextInfo = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Context tuple: (session_id, tenant_id, action, ip_address, user_agent)
/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub tenant_id: Option<String>,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub outcome: AuditOutcome,
    pub risk_score: u32,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: HashMap<String, String>,
    pub event_data: SecurityEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditOutcome {
    Success,
    Failure,
    Warning,
    Information,
}

/// Audit query parameters
#[derive(Debug, Clone)]
pub struct AuditQuery {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub user_id: Option<String>,
    pub event_types: Vec<String>,
    pub outcome: Option<AuditOutcome>,
    pub resource: Option<String>,
    pub min_risk_score: Option<u32>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_events: u64,
    pub events_by_type: HashMap<String, u64>,
    pub events_by_outcome: HashMap<String, u64>,
    pub events_by_user: HashMap<String, u64>,
    pub risk_score_distribution: RiskScoreDistribution,
    pub time_period: DateRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreDistribution {
    pub low: u64,      // 0-25
    pub medium: u64,   // 26-50
    pub high: u64,     // 51-75
    pub critical: u64, // 76-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Audit trail integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityVerification {
    pub verified: bool,
    pub total_entries: u64,
    pub verified_entries: u64,
    pub corrupted_entries: Vec<String>,
    pub verification_timestamp: DateTime<Utc>,
    pub hash_chain_valid: bool,
}

/// Audit service trait
#[async_trait]
pub trait AuditService: Send + Sync {
    async fn log_event(&self, event: SecurityEvent) -> crate::core::error::Result<String>;
    async fn query_events(&self, query: AuditQuery) -> crate::core::error::Result<Vec<AuditEntry>>;
    async fn get_statistics(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> crate::core::error::Result<AuditStatistics>;
    async fn verify_integrity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> crate::core::error::Result<IntegrityVerification>;
    async fn export_audit_log(
        &self,
        query: AuditQuery,
        format: ExportFormat,
    ) -> crate::core::error::Result<Vec<u8>>;
    async fn count_events_by_type(
        &self,
        event_type: &str,
        period: Duration,
    ) -> crate::core::error::Result<u64>;
    async fn purge_old_entries(&self, older_than: DateTime<Utc>)
        -> crate::core::error::Result<u64>;
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
    Pdf,
}

/// Database-backed audit service
/// WARNING: This implementation uses in-memory storage and is intended for
/// demonstration and testing purposes only. Production use requires a
/// persistent database backend for audit trail integrity.
pub struct DatabaseAuditService {
    entries: Mutex<Vec<AuditEntry>>,
    hash_chain: Mutex<Vec<String>>,
}

impl DatabaseAuditService {
    pub fn new() -> crate::core::error::Result<Self> {
        Ok(Self {
            entries: Mutex::new(Vec::new()),
            hash_chain: Mutex::new(Vec::new()),
        })
    }

    fn calculate_risk_score(&self, event: &SecurityEvent) -> u32 {
        match event {
            SecurityEvent::Authentication { success, .. } => {
                if *success {
                    10
                } else {
                    40
                }
            }
            SecurityEvent::Authorization { granted, .. } => {
                if *granted {
                    5
                } else {
                    35
                }
            }
            SecurityEvent::DataAccess { classification, .. } => match classification {
                crate::security::SecurityLevel::Public => 5,
                crate::security::SecurityLevel::Internal => 15,
                crate::security::SecurityLevel::Confidential => 30,
                crate::security::SecurityLevel::Restricted => 50,
                crate::security::SecurityLevel::TopSecret => 75,
            },
            SecurityEvent::ThreatDetected { severity, .. } => match severity {
                crate::security::ThreatSeverity::Low => 30,
                crate::security::ThreatSeverity::Medium => 50,
                crate::security::ThreatSeverity::High => 75,
                crate::security::ThreatSeverity::Critical => 95,
            },
            SecurityEvent::PolicyViolation { severity, .. } => match severity {
                crate::security::ViolationSeverity::Minor => 20,
                crate::security::ViolationSeverity::Major => 60,
                crate::security::ViolationSeverity::Critical => 90,
            },
        }
    }

    fn determine_outcome(&self, event: &SecurityEvent) -> AuditOutcome {
        match event {
            SecurityEvent::Authentication { success, .. } => {
                if *success {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Failure
                }
            }
            SecurityEvent::Authorization { granted, .. } => {
                if *granted {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Warning
                }
            }
            SecurityEvent::DataAccess { .. } => AuditOutcome::Information,
            SecurityEvent::ThreatDetected { .. } => AuditOutcome::Warning,
            SecurityEvent::PolicyViolation { .. } => AuditOutcome::Failure,
        }
    }

    fn extract_metadata(
        &self,
        event: &SecurityEvent,
    ) -> (Option<String>, Option<String>, HashMap<String, String>) {
        let mut metadata = HashMap::new();

        match event {
            SecurityEvent::Authentication {
                user_id,
                method,
                ip_address,
                ..
            } => {
                metadata.insert("auth_method".to_string(), method.clone());
                if let Some(ip) = ip_address {
                    metadata.insert("ip_address".to_string(), ip.clone());
                }
                (Some(user_id.clone()), None, metadata)
            }
            SecurityEvent::Authorization {
                user_id,
                resource,
                action,
                ..
            } => {
                metadata.insert("action".to_string(), action.clone());
                (Some(user_id.clone()), Some(resource.clone()), metadata)
            }
            SecurityEvent::DataAccess {
                user_id,
                resource,
                operation,
                classification,
            } => {
                metadata.insert("operation".to_string(), operation.clone());
                metadata.insert(
                    "classification".to_string(),
                    format!("{:?}", classification),
                );
                (Some(user_id.clone()), Some(resource.clone()), metadata)
            }
            SecurityEvent::ThreatDetected {
                threat_type,
                source,
                details,
                ..
            } => {
                metadata.insert("threat_type".to_string(), threat_type.clone());
                metadata.extend(details.clone());
                (Some(source.clone()), None, metadata)
            }
            SecurityEvent::PolicyViolation {
                user_id,
                policy,
                violation_type,
                ..
            } => {
                metadata.insert("policy".to_string(), policy.clone());
                metadata.insert("violation_type".to_string(), violation_type.clone());
                (Some(user_id.clone()), None, metadata)
            }
        }
    }

    /// Extract context information from SecurityEvent for audit trail.
    /// Returns (session_id, tenant_id, action, ip_address, user_agent).
    /// Some fields may be None depending on event type.
    fn extract_context_info(&self, event: &SecurityEvent) -> ContextInfo {
        match event {
            SecurityEvent::Authentication { ip_address, .. } => {
                // For authentication events, we might have IP address
                (None, None, None, ip_address.clone(), None)
            }
            SecurityEvent::Authorization { action, .. } => {
                // For authorization events, we have the action being authorized
                (None, None, Some(action.clone()), None, None)
            }
            SecurityEvent::DataAccess { operation, .. } => {
                // For data access events, the operation is the action
                (None, None, Some(operation.clone()), None, None)
            }
            SecurityEvent::ThreatDetected { details, .. } => {
                // Extract IP and user agent from threat details if available
                let ip_address = details.get("ip_address").cloned();
                let user_agent = details.get("user_agent").cloned();
                let session_id = details.get("session_id").cloned();
                let tenant_id = details.get("tenant_id").cloned();
                (session_id, tenant_id, None, ip_address, user_agent)
            }
            SecurityEvent::PolicyViolation { violation_type, .. } => {
                // For policy violations, the violation type is the action
                (None, None, Some(violation_type.clone()), None, None)
            }
        }
    }

    fn calculate_entry_hash(&self, entry: &AuditEntry, previous_hash: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(previous_hash);
        hasher.update(entry.id.as_bytes());
        hasher.update(entry.timestamp.timestamp().to_be_bytes());
        hasher.update(entry.event_type.as_bytes());
        if let Some(user_id) = &entry.user_id {
            hasher.update(user_id.as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    fn matches_query(&self, entry: &AuditEntry, query: &AuditQuery) -> bool {
        if entry.timestamp < query.start_time || entry.timestamp > query.end_time {
            return false;
        }

        if let Some(user_id) = &query.user_id {
            if entry.user_id.as_ref() != Some(user_id) {
                return false;
            }
        }

        if !query.event_types.is_empty() && !query.event_types.contains(&entry.event_type) {
            return false;
        }

        if let Some(outcome) = &query.outcome {
            if &entry.outcome != outcome {
                return false;
            }
        }

        if let Some(resource) = &query.resource {
            if entry.resource.as_ref() != Some(resource) {
                return false;
            }
        }

        if let Some(min_risk) = query.min_risk_score {
            if entry.risk_score < min_risk {
                return false;
            }
        }

        true
    }
}

#[async_trait]
impl AuditService for DatabaseAuditService {
    async fn log_event(&self, event: SecurityEvent) -> crate::core::error::Result<String> {
        let entry_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let risk_score = self.calculate_risk_score(&event);
        let outcome = self.determine_outcome(&event);
        let (user_id, resource, metadata) = self.extract_metadata(&event);

        let event_type = match &event {
            SecurityEvent::Authentication { .. } => "authentication",
            SecurityEvent::Authorization { .. } => "authorization",
            SecurityEvent::DataAccess { .. } => "data_access",
            SecurityEvent::ThreatDetected { .. } => "threat_detected",
            SecurityEvent::PolicyViolation { .. } => "policy_violation",
        }
        .to_string();

        // Extract context information for complete audit trail
        let (session_id, tenant_id, action, ip_address, user_agent) =
            self.extract_context_info(&event);

        let entry = AuditEntry {
            id: entry_id.clone(),
            timestamp,
            event_type,
            user_id,
            session_id,
            tenant_id,
            resource,
            action,
            outcome,
            risk_score,
            ip_address,
            user_agent,
            metadata,
            event_data: event,
        };

        // Add to hash chain for integrity
        let mut hash_chain = self.hash_chain.lock().await;
        let previous_hash = hash_chain.last().cloned().unwrap_or_else(|| {
            // Use SHA256 of empty string as genesis hash
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::new().finalize())
        });
        let entry_hash = self.calculate_entry_hash(&entry, &previous_hash);
        hash_chain.push(entry_hash);

        // Store the entry
        let mut entries = self.entries.lock().await;
        entries.push(entry);

        Ok(entry_id)
    }

    async fn query_events(&self, query: AuditQuery) -> crate::core::error::Result<Vec<AuditEntry>> {
        let entries = self.entries.lock().await;
        let mut matching_entries: Vec<AuditEntry> = entries
            .iter()
            .filter(|entry| self.matches_query(entry, &query))
            .cloned()
            .collect();

        // Sort by timestamp descending (newest first)
        matching_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply pagination
        if let Some(offset) = query.offset {
            matching_entries = matching_entries.into_iter().skip(offset).collect();
        }

        if let Some(limit) = query.limit {
            matching_entries.truncate(limit);
        }

        Ok(matching_entries)
    }

    async fn get_statistics(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> crate::core::error::Result<AuditStatistics> {
        let entries = self.entries.lock().await;
        let period_entries: Vec<&AuditEntry> = entries
            .iter()
            .filter(|entry| entry.timestamp >= start && entry.timestamp <= end)
            .collect();

        let total_events = period_entries.len() as u64;

        let mut events_by_type = HashMap::new();
        let mut events_by_outcome = HashMap::new();
        let mut events_by_user = HashMap::new();
        let mut risk_distribution = RiskScoreDistribution {
            low: 0,
            medium: 0,
            high: 0,
            critical: 0,
        };

        for entry in &period_entries {
            *events_by_type.entry(entry.event_type.clone()).or_insert(0) += 1;

            let outcome_str = format!("{:?}", entry.outcome);
            *events_by_outcome.entry(outcome_str).or_insert(0) += 1;

            if let Some(user_id) = &entry.user_id {
                *events_by_user.entry(user_id.clone()).or_insert(0) += 1;
            }

            match entry.risk_score {
                0..=25 => risk_distribution.low += 1,
                26..=50 => risk_distribution.medium += 1,
                51..=75 => risk_distribution.high += 1,
                76..=100 => risk_distribution.critical += 1,
                101..=u32::MAX => risk_distribution.critical += 1,
            }
        }

        Ok(AuditStatistics {
            total_events,
            events_by_type,
            events_by_outcome,
            events_by_user,
            risk_score_distribution: risk_distribution,
            time_period: DateRange { start, end },
        })
    }

    async fn verify_integrity(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> crate::core::error::Result<IntegrityVerification> {
        let entries = self.entries.lock().await;
        let hash_chain = self.hash_chain.lock().await;

        let genesis_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::new().finalize())
        };

        let mut total_entries = 0u64;
        let mut verified_entries = 0u64;
        let mut corrupted_entries = Vec::new();
        let mut hash_chain_valid = true;
        let mut previous_hash = genesis_hash;

        for (index, entry) in entries.iter().enumerate() {
            let expected_hash = self.calculate_entry_hash(entry, &previous_hash);
            let chain_match = hash_chain
                .get(index)
                .map(|stored| stored == &expected_hash)
                .unwrap_or(false);

            let in_period = entry.timestamp >= start && entry.timestamp <= end;
            if in_period {
                total_entries += 1;
                if chain_match {
                    verified_entries += 1;
                } else {
                    corrupted_entries.push(entry.id.clone());
                }
            }

            if !chain_match {
                hash_chain_valid = false;
            }

            previous_hash = expected_hash;
        }

        Ok(IntegrityVerification {
            verified: corrupted_entries.is_empty(),
            total_entries,
            verified_entries,
            corrupted_entries,
            verification_timestamp: Utc::now(),
            hash_chain_valid,
        })
    }

    async fn export_audit_log(
        &self,
        query: AuditQuery,
        format: ExportFormat,
    ) -> crate::core::error::Result<Vec<u8>> {
        let entries = self.query_events(query).await?;

        match format {
            ExportFormat::Json => {
                let json = serde_json::to_string_pretty(&entries).map_err(|e| {
                    crate::core::error::RustChainError::Security(format!(
                        "JSON serialization error: {}",
                        e
                    ))
                })?;
                Ok(json.into_bytes())
            }
            ExportFormat::Csv => {
                use std::fmt::Write;
                let mut csv = String::new();
                writeln!(
                    csv,
                    "ID,Timestamp,EventType,UserID,Resource,Outcome,RiskScore"
                )?;

                for entry in entries {
                    writeln!(
                        csv,
                        "{},{},{},{},{},{:?},{}",
                        entry.id,
                        entry.timestamp.to_rfc3339(),
                        entry.event_type,
                        entry.user_id.as_deref().unwrap_or(""),
                        entry.resource.as_deref().unwrap_or(""),
                        entry.outcome,
                        entry.risk_score
                    )?;
                }

                Ok(csv.into_bytes())
            }
            ExportFormat::Xml => {
                use std::fmt::Write;
                let mut xml = String::new();
                writeln!(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
                writeln!(xml, "<audit_log>")?;

                for entry in entries {
                    writeln!(
                        xml,
                        "  <entry id=\"{}\" timestamp=\"{}\" type=\"{}\" risk=\"{}\">",
                        entry.id,
                        entry.timestamp.to_rfc3339(),
                        entry.event_type,
                        entry.risk_score
                    )?;
                    if let Some(user_id) = &entry.user_id {
                        writeln!(xml, "    <user>{}</user>", user_id)?;
                    }
                    if let Some(resource) = &entry.resource {
                        writeln!(xml, "    <resource>{}</resource>", resource)?;
                    }
                    writeln!(xml, "  </entry>")?;
                }

                writeln!(xml, "</audit_log>")?;
                Ok(xml.into_bytes())
            }
            ExportFormat::Pdf => {
                // PDF export requires a proper PDF library
                // For now, return an error indicating this feature is not implemented
                Err(crate::core::error::RustChainError::Security(
                    "PDF export not implemented - requires PDF library integration".to_string(),
                ))
            }
        }
    }

    async fn count_events_by_type(
        &self,
        event_type: &str,
        period: Duration,
    ) -> crate::core::error::Result<u64> {
        let entries = self.entries.lock().await;
        let cutoff = Utc::now() - period;

        let count = entries
            .iter()
            .filter(|entry| entry.timestamp >= cutoff && entry.event_type == event_type)
            .count() as u64;

        Ok(count)
    }

    async fn purge_old_entries(
        &self,
        older_than: DateTime<Utc>,
    ) -> crate::core::error::Result<u64> {
        let mut entries = self.entries.lock().await;
        let initial_count = entries.len();

        entries.retain(|entry| entry.timestamp >= older_than);

        let purged_count = (initial_count - entries.len()) as u64;
        Ok(purged_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{SecurityEvent, ThreatSeverity};

    #[tokio::test]
    async fn test_log_and_query_events() {
        let audit_service = DatabaseAuditService::new().unwrap();

        let event = SecurityEvent::Authentication {
            user_id: "test_user".to_string(),
            method: "password".to_string(),
            success: true,
            ip_address: Some("127.0.0.1".to_string()),
        };

        let entry_id = audit_service.log_event(event).await.unwrap();
        assert!(!entry_id.is_empty());

        let query = AuditQuery {
            start_time: Utc::now() - Duration::minutes(5),
            end_time: Utc::now() + Duration::minutes(5),
            user_id: Some("test_user".to_string()),
            event_types: vec![],
            outcome: None,
            resource: None,
            min_risk_score: None,
            limit: None,
            offset: None,
        };

        let events = audit_service.query_events(query).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, entry_id);
    }

    #[tokio::test]
    async fn test_risk_score_calculation() {
        let audit_service = DatabaseAuditService::new().unwrap();

        // High-risk threat event
        let threat_event = SecurityEvent::ThreatDetected {
            threat_type: "SQL Injection".to_string(),
            severity: ThreatSeverity::Critical,
            source: "external".to_string(),
            details: std::collections::HashMap::new(),
        };

        let _entry_id = audit_service.log_event(threat_event).await.unwrap();

        let query = AuditQuery {
            start_time: Utc::now() - Duration::minutes(5),
            end_time: Utc::now() + Duration::minutes(5),
            user_id: None,
            event_types: vec!["threat_detected".to_string()],
            outcome: None,
            resource: None,
            min_risk_score: Some(90),
            limit: None,
            offset: None,
        };

        let events = audit_service.query_events(query).await.unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].risk_score >= 90);
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let audit_service = DatabaseAuditService::new().unwrap();

        // Log some events
        for i in 0..5 {
            let event = SecurityEvent::Authentication {
                user_id: format!("user_{}", i),
                method: "password".to_string(),
                success: true,
                ip_address: Some("127.0.0.1".to_string()),
            };
            audit_service.log_event(event).await.unwrap();
        }

        let verification = audit_service
            .verify_integrity(
                Utc::now() - Duration::hours(1),
                Utc::now() + Duration::hours(1),
            )
            .await
            .unwrap();

        assert!(verification.verified);
        assert_eq!(verification.total_entries, 5);
        assert_eq!(verification.verified_entries, 5);
        assert!(verification.hash_chain_valid);
    }
}
