use crate::security::{Credentials, ThreatSeverity};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Threat detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub threat_id: String,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub confidence: f32,
    pub description: String,
    pub details: HashMap<String, String>,
    pub recommended_actions: Vec<String>,
    pub detected_at: DateTime<Utc>,
    pub source: ThreatSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSource {
    Network { ip_address: String },
    User { user_id: String },
    System { component: String },
    External { service: String },
}

/// Threat pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: ThreatSeverity,
    pub indicators: Vec<ThreatIndicator>,
    pub time_window: Duration,
    pub threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatIndicator {
    FailedLoginAttempts { count: u32, window_minutes: u32 },
    UnusualLocation { deviation_km: f64 },
    SuspiciousUserAgent { patterns: Vec<String> },
    RateLimitExceeded { requests_per_minute: u32 },
    UnauthorizedAccess { resource_patterns: Vec<String> },
    DataExfiltration { bytes_per_minute: u64 },
    SqlInjectionPattern { regex_patterns: Vec<String> },
    XssPattern { regex_patterns: Vec<String> },
    FileSystemAccess { suspicious_paths: Vec<String> },
    CommandInjection { command_patterns: Vec<String> },
}

/// Behavioral baseline for users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBaseline {
    pub user_id: String,
    pub typical_locations: Vec<GeoLocation>,
    pub usual_login_times: Vec<TimeRange>,
    pub common_resources: HashSet<String>,
    pub average_session_duration: Duration,
    pub typical_user_agents: Vec<String>,
    pub baseline_created: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub city: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start_hour: u8,
    pub end_hour: u8,
    pub days_of_week: Vec<u8>, // 0=Sunday, 6=Saturday
}

/// Threat detection service trait
#[async_trait]
pub trait ThreatDetectionService: Send + Sync {
    async fn detect_authentication_threat(
        &self,
        credentials: &Credentials,
    ) -> crate::core::error::Result<Option<ThreatDetection>>;
    async fn detect_behavioral_anomaly(
        &self,
        user_id: &str,
        activity: &UserActivity,
    ) -> crate::core::error::Result<Option<ThreatDetection>>;
    async fn detect_network_threat(
        &self,
        network_event: &NetworkEvent,
    ) -> crate::core::error::Result<Option<ThreatDetection>>;
    async fn analyze_request_pattern(
        &self,
        request: &RequestPattern,
    ) -> crate::core::error::Result<Option<ThreatDetection>>;
    async fn get_threat_patterns(&self) -> crate::core::error::Result<Vec<ThreatPattern>>;
}

#[derive(Debug, Clone)]
pub struct UserActivity {
    pub user_id: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub resource: String,
    pub action: String,
    pub success: bool,
    pub session_duration: Option<Duration>,
    pub bytes_transferred: Option<u64>,
    pub geolocation: Option<GeoLocation>,
}

#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub destination_ip: String,
    pub protocol: String,
    pub port: u16,
    pub bytes: u64,
    pub packets: u32,
    pub connection_state: String,
}

#[derive(Debug, Clone)]
pub struct RequestPattern {
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub method: String,
    pub uri: String,
    pub body: Option<String>,
    pub headers: HashMap<String, String>,
    pub response_code: u16,
    pub response_size: u64,
}

/// Rule-based threat detection implementation
pub struct RuleBasedThreatDetector {
    patterns: Vec<ThreatPattern>,
    user_baselines: HashMap<String, UserBaseline>,
    _failed_attempts: HashMap<String, Vec<DateTime<Utc>>>,
    _request_rates: HashMap<String, Vec<DateTime<Utc>>>,
}

impl Default for RuleBasedThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleBasedThreatDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            patterns: Vec::new(),
            user_baselines: HashMap::new(),
            _failed_attempts: HashMap::new(),
            _request_rates: HashMap::new(),
        };

        detector.initialize_default_patterns();
        detector
    }

    fn initialize_default_patterns(&mut self) {
        let patterns = vec![
            ThreatPattern {
                id: "brute_force_login".to_string(),
                name: "Brute Force Login Attack".to_string(),
                description: "Multiple failed login attempts from same IP".to_string(),
                severity: ThreatSeverity::High,
                indicators: vec![ThreatIndicator::FailedLoginAttempts {
                    count: 5,
                    window_minutes: 5,
                }],
                time_window: Duration::minutes(5),
                threshold: 5,
            },
            ThreatPattern {
                id: "sql_injection".to_string(),
                name: "SQL Injection Attack".to_string(),
                description: "Potential SQL injection in request".to_string(),
                severity: ThreatSeverity::Critical,
                indicators: vec![ThreatIndicator::SqlInjectionPattern {
                    regex_patterns: vec![
                        r"(?i)union\s+select".to_string(),
                        r"(?i)drop\s+table".to_string(),
                        r"(?i)insert\s+into".to_string(),
                        r"(?i)delete\s+from".to_string(),
                        r"(?i)'.*or.*'.*=.*'".to_string(),
                    ],
                }],
                time_window: Duration::seconds(1),
                threshold: 1,
            },
            ThreatPattern {
                id: "xss_attack".to_string(),
                name: "Cross-Site Scripting Attack".to_string(),
                description: "Potential XSS payload detected".to_string(),
                severity: ThreatSeverity::High,
                indicators: vec![ThreatIndicator::XssPattern {
                    regex_patterns: vec![
                        r"(?i)<script.*>.*</script>".to_string(),
                        r"(?i)javascript:".to_string(),
                        r"(?i)on\w+\s*=".to_string(),
                        r"(?i)<iframe.*src.*>".to_string(),
                    ],
                }],
                time_window: Duration::seconds(1),
                threshold: 1,
            },
            ThreatPattern {
                id: "rate_limit_abuse".to_string(),
                name: "Rate Limit Abuse".to_string(),
                description: "Excessive requests from single source".to_string(),
                severity: ThreatSeverity::Medium,
                indicators: vec![ThreatIndicator::RateLimitExceeded {
                    requests_per_minute: 100,
                }],
                time_window: Duration::minutes(1),
                threshold: 100,
            },
            ThreatPattern {
                id: "data_exfiltration".to_string(),
                name: "Data Exfiltration".to_string(),
                description: "Unusual large data transfer detected".to_string(),
                severity: ThreatSeverity::High,
                indicators: vec![
                    ThreatIndicator::DataExfiltration {
                        bytes_per_minute: 10_000_000,
                    }, // 10MB/min
                ],
                time_window: Duration::minutes(1),
                threshold: 1,
            },
        ];

        self.patterns = patterns;
    }

    fn _check_failed_login_attempts(&mut self, ip_address: &str) -> Option<ThreatDetection> {
        let now = Utc::now();
        let cutoff = now - Duration::minutes(5);

        // Clean old attempts
        if let Some(attempts) = self._failed_attempts.get_mut(ip_address) {
            attempts.retain(|&time| time > cutoff);
        }

        // Count recent attempts
        let recent_attempts = self
            ._failed_attempts
            .get(ip_address)
            .map(|attempts| attempts.len())
            .unwrap_or(0);

        if recent_attempts >= 5 {
            Some(ThreatDetection {
                threat_id: uuid::Uuid::new_v4().to_string(),
                threat_type: "brute_force_login".to_string(),
                severity: ThreatSeverity::High,
                confidence: 0.85,
                description: format!(
                    "Detected {} failed login attempts from IP {} in 5 minutes",
                    recent_attempts, ip_address
                ),
                details: {
                    let mut details = HashMap::new();
                    details.insert("ip_address".to_string(), ip_address.to_string());
                    details.insert("attempt_count".to_string(), recent_attempts.to_string());
                    details.insert("time_window".to_string(), "5 minutes".to_string());
                    details
                },
                recommended_actions: vec![
                    "Block IP address temporarily".to_string(),
                    "Require CAPTCHA for login".to_string(),
                    "Alert security team".to_string(),
                ],
                detected_at: now,
                source: ThreatSource::Network {
                    ip_address: ip_address.to_string(),
                },
            })
        } else {
            None
        }
    }

    fn check_sql_injection(&self, request: &RequestPattern) -> Option<ThreatDetection> {
        let patterns = vec![
            r"(?i)union\s+select",
            r"(?i)drop\s+table",
            r"(?i)insert\s+into",
            r"(?i)delete\s+from",
            r"(?i)'.*or.*'.*=.*'",
        ];

        let content = format!("{} {}", request.uri, request.body.as_deref().unwrap_or(""));

        for pattern in patterns {
            if let Some(regex) = self.safe_regex_compile(pattern) {
                if regex.is_match(&content) {
                    return Some(ThreatDetection {
                        threat_id: uuid::Uuid::new_v4().to_string(),
                        threat_type: "sql_injection".to_string(),
                        severity: ThreatSeverity::Critical,
                        confidence: 0.9,
                        description: "Potential SQL injection attack detected in request"
                            .to_string(),
                        details: {
                            let mut details = HashMap::new();
                            details.insert("ip_address".to_string(), request.ip_address.clone());
                            details.insert("uri".to_string(), request.uri.clone());
                            details.insert("matched_pattern".to_string(), pattern.to_string());
                            details
                        },
                        recommended_actions: vec![
                            "Block request immediately".to_string(),
                            "Alert security team".to_string(),
                            "Review application logs".to_string(),
                            "Consider blocking IP address".to_string(),
                        ],
                        detected_at: Utc::now(),
                        source: ThreatSource::Network {
                            ip_address: request.ip_address.clone(),
                        },
                    });
                }
            }
        }

        None
    }

    fn check_xss_attack(&self, request: &RequestPattern) -> Option<ThreatDetection> {
        let patterns = vec![
            r"(?i)<script.*>.*</script>",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            r"(?i)<iframe.*src.*>",
        ];

        let content = format!("{} {}", request.uri, request.body.as_deref().unwrap_or(""));

        for pattern in patterns {
            if let Some(regex) = self.safe_regex_compile(pattern) {
                if regex.is_match(&content) {
                    return Some(ThreatDetection {
                        threat_id: uuid::Uuid::new_v4().to_string(),
                        threat_type: "xss_attack".to_string(),
                        severity: ThreatSeverity::High,
                        confidence: 0.8,
                        description: "Potential XSS attack detected in request".to_string(),
                        details: {
                            let mut details = HashMap::new();
                            details.insert("ip_address".to_string(), request.ip_address.clone());
                            details.insert("uri".to_string(), request.uri.clone());
                            details.insert("matched_pattern".to_string(), pattern.to_string());
                            details
                        },
                        recommended_actions: vec![
                            "Sanitize input".to_string(),
                            "Block request".to_string(),
                            "Alert security team".to_string(),
                        ],
                        detected_at: Utc::now(),
                        source: ThreatSource::Network {
                            ip_address: request.ip_address.clone(),
                        },
                    });
                }
            }
        }

        None
    }

    fn _check_rate_limit(&mut self, ip_address: &str) -> Option<ThreatDetection> {
        let now = Utc::now();
        let cutoff = now - Duration::minutes(1);

        // Clean old requests
        if let Some(requests) = self._request_rates.get_mut(ip_address) {
            requests.retain(|&time| time > cutoff);
        }

        // Count recent requests
        let recent_requests = self
            ._request_rates
            .get(ip_address)
            .map(|requests| requests.len())
            .unwrap_or(0);

        if recent_requests > 100 {
            Some(ThreatDetection {
                threat_id: uuid::Uuid::new_v4().to_string(),
                threat_type: "rate_limit_abuse".to_string(),
                severity: ThreatSeverity::Medium,
                confidence: 0.7,
                description: format!(
                    "Rate limit exceeded: {} requests per minute from {}",
                    recent_requests, ip_address
                ),
                details: {
                    let mut details = HashMap::new();
                    details.insert("ip_address".to_string(), ip_address.to_string());
                    details.insert("request_count".to_string(), recent_requests.to_string());
                    details.insert("limit".to_string(), "100".to_string());
                    details
                },
                recommended_actions: vec![
                    "Apply rate limiting".to_string(),
                    "Consider temporary IP block".to_string(),
                ],
                detected_at: now,
                source: ThreatSource::Network {
                    ip_address: ip_address.to_string(),
                },
            })
        } else {
            None
        }
    }

    fn check_behavioral_anomaly(
        &self,
        user_id: &str,
        activity: &UserActivity,
    ) -> Option<ThreatDetection> {
        if let Some(baseline) = self.user_baselines.get(user_id) {
            // Check for unusual location
            if let Some(current_location) = &activity.geolocation {
                let is_unusual_location = baseline.typical_locations.iter().all(|typical| {
                    self.calculate_distance(current_location, typical) > 1000.0 // 1000km threshold
                });

                if is_unusual_location {
                    return Some(ThreatDetection {
                        threat_id: uuid::Uuid::new_v4().to_string(),
                        threat_type: "unusual_location".to_string(),
                        severity: ThreatSeverity::Medium,
                        confidence: 0.6,
                        description: format!("User {} accessing from unusual location", user_id),
                        details: {
                            let mut details = HashMap::new();
                            details.insert("user_id".to_string(), user_id.to_string());
                            details.insert(
                                "current_location".to_string(),
                                format!(
                                    "{},{}",
                                    current_location.latitude, current_location.longitude
                                ),
                            );
                            details
                        },
                        recommended_actions: vec![
                            "Require additional authentication".to_string(),
                            "Send location alert to user".to_string(),
                        ],
                        detected_at: Utc::now(),
                        source: ThreatSource::User {
                            user_id: user_id.to_string(),
                        },
                    });
                }
            }

            // Check for unusual user agent
            if !baseline.typical_user_agents.contains(&activity.user_agent) {
                return Some(ThreatDetection {
                    threat_id: uuid::Uuid::new_v4().to_string(),
                    threat_type: "unusual_user_agent".to_string(),
                    severity: ThreatSeverity::Low,
                    confidence: 0.4,
                    description: format!("User {} using unusual user agent", user_id),
                    details: {
                        let mut details = HashMap::new();
                        details.insert("user_id".to_string(), user_id.to_string());
                        details.insert("user_agent".to_string(), activity.user_agent.clone());
                        details
                    },
                    recommended_actions: vec![
                        "Monitor user activity".to_string(),
                        "Consider step-up authentication".to_string(),
                    ],
                    detected_at: Utc::now(),
                    source: ThreatSource::User {
                        user_id: user_id.to_string(),
                    },
                });
            }
        }

        None
    }

    fn calculate_distance(&self, loc1: &GeoLocation, loc2: &GeoLocation) -> f64 {
        // Simplified distance calculation (Haversine formula approximation)
        let lat_diff = (loc1.latitude - loc2.latitude).abs();
        let lon_diff = (loc1.longitude - loc2.longitude).abs();

        // Rough approximation: 111km per degree
        (lat_diff * lat_diff + lon_diff * lon_diff).sqrt() * 111.0
    }

    /// Safely compile a regex pattern, returning None on invalid patterns
    fn safe_regex_compile(&self, pattern: &str) -> Option<regex::Regex> {
        regex::Regex::new(pattern).ok()
    }
}

#[async_trait]
impl ThreatDetectionService for RuleBasedThreatDetector {
    async fn detect_authentication_threat(
        &self,
        credentials: &Credentials,
    ) -> crate::core::error::Result<Option<ThreatDetection>> {
        let ip_address = credentials.ip_address().unwrap_or_default();

        // Simulate threat detection logic
        // In a real implementation, this would check various threat indicators

        if ip_address == "192.168.1.100" {
            // Simulate a known malicious IP
            return Ok(Some(ThreatDetection {
                threat_id: uuid::Uuid::new_v4().to_string(),
                threat_type: "known_malicious_ip".to_string(),
                severity: ThreatSeverity::High,
                confidence: 0.95,
                description: "Authentication attempt from known malicious IP address".to_string(),
                details: {
                    let mut details = HashMap::new();
                    details.insert("ip_address".to_string(), ip_address);
                    details.insert(
                        "threat_intel_source".to_string(),
                        "Internal Blacklist".to_string(),
                    );
                    details
                },
                recommended_actions: vec![
                    "Block IP immediately".to_string(),
                    "Alert security team".to_string(),
                ],
                detected_at: Utc::now(),
                source: ThreatSource::Network {
                    ip_address: credentials.ip_address().unwrap_or_default(),
                },
            }));
        }

        Ok(None)
    }

    async fn detect_behavioral_anomaly(
        &self,
        user_id: &str,
        activity: &UserActivity,
    ) -> crate::core::error::Result<Option<ThreatDetection>> {
        Ok(self.check_behavioral_anomaly(user_id, activity))
    }

    async fn detect_network_threat(
        &self,
        _network_event: &NetworkEvent,
    ) -> crate::core::error::Result<Option<ThreatDetection>> {
        // Network threat detection requires enterprise features
        Err(crate::core::error::RustChainError::Security(
            "Network threat detection requires enterprise features. Use --features enterprise to enable.".to_string()
        ))
    }

    async fn analyze_request_pattern(
        &self,
        request: &RequestPattern,
    ) -> crate::core::error::Result<Option<ThreatDetection>> {
        // Check for SQL injection
        if let Some(threat) = self.check_sql_injection(request) {
            return Ok(Some(threat));
        }

        // Check for XSS
        if let Some(threat) = self.check_xss_attack(request) {
            return Ok(Some(threat));
        }

        Ok(None)
    }

    async fn get_threat_patterns(&self) -> crate::core::error::Result<Vec<ThreatPattern>> {
        Ok(self.patterns.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_detection() {
        let detector = RuleBasedThreatDetector::new();

        let request = RequestPattern {
            timestamp: Utc::now(),
            ip_address: "192.168.1.10".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            method: "POST".to_string(),
            uri: "/login".to_string(),
            body: Some("username=admin' OR '1'='1".to_string()),
            headers: HashMap::new(),
            response_code: 200,
            response_size: 1024,
        };

        let result = detector.analyze_request_pattern(&request).await.unwrap();
        assert!(result.is_some());

        let threat = result.unwrap();
        assert_eq!(threat.threat_type, "sql_injection");
        assert!(matches!(threat.severity, ThreatSeverity::Critical));
    }

    #[tokio::test]
    async fn test_xss_detection() {
        let detector = RuleBasedThreatDetector::new();

        let request = RequestPattern {
            timestamp: Utc::now(),
            ip_address: "192.168.1.10".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            method: "POST".to_string(),
            uri: "/comment".to_string(),
            body: Some("comment=<script>alert('xss')</script>".to_string()),
            headers: HashMap::new(),
            response_code: 200,
            response_size: 1024,
        };

        let result = detector.analyze_request_pattern(&request).await.unwrap();
        assert!(result.is_some());

        let threat = result.unwrap();
        assert_eq!(threat.threat_type, "xss_attack");
        assert!(matches!(threat.severity, ThreatSeverity::High));
    }
}
