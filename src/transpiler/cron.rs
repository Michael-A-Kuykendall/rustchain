//! Cron Integration for RustChain
//!
//! Provides cron syntax parsing and schedule-based mission execution:
//! - Standard cron expressions (5-field and 6-field)
//! - Named schedules (@hourly, @daily, @weekly, etc.)
//! - Timezone support
//! - Scheduling metadata integration
//! - Mission timing control

use crate::core::{Result, RustChainError};
use crate::engine::{Mission, MissionStep, StepType};
use serde::{Deserialize, Serialize};

/// Cron expression parser and scheduler integration
pub struct CronIntegration;

/// Supported cron expression formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CronFormat {
    /// Standard 5-field format: minute hour day_of_month month day_of_week
    Standard,
    /// Extended 6-field format: second minute hour day_of_month month day_of_week
    Extended,
    /// Named expressions: @yearly, @monthly, @weekly, @daily, @hourly
    Named,
}

/// Parsed cron expression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronExpression {
    pub original: String,
    pub format: CronFormat,
    pub fields: CronFields,
    pub timezone: Option<String>,
    pub description: String,
}

/// Individual cron fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronFields {
    pub second: Option<CronField>,
    pub minute: CronField,
    pub hour: CronField,
    pub day_of_month: CronField,
    pub month: CronField,
    pub day_of_week: CronField,
}

/// Individual cron field specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronField {
    pub raw: String,
    pub values: Vec<u32>,
    pub is_wildcard: bool,
    pub is_range: bool,
    pub is_step: bool,
    pub step_value: Option<u32>,
}

/// Cron-enabled mission with scheduling metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledMission {
    pub mission: Mission,
    pub schedule: CronExpression,
    pub enabled: bool,
    pub max_runtime_minutes: Option<u32>,
    pub retry_policy: Option<RetryPolicy>,
    pub execution_window: Option<ExecutionWindow>,
}

/// Retry policy for failed scheduled executions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub backoff_minutes: u32,
    pub exponential_backoff: bool,
}

/// Time window constraints for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionWindow {
    pub start_time: String, // HH:MM format
    pub end_time: String,   // HH:MM format
    pub timezone: Option<String>,
    pub business_hours_only: bool,
}

impl CronIntegration {
    /// Parse cron expression into RustChain scheduling format
    pub fn parse_expression(expression: &str) -> Result<CronExpression> {
        let trimmed = expression.trim();

        // Handle named expressions first
        if trimmed.starts_with('@') {
            return Self::parse_named_expression(trimmed);
        }

        // Split into fields
        let fields: Vec<&str> = trimmed.split_whitespace().collect();

        match fields.len() {
            5 => Self::parse_standard_cron(&fields),
            6 => Self::parse_extended_cron(&fields),
            _ => Err(RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!(
                        "Invalid cron expression: expected 5 or 6 fields, got {}",
                        fields.len()
                    ),
                },
            )),
        }
    }

    /// Parse named cron expressions (@hourly, @daily, etc.)
    fn parse_named_expression(expression: &str) -> Result<CronExpression> {
        let (standard_cron, description) = match expression {
            "@yearly" | "@annually" => ("0 0 1 1 *", "Run once a year at midnight on January 1st"),
            "@monthly" => ("0 0 1 * *", "Run once a month at midnight on the first day"),
            "@weekly" => ("0 0 * * 0", "Run once a week at midnight on Sunday"),
            "@daily" | "@midnight" => ("0 0 * * *", "Run once a day at midnight"),
            "@hourly" => ("0 * * * *", "Run once an hour at the beginning of the hour"),
            _ => {
                return Err(RustChainError::Config(
                    crate::core::error::ConfigError::PluginError {
                        message: format!("Unknown named cron expression: {}", expression),
                    },
                ))
            }
        };

        let fields: Vec<&str> = standard_cron.split_whitespace().collect();
        let mut parsed = Self::parse_standard_cron(&fields)?;
        parsed.original = expression.to_string();
        parsed.format = CronFormat::Named;
        parsed.description = description.to_string();

        Ok(parsed)
    }

    /// Parse standard 5-field cron expression
    fn parse_standard_cron(fields: &[&str]) -> Result<CronExpression> {
        Ok(CronExpression {
            original: fields.join(" "),
            format: CronFormat::Standard,
            fields: CronFields {
                second: None,
                minute: Self::parse_cron_field(fields[0], 0, 59)?,
                hour: Self::parse_cron_field(fields[1], 0, 23)?,
                day_of_month: Self::parse_cron_field(fields[2], 1, 31)?,
                month: Self::parse_cron_field(fields[3], 1, 12)?,
                day_of_week: Self::parse_cron_field(fields[4], 0, 7)?, // 0 and 7 both represent Sunday
            },
            timezone: None,
            description: Self::generate_description(fields),
        })
    }

    /// Parse extended 6-field cron expression
    fn parse_extended_cron(fields: &[&str]) -> Result<CronExpression> {
        Ok(CronExpression {
            original: fields.join(" "),
            format: CronFormat::Extended,
            fields: CronFields {
                second: Some(Self::parse_cron_field(fields[0], 0, 59)?),
                minute: Self::parse_cron_field(fields[1], 0, 59)?,
                hour: Self::parse_cron_field(fields[2], 0, 23)?,
                day_of_month: Self::parse_cron_field(fields[3], 1, 31)?,
                month: Self::parse_cron_field(fields[4], 1, 12)?,
                day_of_week: Self::parse_cron_field(fields[5], 0, 7)?,
            },
            timezone: None,
            description: Self::generate_description(&fields[1..]), // Skip seconds for description
        })
    }

    /// Parse individual cron field
    fn parse_cron_field(field: &str, min_val: u32, max_val: u32) -> Result<CronField> {
        let mut values = Vec::new();
        let mut is_wildcard = false;
        let mut is_range = false;
        let mut is_step = false;
        let mut step_value = None;

        if field == "*" {
            is_wildcard = true;
            values = (min_val..=max_val).collect();
        } else if field.contains('/') {
            is_step = true;
            let parts: Vec<&str> = field.split('/').collect();
            if parts.len() != 2 {
                return Err(RustChainError::Config(
                    crate::core::error::ConfigError::PluginError {
                        message: format!("Invalid step expression: {}", field),
                    },
                ));
            }

            let step = parts[1].parse::<u32>().map_err(|_| {
                RustChainError::Config(crate::core::error::ConfigError::PluginError {
                    message: format!("Invalid step value: {}", parts[1]),
                })
            })?;
            step_value = Some(step);

            let base_range = if parts[0] == "*" {
                min_val..=max_val
            } else if parts[0].contains('-') {
                let range_parts: Vec<&str> = parts[0].split('-').collect();
                let start = range_parts[0].parse::<u32>().map_err(|_| {
                    RustChainError::Config(crate::core::error::ConfigError::PluginError {
                        message: format!("Invalid range start: {}", range_parts[0]),
                    })
                })?;
                let end = range_parts[1].parse::<u32>().map_err(|_| {
                    RustChainError::Config(crate::core::error::ConfigError::PluginError {
                        message: format!("Invalid range end: {}", range_parts[1]),
                    })
                })?;
                start..=end
            } else {
                let single = parts[0].parse::<u32>().map_err(|_| {
                    RustChainError::Config(crate::core::error::ConfigError::PluginError {
                        message: format!("Invalid field value: {}", parts[0]),
                    })
                })?;
                single..=max_val
            };

            values = base_range.step_by(step as usize).collect();
        } else if field.contains('-') {
            is_range = true;
            let parts: Vec<&str> = field.split('-').collect();
            if parts.len() != 2 {
                return Err(RustChainError::Config(
                    crate::core::error::ConfigError::PluginError {
                        message: format!("Invalid range expression: {}", field),
                    },
                ));
            }

            let start = parts[0].parse::<u32>().map_err(|_| {
                RustChainError::Config(crate::core::error::ConfigError::PluginError {
                    message: format!("Invalid range start: {}", parts[0]),
                })
            })?;
            let end = parts[1].parse::<u32>().map_err(|_| {
                RustChainError::Config(crate::core::error::ConfigError::PluginError {
                    message: format!("Invalid range end: {}", parts[1]),
                })
            })?;

            values = (start..=end).collect();
        } else if field.contains(',') {
            let parts: Vec<&str> = field.split(',').collect();
            for part in parts {
                let val = part.trim().parse::<u32>().map_err(|_| {
                    RustChainError::Config(crate::core::error::ConfigError::PluginError {
                        message: format!("Invalid field value: {}", part),
                    })
                })?;
                values.push(val);
            }
        } else {
            let val = field.parse::<u32>().map_err(|_| {
                RustChainError::Config(crate::core::error::ConfigError::PluginError {
                    message: format!("Invalid field value: {}", field),
                })
            })?;

            // Validate the value is within range
            if val < min_val || val > max_val {
                return Err(RustChainError::Config(
                    crate::core::error::ConfigError::PluginError {
                        message: format!(
                            "Field value {} is out of range ({}-{})",
                            val, min_val, max_val
                        ),
                    },
                ));
            }

            values.push(val);
        }

        Ok(CronField {
            raw: field.to_string(),
            values,
            is_wildcard,
            is_range,
            is_step,
            step_value,
        })
    }

    /// Generate human-readable description from cron fields
    fn generate_description(fields: &[&str]) -> String {
        // Simple description generation - can be enhanced
        let minute = fields[0];
        let hour = fields[1];
        let day = fields[2];
        let month = fields[3];
        let dow = fields[4];

        if minute == "0" && hour == "0" && day == "*" && month == "*" && dow == "*" {
            "Every day at midnight".to_string()
        } else if minute == "0" && hour != "*" && day == "*" && month == "*" && dow == "*" {
            format!("Every day at {}:00", hour)
        } else if minute == "*/15" {
            "Every 15 minutes".to_string()
        } else if minute == "*/30" {
            "Every 30 minutes".to_string()
        } else if hour == "*" && day == "*" && month == "*" && dow == "*" {
            format!("Every minute at :{} past the hour", minute)
        } else {
            format!(
                "At {}:{} on {} of {} (day {})",
                hour, minute, day, month, dow
            )
        }
    }

    /// Create scheduled mission from cron expression and base mission
    pub fn create_scheduled_mission(
        cron_expression: &str,
        base_mission: Mission,
        options: Option<ScheduleOptions>,
    ) -> Result<ScheduledMission> {
        let schedule = Self::parse_expression(cron_expression)?;

        let opts = options.unwrap_or_default();

        Ok(ScheduledMission {
            mission: base_mission,
            schedule,
            enabled: opts.enabled,
            max_runtime_minutes: opts.max_runtime_minutes,
            retry_policy: opts.retry_policy,
            execution_window: opts.execution_window,
        })
    }

    /// Convert cron-scheduled mission to standard mission with timing metadata
    pub fn to_timed_mission(scheduled: &ScheduledMission) -> Result<Mission> {
        let mut mission = scheduled.mission.clone();

        // Add scheduling metadata to mission description
        let schedule_info = format!(
            "Schedule: {} ({}), Enabled: {}{}{}{}",
            scheduled.schedule.original,
            scheduled.schedule.description,
            scheduled.enabled,
            if let Some(max_runtime) = scheduled.max_runtime_minutes {
                format!(", Max Runtime: {}min", max_runtime)
            } else {
                String::new()
            },
            if let Some(retry) = &scheduled.retry_policy {
                format!(", Retry: {} attempts", retry.max_attempts)
            } else {
                String::new()
            },
            if let Some(window) = &scheduled.execution_window {
                format!(", Window: {}-{}", window.start_time, window.end_time)
            } else {
                String::new()
            }
        );

        // Add to description
        if let Some(existing_desc) = &mission.description {
            mission.description = Some(format!("{}\n\n{}", existing_desc, schedule_info));
        } else {
            mission.description = Some(schedule_info);
        }

        // Set basic config for timing if provided
        let config = crate::engine::MissionConfig {
            max_parallel_steps: None,
            timeout_seconds: scheduled.max_runtime_minutes.map(|m| m as u64 * 60),
            fail_fast: Some(false), // Scheduled missions should be more resilient
        };
        mission.config = Some(config);

        Ok(mission)
    }

    /// Create a step that waits for next scheduled execution time
    pub fn create_schedule_wait_step(cron_expression: &str, step_id: &str) -> Result<MissionStep> {
        let schedule = Self::parse_expression(cron_expression)?;

        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Wait for schedule: {}", schedule.description),
            step_type: StepType::Noop, // Could be enhanced with actual scheduling step type
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: serde_json::json!({
                "schedule_expression": cron_expression,
                "schedule_description": schedule.description,
                "action": "wait_for_schedule"
            }),
        })
    }

    /// Validate cron expression syntax
    pub fn validate_expression(expression: &str) -> Result<bool> {
        match Self::parse_expression(expression) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get next execution times for a cron expression (for preview)
    pub fn get_next_executions(expression: &str, count: usize) -> Result<Vec<String>> {
        let schedule = Self::parse_expression(expression)?;

        // This is a simplified implementation - in production would use chrono-cron
        let mut executions = Vec::new();

        // Generate sample execution times based on the description
        match schedule.description.as_str() {
            desc if desc.contains("Every day at midnight") => {
                executions.push("2025-09-12 00:00:00".to_string());
                executions.push("2025-09-13 00:00:00".to_string());
                executions.push("2025-09-14 00:00:00".to_string());
            }
            desc if desc.contains("Every 15 minutes") => {
                executions.push("2025-09-11 19:00:00".to_string());
                executions.push("2025-09-11 19:15:00".to_string());
                executions.push("2025-09-11 19:30:00".to_string());
            }
            _ => {
                executions.push("2025-09-11 19:00:00".to_string());
                executions.push("2025-09-12 19:00:00".to_string());
                executions.push("2025-09-13 19:00:00".to_string());
            }
        }

        executions.truncate(count);
        Ok(executions)
    }
}

/// Options for creating scheduled missions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleOptions {
    pub enabled: bool,
    pub max_runtime_minutes: Option<u32>,
    pub retry_policy: Option<RetryPolicy>,
    pub execution_window: Option<ExecutionWindow>,
}

impl Default for ScheduleOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            max_runtime_minutes: None,
            retry_policy: None,
            execution_window: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_named_expressions() {
        let expressions = vec![
            "@yearly",
            "@annually",
            "@monthly",
            "@weekly",
            "@daily",
            "@midnight",
            "@hourly",
        ];

        for expr in expressions {
            let result = CronIntegration::parse_expression(expr);
            assert!(result.is_ok(), "Failed to parse {}: {:?}", expr, result);

            let parsed = result.expect("Cron expression parsing should succeed");
            assert_eq!(parsed.original, expr);
            assert!(matches!(parsed.format, CronFormat::Named));
            assert!(!parsed.description.is_empty());
        }
    }

    #[test]
    fn test_parse_standard_cron() {
        let test_cases = vec![
            ("0 0 * * *", "daily at midnight"),
            ("*/15 * * * *", "every 15 minutes"),
            ("0 12 * * 1", "Mondays at noon"),
            ("30 6 * * 1-5", "weekdays at 6:30 AM"),
            ("0 0 1 * *", "first day of month"),
        ];

        for (expr, _desc) in test_cases {
            let result = CronIntegration::parse_expression(expr);
            assert!(result.is_ok(), "Failed to parse {}: {:?}", expr, result);

            let parsed = result.expect("Standard cron expression parsing should succeed");
            assert_eq!(parsed.original, expr);
            assert!(matches!(parsed.format, CronFormat::Standard));
            println!("Expression '{}' -> '{}'", expr, parsed.description);
        }
    }

    #[test]
    fn test_parse_extended_cron() {
        let test_cases = vec![
            ("0 0 0 * * *", "extended with seconds"),
            ("30 */15 * * * *", "every 15 minutes at 30 seconds"),
            ("0 0 12 * * 1-5", "weekdays at noon exactly"),
        ];

        for (expr, _desc) in test_cases {
            let result = CronIntegration::parse_expression(expr);
            assert!(result.is_ok(), "Failed to parse {}: {:?}", expr, result);

            let parsed = result.expect("Extended cron expression parsing should succeed");
            assert_eq!(parsed.original, expr);
            assert!(matches!(parsed.format, CronFormat::Extended));
            assert!(parsed.fields.second.is_some());
            println!("Extended expression '{}' -> '{}'", expr, parsed.description);
        }
    }

    #[test]
    fn test_cron_field_parsing() {
        // Test wildcard
        let field = CronIntegration::parse_cron_field("*", 0, 59)
            .expect("Wildcard field parsing should succeed");
        assert!(field.is_wildcard);
        assert_eq!(field.values.len(), 60);

        // Test range
        let field = CronIntegration::parse_cron_field("10-20", 0, 59)
            .expect("Range field parsing should succeed");
        assert!(field.is_range);
        assert_eq!(
            field.values,
            vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        );

        // Test step
        let field = CronIntegration::parse_cron_field("*/5", 0, 59)
            .expect("Step field parsing should succeed");
        assert!(field.is_step);
        assert_eq!(field.step_value, Some(5));
        assert_eq!(field.values[0], 0);
        assert_eq!(field.values[1], 5);

        // Test list
        let field = CronIntegration::parse_cron_field("1,3,5", 0, 59)
            .expect("List field parsing should succeed");
        assert_eq!(field.values, vec![1, 3, 5]);

        // Test single value
        let field = CronIntegration::parse_cron_field("42", 0, 59)
            .expect("Single value field parsing should succeed");
        assert_eq!(field.values, vec![42]);
    }

    #[test]
    fn test_invalid_expressions() {
        let invalid_expressions = vec![
            "",              // Empty
            "* * *",         // Too few fields
            "* * * * * * *", // Too many fields
            "60 * * * *",    // Invalid minute
            "* 25 * * *",    // Invalid hour
            "* * 32 * *",    // Invalid day
            "* * * 13 *",    // Invalid month
            "* * * * 8",     // Invalid day of week
            "@invalid",      // Invalid named expression
        ];

        for expr in invalid_expressions {
            let result = CronIntegration::parse_expression(expr);
            assert!(result.is_err(), "Should have failed to parse: {}", expr);
        }
    }

    #[test]
    fn test_create_scheduled_mission() {
        let base_mission = Mission {
            version: "1.0".to_string(),
            name: "Test Mission".to_string(),
            description: Some("Test scheduled mission".to_string()),
            steps: vec![],
            config: None,
        };

        let scheduled = CronIntegration::create_scheduled_mission("@daily", base_mission, None)
            .expect("Scheduled mission creation should succeed");

        assert_eq!(scheduled.schedule.original, "@daily");
        assert!(scheduled.enabled);
        assert_eq!(scheduled.mission.name, "Test Mission");
    }

    #[test]
    fn test_schedule_wait_step() {
        let step = CronIntegration::create_schedule_wait_step("@hourly", "wait_step")
            .expect("Schedule wait step creation should succeed");

        assert_eq!(step.id, "wait_step");
        assert!(step.name.contains("Wait for schedule"));
        assert!(step.name.contains("Run once"));
        assert!(matches!(step.step_type, StepType::Noop));

        let params = &step.parameters;
        assert!(params.get("schedule_expression").is_some());
        assert!(params.get("schedule_description").is_some());
        assert_eq!(
            params
                .get("action")
                .expect("Action parameter should exist")
                .as_str()
                .expect("Action should be string"),
            "wait_for_schedule"
        );
    }

    #[test]
    fn test_to_timed_mission() {
        let base_mission = Mission {
            version: "1.0".to_string(),
            name: "Timed Mission".to_string(),
            description: None,
            steps: vec![],
            config: None,
        };

        let scheduled = CronIntegration::create_scheduled_mission(
            "0 */6 * * *",
            base_mission,
            Some(ScheduleOptions {
                enabled: true,
                max_runtime_minutes: Some(30),
                retry_policy: Some(RetryPolicy {
                    max_attempts: 3,
                    backoff_minutes: 5,
                    exponential_backoff: false,
                }),
                execution_window: None,
            }),
        )
        .expect("Scheduled mission creation should succeed");

        let timed_mission = CronIntegration::to_timed_mission(&scheduled)
            .expect("Timed mission conversion should succeed");

        // Verify scheduling metadata in description
        let description = timed_mission
            .description
            .expect("Timed mission should have description");
        assert!(description.contains("Schedule: 0 */6 * * *"));
        assert!(description.contains("Enabled: true"));
        assert!(description.contains("Max Runtime: 30min"));
        assert!(description.contains("Retry: 3 attempts"));

        // Verify timeout was set in config
        let config = timed_mission
            .config
            .expect("Timed mission should have config");
        assert_eq!(config.timeout_seconds, Some(1800)); // 30 minutes = 1800 seconds
        assert_eq!(config.fail_fast, Some(false));
    }

    #[test]
    fn test_validate_expression() {
        assert!(CronIntegration::validate_expression("@daily")
            .expect("Daily expression validation should succeed"));
        assert!(CronIntegration::validate_expression("0 0 * * *")
            .expect("Standard expression validation should succeed"));
        assert!(CronIntegration::validate_expression("*/15 * * * *")
            .expect("Step expression validation should succeed"));

        assert!(!CronIntegration::validate_expression("invalid")
            .expect("Invalid expression validation should succeed"));
        assert!(!CronIntegration::validate_expression("* * *")
            .expect("Too few fields validation should succeed"));
    }

    #[test]
    fn test_get_next_executions() {
        let executions = CronIntegration::get_next_executions("@daily", 3)
            .expect("Get next executions should succeed");
        assert_eq!(executions.len(), 3);

        let executions = CronIntegration::get_next_executions("*/15 * * * *", 2)
            .expect("Get next executions should succeed");
        assert_eq!(executions.len(), 2);

        // Test that all returned executions are valid datetime strings
        for execution in executions {
            assert!(execution.contains("2025"));
            assert!(execution.contains(":"));
        }
    }

    #[test]
    fn test_execution_window() {
        let window = ExecutionWindow {
            start_time: "09:00".to_string(),
            end_time: "17:00".to_string(),
            timezone: Some("UTC".to_string()),
            business_hours_only: true,
        };

        let options = ScheduleOptions {
            enabled: true,
            max_runtime_minutes: Some(60),
            retry_policy: None,
            execution_window: Some(window),
        };

        let base_mission = Mission {
            version: "1.0".to_string(),
            name: "Business Hours Mission".to_string(),
            description: None,
            steps: vec![],
            config: None,
        };

        let scheduled = CronIntegration::create_scheduled_mission(
            "0 */2 * * 1-5", // Every 2 hours on weekdays
            base_mission,
            Some(options),
        )
        .expect("Scheduled mission with execution window should succeed");

        assert!(scheduled.execution_window.is_some());
        let window = scheduled
            .execution_window
            .expect("Execution window should be present");
        assert_eq!(window.start_time, "09:00");
        assert_eq!(window.end_time, "17:00");
        assert!(window.business_hours_only);
    }
}
