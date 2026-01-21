use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Required field '{field}' is missing")]
    Required { field: String },

    #[error("Field '{field}' has invalid format: {reason}")]
    InvalidFormat { field: String, reason: String },

    #[error("Field '{field}' exceeds maximum length of {max_length}")]
    TooLong { field: String, max_length: usize },

    #[error("Field '{field}' is below minimum length of {min_length}")]
    TooShort { field: String, min_length: usize },

    #[error("Field '{field}' value '{value}' is not in allowed list")]
    NotInAllowedList { field: String, value: String },

    #[error("Field '{field}' contains prohibited characters")]
    ProhibitedCharacters { field: String },

    #[error("Field '{field}' has invalid pattern")]
    InvalidPattern { field: String },

    #[error("Multiple validation errors: {errors:?}")]
    Multiple { errors: Vec<ValidationError> },
}

pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    pub required: bool,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub allowed_values: Option<Vec<String>>,
    pub prohibited_chars: Option<Vec<char>>,
}

impl Default for ValidationRule {
    fn default() -> Self {
        Self {
            required: false,
            min_length: None,
            max_length: None,
            pattern: None,
            allowed_values: None,
            prohibited_chars: Some(vec!['<', '>', '&', '"', '\'']), // Basic XSS protection
        }
    }
}

pub struct InputValidator {
    rules: HashMap<String, ValidationRule>,
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl InputValidator {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    pub fn add_rule<S: Into<String>>(mut self, field: S, rule: ValidationRule) -> Self {
        self.rules.insert(field.into(), rule);
        self
    }

    pub fn validate_string(&self, field: &str, value: Option<&str>) -> ValidationResult<()> {
        let default_rule = ValidationRule::default();
        let rule = self.rules.get(field).unwrap_or(&default_rule);

        // Check if required
        if rule.required && value.is_none() {
            return Err(ValidationError::Required {
                field: field.to_string(),
            });
        }

        if let Some(string_value) = value {
            // Check length constraints
            if let Some(min_len) = rule.min_length {
                if string_value.len() < min_len {
                    return Err(ValidationError::TooShort {
                        field: field.to_string(),
                        min_length: min_len,
                    });
                }
            }

            if let Some(max_len) = rule.max_length {
                if string_value.len() > max_len {
                    return Err(ValidationError::TooLong {
                        field: field.to_string(),
                        max_length: max_len,
                    });
                }
            }

            // Check allowed values
            if let Some(allowed) = &rule.allowed_values {
                if !allowed.contains(&string_value.to_string()) {
                    return Err(ValidationError::NotInAllowedList {
                        field: field.to_string(),
                        value: string_value.to_string(),
                    });
                }
            }

            // Check prohibited characters
            if let Some(prohibited) = &rule.prohibited_chars {
                for &ch in prohibited {
                    if string_value.contains(ch) {
                        return Err(ValidationError::ProhibitedCharacters {
                            field: field.to_string(),
                        });
                    }
                }
            }

            // Check pattern
            #[cfg(feature = "transpiler")]
            if let Some(pattern) = &rule.pattern {
                let regex =
                    regex::Regex::new(pattern).map_err(|_| ValidationError::InvalidPattern {
                        field: field.to_string(),
                    })?;

                if !regex.is_match(string_value) {
                    return Err(ValidationError::InvalidFormat {
                        field: field.to_string(),
                        reason: format!("does not match pattern: {}", pattern),
                    });
                }
            }

            // Fallback for when regex is not available
            #[cfg(not(feature = "transpiler"))]
            if rule.pattern.is_some() {
                // Basic pattern matching without regex - just check if pattern is set
                // This provides compatibility when transpiler feature is disabled
                return Err(ValidationError::InvalidFormat {
                    field: field.to_string(),
                    reason: "Pattern validation requires transpiler feature".to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn validate_mission_input(&self, input: &serde_json::Value) -> ValidationResult<()> {
        let mut errors = Vec::new();

        if let Some(json_object) = input.as_object() {
            for (key, value) in json_object {
                let string_value = value.as_str();
                if let Err(e) = self.validate_string(key, string_value) {
                    errors.push(e);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.remove(0))
        } else {
            Err(ValidationError::Multiple { errors })
        }
    }
}

pub fn create_mission_validator() -> InputValidator {
    InputValidator::new()
        .add_rule(
            "name",
            ValidationRule {
                required: true,
                min_length: Some(1),
                max_length: Some(100),
                pattern: Some(r"^[a-zA-Z0-9\s\-_]+$".to_string()),
                ..Default::default()
            },
        )
        .add_rule(
            "version",
            ValidationRule {
                required: true,
                pattern: Some(r"^\d+\.\d+(\.\d+)?$".to_string()),
                ..Default::default()
            },
        )
        .add_rule(
            "description",
            ValidationRule {
                max_length: Some(1000),
                ..Default::default()
            },
        )
}

pub fn create_tool_input_validator() -> InputValidator {
    InputValidator::new()
        .add_rule(
            "tool_name",
            ValidationRule {
                required: true,
                min_length: Some(1),
                max_length: Some(50),
                pattern: Some(r"^[a-zA-Z0-9_]+$".to_string()),
                ..Default::default()
            },
        )
        .add_rule(
            "command",
            ValidationRule {
                max_length: Some(500),
                prohibited_chars: Some(vec!['&', '|', ';', '`', '$']),
                ..Default::default()
            },
        )
        .add_rule(
            "file_path",
            ValidationRule {
                max_length: Some(255),
                prohibited_chars: Some(vec!['<', '>', ':', '"', '|', '?', '*']),
                ..Default::default()
            },
        )
}

pub fn create_api_input_validator() -> InputValidator {
    InputValidator::new()
        .add_rule(
            "api_key",
            ValidationRule {
                required: true,
                min_length: Some(16),
                max_length: Some(128),
                pattern: Some(r"^[a-zA-Z0-9\-_]+$".to_string()),
                ..Default::default()
            },
        )
        .add_rule(
            "endpoint",
            ValidationRule {
                required: true,
                pattern: Some(r"^/[a-zA-Z0-9\-_/]*$".to_string()),
                max_length: Some(200),
                ..Default::default()
            },
        )
        .add_rule(
            "user_input",
            ValidationRule {
                max_length: Some(10000),
                prohibited_chars: Some(vec!['<', '>', '&', '"', '\'']),
                ..Default::default()
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_field_validation() {
        let validator = InputValidator::new().add_rule(
            "required_field",
            ValidationRule {
                required: true,
                ..Default::default()
            },
        );

        assert!(validator.validate_string("required_field", None).is_err());
        assert!(validator
            .validate_string("required_field", Some("value"))
            .is_ok());
    }

    #[test]
    fn test_length_validation() {
        let validator = InputValidator::new().add_rule(
            "length_field",
            ValidationRule {
                min_length: Some(3),
                max_length: Some(10),
                ..Default::default()
            },
        );

        assert!(validator
            .validate_string("length_field", Some("ab"))
            .is_err());
        assert!(validator
            .validate_string("length_field", Some("abc"))
            .is_ok());
        assert!(validator
            .validate_string("length_field", Some("abcdefghijk"))
            .is_err());
    }

    #[test]
    fn test_prohibited_characters() {
        let validator = InputValidator::new().add_rule(
            "safe_field",
            ValidationRule {
                prohibited_chars: Some(vec!['<', '>', '&']),
                ..Default::default()
            },
        );

        assert!(validator
            .validate_string("safe_field", Some("safe text"))
            .is_ok());
        assert!(validator
            .validate_string("safe_field", Some("unsafe <script>"))
            .is_err());
        assert!(validator
            .validate_string("safe_field", Some("unsafe & dangerous"))
            .is_err());
    }

    #[test]
    fn test_pattern_validation() {
        let validator = InputValidator::new().add_rule(
            "version",
            ValidationRule {
                pattern: Some(r"^\d+\.\d+\.\d+$".to_string()),
                ..Default::default()
            },
        );

        assert!(validator.validate_string("version", Some("1.0.0")).is_ok());
        assert!(validator
            .validate_string("version", Some("invalid"))
            .is_err());
    }

    #[test]
    fn test_mission_validator() {
        let validator = create_mission_validator();

        let valid_mission = serde_json::json!({
            "name": "Valid Mission",
            "version": "1.0.0",
            "description": "A valid mission description"
        });

        assert!(validator.validate_mission_input(&valid_mission).is_ok());

        let invalid_mission = serde_json::json!({
            "name": "Invalid<script>",
            "version": "invalid_version"
        });

        assert!(validator.validate_mission_input(&invalid_mission).is_err());
    }

    #[test]
    fn test_tool_input_validator() {
        let validator = create_tool_input_validator();

        assert!(validator
            .validate_string("tool_name", Some("valid_tool"))
            .is_ok());
        assert!(validator
            .validate_string("tool_name", Some("invalid-tool!"))
            .is_err());

        assert!(validator.validate_string("command", Some("ls -la")).is_ok());
        assert!(validator
            .validate_string("command", Some("rm -rf / && evil"))
            .is_err());
    }
}
