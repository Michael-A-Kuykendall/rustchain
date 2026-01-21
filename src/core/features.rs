use crate::core::{Result, RuntimeContext};
use std::collections::HashMap;

/// Feature detection and boundary enforcement utilities
/// This module provides runtime feature detection for clean community/enterprise separation
/// Enterprise feature categories with their associated capabilities
#[derive(Debug, Clone)]
pub struct FeatureRegistry {
    categories: HashMap<String, Vec<String>>,
}

impl FeatureRegistry {
    pub fn new() -> Self {
        let mut categories = HashMap::new();

        // Community Core features (available)
        categories.insert(
            "core".to_string(),
            vec![
                "mission_execution".to_string(),
                "dag_orchestration".to_string(),
                "enhanced_chain_system".to_string(),
                "agent_reasoning".to_string(),
                "tool_framework".to_string(),
                "llm_integration".to_string(),
                "safety_validation".to_string(),
                "policy_engine".to_string(),
                "audit_system".to_string(),
                "variable_scoping".to_string(),
                "async_recursion".to_string(),
            ],
        );

        // Authentication & Authorization features (enterprise)
        categories.insert(
            "auth".to_string(),
            vec![
                "jwt_auth".to_string(),
                "oauth2".to_string(),
                "rbac".to_string(),
                "multi_factor_auth".to_string(),
                "ldap_integration".to_string(),
                "saml_sso".to_string(),
            ],
        );

        // Monitoring & Performance features
        categories.insert(
            "monitoring".to_string(),
            vec![
                "prometheus_metrics".to_string(),
                "performance_dashboard".to_string(),
                "alerting_system".to_string(),
                "resource_tracking".to_string(),
                "anomaly_detection".to_string(),
                "distributed_tracing".to_string(),
                "custom_dashboards".to_string(),
            ],
        );

        // Multi-tenancy features
        categories.insert(
            "multi_tenant".to_string(),
            vec![
                "tenant_isolation".to_string(),
                "resource_quotas".to_string(),
                "tenant_specific_configs".to_string(),
                "cross_tenant_analytics".to_string(),
            ],
        );

        // Advanced AI features
        categories.insert(
            "ai_advanced".to_string(),
            vec![
                "custom_model_training".to_string(),
                "model_fine_tuning".to_string(),
                "enterprise_model_catalog".to_string(),
                "model_performance_analytics".to_string(),
            ],
        );

        Self { categories }
    }

    /// Get all features in a category
    pub fn get_category_features(&self, category: &str) -> Vec<String> {
        self.categories.get(category).cloned().unwrap_or_default()
    }

    /// Get all available feature categories
    pub fn get_categories(&self) -> Vec<String> {
        self.categories.keys().cloned().collect()
    }

    /// Check if a feature belongs to a specific category
    pub fn feature_in_category(&self, feature: &str, category: &str) -> bool {
        if let Some(features) = self.categories.get(category) {
            features.contains(&feature.to_string())
        } else {
            false
        }
    }
}

impl Default for FeatureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Feature detection result with detailed information
#[derive(Debug, Clone)]
pub struct FeatureStatus {
    pub feature: String,
    pub available: bool,
    pub category: Option<String>,
    pub reason: Option<String>,
}

/// Feature detection and enforcement utilities
pub struct FeatureDetector {
    registry: FeatureRegistry,
}

impl FeatureDetector {
    pub fn new() -> Self {
        Self {
            registry: FeatureRegistry::new(),
        }
    }

    /// Check if a feature is available through runtime detection
    pub async fn is_feature_available(
        &self,
        context: &RuntimeContext,
        feature: &str,
    ) -> FeatureStatus {
        let category = self.find_feature_category(feature);

        // Community core features are always available
        let available = if let Some(cat) = &category {
            if cat == "core" {
                true // Community features available
            } else {
                // Enterprise features check
                context.has_enterprise_feature(feature).await
            }
        } else {
            false
        };

        let reason = if available {
            None
        } else {
            Some(if let Some(_cat) = &category {
                if cfg!(feature = "enterprise") {
                    "Feature plugin not loaded".to_string()
                } else {
                    "Feature not available in this version".to_string()
                }
            } else {
                "Unknown feature".to_string()
            })
        };

        FeatureStatus {
            feature: feature.to_string(),
            available,
            category,
            reason,
        }
    }

    /// Get status for multiple features
    pub async fn get_features_status(
        &self,
        context: &RuntimeContext,
        features: Vec<&str>,
    ) -> Vec<FeatureStatus> {
        let mut statuses = Vec::new();
        for feature in features {
            statuses.push(self.is_feature_available(context, feature).await);
        }
        statuses
    }

    /// Get status for all features in a category
    pub async fn get_category_status(
        &self,
        context: &RuntimeContext,
        category: &str,
    ) -> Vec<FeatureStatus> {
        let features = self.registry.get_category_features(category);
        let feature_refs: Vec<&str> = features.iter().map(|s| s.as_str()).collect();
        self.get_features_status(context, feature_refs).await
    }

    /// Find which category a feature belongs to
    fn find_feature_category(&self, feature: &str) -> Option<String> {
        for (category, features) in &self.registry.categories {
            if features.contains(&feature.to_string()) {
                return Some(category.clone());
            }
        }
        None
    }

    /// Require a specific feature or return error
    pub async fn require_feature(&self, context: &RuntimeContext, feature: &str) -> Result<()> {
        let status = self.is_feature_available(context, feature).await;
        if status.available {
            Ok(())
        } else {
            Err(crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: status
                        .reason
                        .unwrap_or_else(|| format!("Feature '{}' not available", feature)),
                },
            ))
        }
    }

    /// Get a user-friendly feature availability summary
    pub async fn get_feature_summary(&self, context: &RuntimeContext) -> FeatureSummary {
        let mut summary = FeatureSummary {
            edition: if cfg!(feature = "enterprise") {
                "Enterprise".to_string()
            } else {
                "Community".to_string()
            },
            categories: HashMap::new(),
            total_available: 0,
            total_features: 0,
        };

        for category in self.registry.get_categories() {
            let statuses = self.get_category_status(context, &category).await;
            let available_count = statuses.iter().filter(|s| s.available).count();
            let total_count = statuses.len();

            summary.categories.insert(
                category.clone(),
                CategorySummary {
                    name: category,
                    available: available_count,
                    total: total_count,
                    features: statuses,
                },
            );

            summary.total_available += available_count;
            summary.total_features += total_count;
        }

        summary
    }
}

impl Default for FeatureDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of feature availability across categories
#[derive(Debug, Clone)]
pub struct FeatureSummary {
    pub edition: String,
    pub categories: HashMap<String, CategorySummary>,
    pub total_available: usize,
    pub total_features: usize,
}

#[derive(Debug, Clone)]
pub struct CategorySummary {
    pub name: String,
    pub available: usize,
    pub total: usize,
    pub features: Vec<FeatureStatus>,
}

impl FeatureSummary {
    /// Get availability percentage
    pub fn availability_percentage(&self) -> f64 {
        if self.total_features == 0 {
            0.0
        } else {
            (self.total_available as f64 / self.total_features as f64) * 100.0
        }
    }

    /// Check if this is a complete enterprise installation
    pub fn is_enterprise_complete(&self) -> bool {
        self.edition == "Enterprise" && self.availability_percentage() > 95.0
    }

    /// Get missing features for upgrade recommendations
    pub fn get_missing_features(&self) -> Vec<FeatureStatus> {
        let mut missing = Vec::new();
        for category in self.categories.values() {
            for feature in &category.features {
                if !feature.available {
                    missing.push(feature.clone());
                }
            }
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RuntimeContext;

    #[test]
    fn test_feature_registry_creation() {
        let registry = FeatureRegistry::new();
        let categories = registry.get_categories();

        assert!(categories.contains(&"auth".to_string()));
        assert!(categories.contains(&"monitoring".to_string()));

        let auth_features = registry.get_category_features("auth");
        assert!(auth_features.contains(&"jwt_auth".to_string()));
        assert!(auth_features.contains(&"oauth2".to_string()));
    }

    #[test]
    fn test_feature_detector_creation() {
        let detector = FeatureDetector::new();
        assert!(detector.find_feature_category("jwt_auth").is_some());
        assert!(detector.find_feature_category("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_feature_detection_community() {
        let detector = FeatureDetector::new();
        let context = RuntimeContext::new();

        // In this version, enterprise features should not be available
        let status = detector.is_feature_available(&context, "jwt_auth").await;

        assert_eq!(status.feature, "jwt_auth");
        assert_eq!(status.category, Some("auth".to_string()));

        if cfg!(not(feature = "enterprise")) {
            assert!(!status.available);
            assert!(status.reason.is_some());
        }
    }

    #[tokio::test]
    async fn test_feature_summary() {
        let detector = FeatureDetector::new();
        let context = RuntimeContext::new();

        let summary = detector.get_feature_summary(&context).await;

        assert!(summary.categories.contains_key("auth"));
        assert!(summary.categories.contains_key("monitoring"));
        assert!(summary.total_features > 0);

        if cfg!(feature = "enterprise") {
            assert_eq!(summary.edition, "Enterprise");
        } else {
            assert_eq!(summary.edition, "Community");
            assert_eq!(summary.total_available, 11); // Core features available in community
        }
    }

    #[tokio::test]
    async fn test_require_feature() {
        let detector = FeatureDetector::new();
        let context = RuntimeContext::new();

        // Test requiring a feature
        let result = detector.require_feature(&context, "jwt_auth").await;

        if cfg!(feature = "enterprise") {
            // May succeed if plugins are loaded
        } else {
            // Should fail in this version
            assert!(result.is_err());
        }
    }
}
