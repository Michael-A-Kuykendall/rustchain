//! Kubernetes Parser for RustChain
//!
//! Converts Kubernetes manifests to RustChain missions:
//! - Parse YAML manifests (Deployments, Jobs, CronJobs, Services)
//! - Extract resource definitions and dependencies  
//! - Convert to RustChain steps with appropriate timing
//! - Handle multi-resource files

use crate::core::Result;
use crate::engine::{Mission, MissionConfig, MissionStep, StepType};
use crate::transpiler::common::TranspilationContext;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Kubernetes parser for converting K8s manifests to RustChain missions
pub struct KubernetesParser;

/// Represents a Kubernetes resource from a manifest
#[derive(Debug, Clone)]
pub struct KubernetesResource {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
    pub spec: HashMap<String, Value>,
    pub dependencies: Vec<String>,
}

/// Represents a Kubernetes Job or CronJob schedule
#[derive(Debug, Clone)]
pub struct KubernetesSchedule {
    pub schedule: Option<String>, // For CronJobs
    pub job_template: Option<HashMap<String, Value>>,
    pub parallelism: Option<i32>,
    pub completions: Option<i32>,
}

impl KubernetesParser {
    /// Parse a Kubernetes manifest file and convert to RustChain mission
    pub async fn parse_file(file_path: &str) -> Result<Mission> {
        let content = tokio::fs::read_to_string(std::path::Path::new(file_path)).await?;
        Self::parse_string(&content).await
    }

    /// Parse Kubernetes manifest content from string
    pub async fn parse_string(content: &str) -> Result<Mission> {
        let mut context = TranspilationContext::new("Kubernetes Deployment Mission".to_string());

        // Parse YAML documents (supports multi-doc YAML with ---)
        let resources = Self::parse_resources(content)?;

        // Convert to RustChain steps
        let mut steps = Vec::new();
        let mut step_counter = 1;

        // Group resources by dependencies
        let ordered_resources = Self::order_resources_by_dependencies(&resources)?;

        // Create steps for each resource
        for resource in &ordered_resources {
            let step = Self::create_resource_step(resource, &format!("k8s_{}", step_counter))?;
            steps.push(step);
            step_counter += 1;

            // Add health check step for services and deployments
            if matches!(
                resource.kind.as_str(),
                "Deployment" | "Service" | "StatefulSet"
            ) {
                let health_step =
                    Self::create_health_check_step(resource, &format!("health_{}", step_counter))?;
                steps.push(health_step);
                step_counter += 1;
            }
        }

        context.add_variable("total_resources".to_string(), resources.len().to_string());
        context.add_variable(
            "resource_types".to_string(),
            Self::get_resource_types(&resources).join(","),
        );

        Ok(Mission {
            version: "1.0".to_string(),
            name: "Kubernetes Deployment Mission".to_string(),
            description: Some(format!(
                "Converted from Kubernetes manifest with {} resources: {}",
                resources.len(),
                Self::get_resource_types(&resources).join(", ")
            )),
            steps,
            config: Some(MissionConfig {
                max_parallel_steps: Some(2), // K8s deployments should be more sequential
                timeout_seconds: Some(1800), // 30 minutes for K8s operations
                fail_fast: Some(true),       // Fail fast for infrastructure
            }),
        })
    }

    /// Parse Kubernetes resources from YAML content
    fn parse_resources(content: &str) -> Result<Vec<KubernetesResource>> {
        let mut resources = Vec::new();

        // Split on YAML document separator
        let documents = content.split("---").filter(|doc| !doc.trim().is_empty());

        for doc in documents {
            if let Some(resource) = Self::parse_single_resource(doc)? {
                resources.push(resource);
            }
        }

        Ok(resources)
    }

    /// Parse a single Kubernetes resource from YAML
    fn parse_single_resource(yaml_content: &str) -> Result<Option<KubernetesResource>> {
        // Simple YAML parsing for demo - in production use serde_yaml
        let lines: Vec<&str> = yaml_content.lines().map(|l| l.trim()).collect();

        let mut api_version = String::new();
        let mut kind = String::new();
        let mut name = String::new();
        let mut namespace = None;
        let spec = HashMap::new();

        for line in lines {
            if line.starts_with("apiVersion:") {
                api_version = line.replace("apiVersion:", "").trim().to_string();
            } else if line.starts_with("kind:") {
                kind = line.replace("kind:", "").trim().to_string();
            } else if line.contains("name:") && name.is_empty() {
                name = line.replace("name:", "").trim().to_string();
            } else if line.contains("namespace:") {
                namespace = Some(line.replace("namespace:", "").trim().to_string());
            }
        }

        if api_version.is_empty() || kind.is_empty() || name.is_empty() {
            return Ok(None);
        }

        Ok(Some(KubernetesResource {
            api_version,
            kind,
            name,
            namespace,
            spec,
            dependencies: Vec::new(),
        }))
    }

    /// Order resources by dependencies (Namespaces first, then ConfigMaps, then apps)
    fn order_resources_by_dependencies(
        resources: &[KubernetesResource],
    ) -> Result<Vec<KubernetesResource>> {
        let mut ordered = Vec::new();

        // Define deployment order
        let order_priority = [
            "Namespace",
            "ConfigMap",
            "Secret",
            "PersistentVolume",
            "PersistentVolumeClaim",
            "ServiceAccount",
            "Role",
            "RoleBinding",
            "Service",
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "Job",
            "CronJob",
            "Ingress",
        ];

        for priority_kind in &order_priority {
            for resource in resources {
                if resource.kind == *priority_kind {
                    ordered.push(resource.clone());
                }
            }
        }

        // Add any remaining resources not in the priority list
        for resource in resources {
            if !ordered
                .iter()
                .any(|r| r.name == resource.name && r.kind == resource.kind)
            {
                ordered.push(resource.clone());
            }
        }

        Ok(ordered)
    }

    /// Get unique resource types from resources list
    fn get_resource_types(resources: &[KubernetesResource]) -> Vec<String> {
        let mut types: Vec<String> = resources
            .iter()
            .map(|r| r.kind.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        types.sort();
        types
    }

    /// Convert Kubernetes resource to RustChain step
    fn create_resource_step(resource: &KubernetesResource, step_id: &str) -> Result<MissionStep> {
        let step_type = Self::step_type_for(&resource.kind);
        let (timeout, continue_on_error) = Self::get_step_characteristics(&resource.kind);

        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Deploy {} {}", resource.kind, resource.name),
            step_type,
            depends_on: if resource.dependencies.is_empty() {
                None
            } else {
                Some(resource.dependencies.clone())
            },
            timeout_seconds: Some(timeout),
            continue_on_error: Some(continue_on_error),
            parameters: json!({
                "action": "apply",
                "resource_type": resource.kind,
                "resource_name": resource.name,
                "api_version": resource.api_version,
                "namespace": resource.namespace.as_deref().unwrap_or("default"),
                "kubernetes_resource": true,
                "wait_for_ready": matches!(resource.kind.as_str(), "Deployment" | "StatefulSet" | "DaemonSet")
            }),
        })
    }

    /// Create health check step for deployments and services  
    fn create_health_check_step(
        resource: &KubernetesResource,
        step_id: &str,
    ) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Health Check {} {}", resource.kind, resource.name),
            step_type: StepType::Http,
            depends_on: Some(vec![format!("k8s_deploy_{}", resource.name)]),
            timeout_seconds: Some(300),     // 5 minutes for health checks
            continue_on_error: Some(false), // Health checks should not be ignored
            parameters: json!({
                "action": "health_check",
                "resource_type": resource.kind,
                "resource_name": resource.name,
                "namespace": resource.namespace.as_deref().unwrap_or("default"),
                "method": "GET",
                "url": format!("http://{}.{}.svc.cluster.local/health",
                              resource.name,
                              resource.namespace.as_deref().unwrap_or("default")),
                "expected_status": 200,
                "retry_count": 3,
                "retry_delay": 10
            }),
        })
    }

    /// Map Kubernetes resource types to RustChain step types
    fn step_type_for(kind: &str) -> StepType {
        match kind {
            "ConfigMap" | "Secret" => StepType::CreateFile, // Create config
            "Namespace" => StepType::Noop, // Namespace creation is usually idempotent
            "Job" => StepType::Command,    // Jobs are essentially commands
            "CronJob" => StepType::Noop,   // CronJobs define schedules
            "Deployment" | "StatefulSet" | "DaemonSet" => StepType::Http, // API calls
            "Service" | "Ingress" => StepType::Http, // Network resources
            "PersistentVolume" | "PersistentVolumeClaim" => StepType::Http, // Storage
            _ => StepType::Http,           // Default to HTTP for K8s API calls
        }
    }

    /// Get step characteristics (timeout, error handling) based on resource type
    fn get_step_characteristics(kind: &str) -> (u64, bool) {
        match kind {
            "Namespace" | "ConfigMap" | "Secret" => (60, false), // Fast, critical
            "Job" => (1800, true),                               // Slow, can continue on error
            "Deployment" | "StatefulSet" => (600, false),        // Medium, critical
            "Service" | "Ingress" => (120, false),               // Fast, critical
            "PersistentVolume" | "PersistentVolumeClaim" => (300, false), // Medium, critical
            _ => (300, false), // Default: medium timeout, critical
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_simple_deployment() {
        let k8s_manifest = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
        "#;

        let result = KubernetesParser::parse_string(k8s_manifest).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert_eq!(mission.name, "Kubernetes Deployment Mission");
        assert!(!mission.steps.is_empty()); // At least deployment step

        // Check that we have a deployment step
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names
            .iter()
            .any(|name| name.contains("Deployment") && name.contains("nginx-deployment")));
    }

    #[tokio::test]
    async fn test_parse_multi_resource_manifest() {
        let k8s_manifest = r#"
apiVersion: v1
kind: Namespace
metadata:
  name: test-namespace
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: test-namespace
data:
  config.yml: |
    app:
      name: test-app
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deployment
  namespace: test-namespace
spec:
  replicas: 2
        "#;

        let result = KubernetesParser::parse_string(k8s_manifest).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert!(mission.steps.len() >= 3); // Namespace + ConfigMap + Deployment
        assert!(mission.description.unwrap().contains("3 resources"));

        // Check resource types are captured
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names.iter().any(|name| name.contains("Namespace")));
        assert!(step_names.iter().any(|name| name.contains("ConfigMap")));
        assert!(step_names.iter().any(|name| name.contains("Deployment")));
    }

    #[test]
    fn test_resource_ordering() {
        let resources = vec![
            KubernetesResource {
                api_version: "apps/v1".to_string(),
                kind: "Deployment".to_string(),
                name: "app".to_string(),
                namespace: None,
                spec: HashMap::new(),
                dependencies: vec![],
            },
            KubernetesResource {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                name: "config".to_string(),
                namespace: None,
                spec: HashMap::new(),
                dependencies: vec![],
            },
            KubernetesResource {
                api_version: "v1".to_string(),
                kind: "Namespace".to_string(),
                name: "test".to_string(),
                namespace: None,
                spec: HashMap::new(),
                dependencies: vec![],
            },
        ];

        let ordered = KubernetesParser::order_resources_by_dependencies(&resources).unwrap();

        // Namespace should be first, ConfigMap second, Deployment third
        assert_eq!(ordered[0].kind, "Namespace");
        assert_eq!(ordered[1].kind, "ConfigMap");
        assert_eq!(ordered[2].kind, "Deployment");
    }

    #[test]
    fn test_step_type_mapping() {
        assert!(matches!(
            KubernetesParser::step_type_for("Deployment"),
            StepType::Http
        ));
        assert!(matches!(
            KubernetesParser::step_type_for("ConfigMap"),
            StepType::CreateFile
        ));
        assert!(matches!(
            KubernetesParser::step_type_for("Job"),
            StepType::Command
        ));
        assert!(matches!(
            KubernetesParser::step_type_for("Service"),
            StepType::Http
        ));
    }

    #[test]
    fn test_step_characteristics() {
        let (timeout, continue_on_error) = KubernetesParser::get_step_characteristics("Job");
        assert_eq!(timeout, 1800); // Jobs can take a while
        assert!(continue_on_error); // Jobs can fail and we can continue

        let (timeout, continue_on_error) = KubernetesParser::get_step_characteristics("Deployment");
        assert_eq!(timeout, 600); // Deployments are medium speed
        assert!(!continue_on_error); // Deployment failures are critical
    }

    #[tokio::test]
    async fn test_empty_manifest() {
        let result = KubernetesParser::parse_string("").await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert_eq!(mission.steps.len(), 0);
        assert!(mission.description.unwrap().contains("0 resources"));
    }

    #[tokio::test]
    async fn test_cronjob_parsing() {
        let k8s_manifest = r#"
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-job
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: backup:latest
            command: ["/bin/bash", "-c", "backup-script.sh"]
          restartPolicy: Never
        "#;

        let result = KubernetesParser::parse_string(k8s_manifest).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert!(!mission.steps.is_empty());

        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names
            .iter()
            .any(|name| name.contains("CronJob") && name.contains("backup-job")));
    }
}
