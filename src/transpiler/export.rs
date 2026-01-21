//! Export Engine Foundation for RustChain
//!
//! Universal export architecture for converting RustChain missions to various formats:
//! - GitHub Actions workflows
//! - Terraform configurations
//! - Kubernetes manifests
//! - Jenkins pipelines
//! - Docker Compose files
//! - And more...

use crate::core::{Result, RustChainError};
use crate::engine::{Mission, MissionStep, StepType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Universal export engine for RustChain missions
pub struct ExportEngine;

/// Supported export formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    GitHubActions,
    Terraform,
    Kubernetes,
    Jenkins,
    DockerCompose,
    AnsiblePlaybook,
    AzureDevOps,
    CircleCI,
    BashScript,
}

/// Export configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub format: ExportFormat,
    pub target_version: Option<String>,
    pub include_comments: bool,
    pub optimize_for_readability: bool,
    pub custom_templates: HashMap<String, String>,
    pub environment_variables: HashMap<String, String>,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            format: ExportFormat::GitHubActions,
            target_version: None,
            include_comments: true,
            optimize_for_readability: true,
            custom_templates: HashMap::new(),
            environment_variables: HashMap::new(),
        }
    }
}

impl ExportEngine {
    /// Export a RustChain mission to the specified format
    pub async fn export_mission(mission: &Mission, config: &ExportConfig) -> Result<String> {
        match config.format {
            ExportFormat::GitHubActions => Self::export_to_github_actions(mission, config),
            ExportFormat::Terraform => Self::export_to_terraform(mission, config),
            ExportFormat::Kubernetes => Self::export_to_kubernetes(mission, config),
            ExportFormat::Jenkins => Self::export_to_jenkins(mission, config),
            ExportFormat::DockerCompose => Self::export_to_docker_compose(mission, config),
            ExportFormat::BashScript => Self::export_to_bash_script(mission, config),
            _ => Err(RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!("Export format {:?} not yet implemented", config.format),
                },
            )),
        }
    }

    /// Export RustChain mission to GitHub Actions workflow
    pub fn export_to_github_actions(mission: &Mission, config: &ExportConfig) -> Result<String> {
        let mut workflow = String::new();

        // Workflow header
        workflow.push_str(&format!("name: '{}'\n\n", mission.name));

        // Add trigger configuration
        workflow.push_str("on:\n");
        workflow.push_str("  workflow_dispatch:\n");
        workflow.push_str("  push:\n");
        workflow.push_str("    branches: [ main ]\n\n");

        // Add environment variables if specified
        if !config.environment_variables.is_empty() {
            workflow.push_str("env:\n");
            for (key, value) in &config.environment_variables {
                workflow.push_str(&format!("  {}: {}\n", key, value));
            }
            workflow.push('\n');
        }

        // Jobs section
        workflow.push_str("jobs:\n");
        workflow.push_str("  rustchain-mission:\n");
        workflow.push_str("    runs-on: ubuntu-latest\n");

        if config.include_comments {
            workflow.push_str(&format!(
                "    # Generated from RustChain mission: {}\n",
                mission.name
            ));
            if let Some(desc) = &mission.description {
                workflow.push_str(&format!("    # Description: {}\n", desc));
            }
        }

        workflow.push_str("    steps:\n");

        // Convert each mission step to GitHub Actions step
        for (index, step) in mission.steps.iter().enumerate() {
            let gh_step = Self::to_github_actions(step, config)?;
            workflow.push_str(&Self::indent_yaml(&gh_step, 6));

            if index < mission.steps.len() - 1 {
                workflow.push('\n');
            }
        }

        Ok(workflow)
    }

    /// Export RustChain mission to Terraform configuration
    pub fn export_to_terraform(mission: &Mission, config: &ExportConfig) -> Result<String> {
        let mut terraform = String::new();

        // Terraform configuration header
        if config.include_comments {
            terraform.push_str(&format!(
                "# Generated from RustChain mission: {}\n",
                mission.name
            ));
            if let Some(desc) = &mission.description {
                terraform.push_str(&format!("# Description: {}\n", desc));
            }
            terraform.push_str("#\n");
            terraform.push_str("# This Terraform configuration implements the RustChain mission\n");
            terraform.push_str("# as infrastructure-as-code resources\n\n");
        }

        // Terraform provider configuration
        terraform.push_str("terraform {\n");
        terraform.push_str("  required_providers {\n");
        terraform.push_str("    local = {\n");
        terraform.push_str("      source  = \"hashicorp/local\"\n");
        terraform.push_str("      version = \"~> 2.0\"\n");
        terraform.push_str("    }\n");
        terraform.push_str("    null = {\n");
        terraform.push_str("      source  = \"hashicorp/null\"\n");
        terraform.push_str("      version = \"~> 3.0\"\n");
        terraform.push_str("    }\n");
        terraform.push_str("  }\n");
        terraform.push_str("}\n\n");

        // Convert each mission step to Terraform resource
        for step in &mission.steps {
            let tf_resource = Self::to_terraform(step, config)?;
            terraform.push_str(&tf_resource);
            terraform.push('\n');
            terraform.push('\n');
        }

        // Add outputs for important values
        terraform.push_str("# Mission execution outputs\n");
        terraform.push_str("output \"mission_name\" {\n");
        terraform.push_str("  description = \"Name of the executed RustChain mission\"\n");
        terraform.push_str(&format!("  value       = \"{}\"\n", mission.name));
        terraform.push_str("}\n\n");

        terraform.push_str("output \"steps_count\" {\n");
        terraform.push_str("  description = \"Number of steps in the mission\"\n");
        terraform.push_str(&format!("  value       = {}\n", mission.steps.len()));
        terraform.push_str("}\n");

        Ok(terraform)
    }

    /// Export RustChain mission to Kubernetes manifests
    pub fn export_to_kubernetes(mission: &Mission, config: &ExportConfig) -> Result<String> {
        let mut k8s = String::new();

        if config.include_comments {
            k8s.push_str(&format!(
                "# Generated from RustChain mission: {}\n",
                mission.name
            ));
            k8s.push_str("# Kubernetes Job manifest\n");
            k8s.push_str("---\n");
        }

        // Kubernetes Job manifest
        k8s.push_str("apiVersion: batch/v1\n");
        k8s.push_str("kind: Job\n");
        k8s.push_str("metadata:\n");
        k8s.push_str(&format!(
            "  name: {}\n",
            Self::sanitize_k8s_name(&mission.name)
        ));
        k8s.push_str("  labels:\n");
        k8s.push_str("    app: rustchain-mission\n");
        k8s.push_str(&format!(
            "    mission: {}\n",
            Self::sanitize_k8s_name(&mission.name)
        ));
        k8s.push_str("spec:\n");
        k8s.push_str("  template:\n");
        k8s.push_str("    spec:\n");
        k8s.push_str("      restartPolicy: OnFailure\n");
        k8s.push_str("      containers:\n");
        k8s.push_str("      - name: rustchain-executor\n");
        k8s.push_str("        image: rustchain/executor:latest\n");
        k8s.push_str("        command: [\"/bin/sh\"]\n");
        k8s.push_str("        args:\n");
        k8s.push_str("        - -c\n");
        k8s.push_str("        - |\n");

        // Convert steps to shell commands
        for step in &mission.steps {
            let shell_command = Self::to_shell_command(step)?;
            k8s.push_str(&format!(
                "          echo \"Executing step: {}\"\n",
                step.name
            ));
            k8s.push_str(&format!("          {}\n", shell_command));
        }

        k8s.push_str("        env:\n");
        for (key, value) in &config.environment_variables {
            k8s.push_str(&format!("        - name: {}\n", key));
            k8s.push_str(&format!("          value: \"{}\"\n", value));
        }

        Ok(k8s)
    }

    /// Export RustChain mission to Jenkins pipeline
    pub fn export_to_jenkins(mission: &Mission, config: &ExportConfig) -> Result<String> {
        let mut jenkins = String::new();

        // Jenkinsfile header
        jenkins.push_str("pipeline {\n");
        jenkins.push_str("    agent any\n\n");

        // Environment variables
        if !config.environment_variables.is_empty() {
            jenkins.push_str("    environment {\n");
            for (key, value) in &config.environment_variables {
                jenkins.push_str(&format!("        {} = '{}'\n", key, value));
            }
            jenkins.push_str("    }\n\n");
        }

        jenkins.push_str("    stages {\n");

        // Convert each step to Jenkins stage
        for step in &mission.steps {
            jenkins.push_str(&format!("        stage('{}') {{\n", step.name));
            jenkins.push_str("            steps {\n");

            let command = Self::to_shell_command(step)?;
            jenkins.push_str(&format!(
                "                sh '{}'\n",
                command.replace("'", "\\'")
            ));

            jenkins.push_str("            }\n");
            jenkins.push_str("        }\n");
        }

        jenkins.push_str("    }\n");

        // Post-build actions
        jenkins.push_str("\n    post {\n");
        jenkins.push_str("        always {\n");
        jenkins.push_str("            echo 'RustChain mission execution completed'\n");
        jenkins.push_str("        }\n");
        jenkins.push_str("        success {\n");
        jenkins.push_str("            echo 'Mission completed successfully'\n");
        jenkins.push_str("        }\n");
        jenkins.push_str("        failure {\n");
        jenkins.push_str("            echo 'Mission failed'\n");
        jenkins.push_str("        }\n");
        jenkins.push_str("    }\n");
        jenkins.push_str("}\n");

        Ok(jenkins)
    }

    /// Export RustChain mission to Docker Compose
    pub fn export_to_docker_compose(mission: &Mission, config: &ExportConfig) -> Result<String> {
        let mut compose = String::new();

        compose.push_str("version: '3.8'\n\n");

        if config.include_comments {
            compose.push_str(&format!(
                "# Generated from RustChain mission: {}\n",
                mission.name
            ));
            compose.push_str("# Docker Compose configuration\n\n");
        }

        compose.push_str("services:\n");

        // Create a service for the mission execution
        compose.push_str(&format!(
            "  {}:\n",
            Self::sanitize_service_name(&mission.name)
        ));
        compose.push_str("    image: rustchain/executor:latest\n");
        compose.push_str("    container_name: rustchain-mission\n");

        // Environment variables
        if !config.environment_variables.is_empty() {
            compose.push_str("    environment:\n");
            for (key, value) in &config.environment_variables {
                compose.push_str(&format!("      - {}={}\n", key, value));
            }
        }

        // Generate startup command
        let mut commands = Vec::new();
        for step in &mission.steps {
            let cmd = Self::to_shell_command(step)?;
            commands.push(cmd);
        }

        compose.push_str("    command: >\n");
        compose.push_str("      bash -c '\n");
        for cmd in commands {
            compose.push_str(&format!("        {} &&\n", cmd));
        }
        compose.push_str("        echo \"Mission completed successfully\"'\n");

        Ok(compose)
    }

    /// Export RustChain mission to Bash script
    pub fn export_to_bash_script(mission: &Mission, config: &ExportConfig) -> Result<String> {
        let mut script = String::new();

        // Bash script header
        script.push_str("#!/bin/bash\n");
        script.push_str("set -euo pipefail\n\n");

        if config.include_comments {
            script.push_str(&format!(
                "# Generated from RustChain mission: {}\n",
                mission.name
            ));
            if let Some(desc) = &mission.description {
                script.push_str(&format!("# Description: {}\n", desc));
            }
            script.push_str("# This script implements the RustChain mission as a bash script\n\n");
        }

        // Environment variables
        if !config.environment_variables.is_empty() {
            script.push_str("# Environment variables\n");
            for (key, value) in &config.environment_variables {
                script.push_str(&format!("export {}=\"{}\"\n", key, value));
            }
            script.push('\n');
        }

        // Mission execution function
        script.push_str("execute_mission() {\n");
        script.push_str(&format!(
            "    echo \"Starting RustChain mission: {}\"\n",
            mission.name
        ));
        script.push_str("    \n");

        // Convert each step to shell command
        for (index, step) in mission.steps.iter().enumerate() {
            script.push_str(&format!("    # Step {}: {}\n", index + 1, step.name));
            script.push_str(&format!("    echo \"Executing step: {}\"\n", step.name));

            let command = Self::to_shell_command(step)?;
            script.push_str(&format!("    {}\n", command));
            script.push_str("    \n");
        }

        script.push_str("    echo \"Mission completed successfully\"\n");
        script.push_str("}\n\n");

        // Error handling
        script.push_str("# Error handling\n");
        script.push_str("trap 'echo \"Mission failed at step $STEP_NUMBER\"; exit 1' ERR\n\n");

        // Main execution
        script.push_str("# Execute the mission\n");
        script.push_str("execute_mission\n");

        Ok(script)
    }

    /// Convert a RustChain step to GitHub Actions step format
    fn to_github_actions(step: &MissionStep, _config: &ExportConfig) -> Result<String> {
        let mut gh_step = String::new();

        gh_step.push_str(&format!("- name: '{}'\n", step.name));

        match step.step_type {
            StepType::Command => {
                if let Some(command) = step.parameters.get("command") {
                    let cmd = command.as_str().unwrap_or("");
                    let args = step
                        .parameters
                        .get("args")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();

                    gh_step.push_str(&format!("  run: {} {}\n", cmd, args));
                } else {
                    gh_step.push_str("  run: echo 'No command specified'\n");
                }
            }
            StepType::CreateFile => {
                if let Some(path) = step.parameters.get("path") {
                    let content = step
                        .parameters
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("");
                    gh_step.push_str(&format!(
                        "  run: |\n    cat > {} << 'EOF'\n    {}\n    EOF\n",
                        path.as_str().unwrap_or(""),
                        content
                    ));
                }
            }
            StepType::Http => {
                if let Some(url) = step.parameters.get("url") {
                    let method = step
                        .parameters
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or("GET");
                    gh_step.push_str(&format!(
                        "  run: curl -X {} {}\n",
                        method,
                        url.as_str().unwrap_or("")
                    ));
                }
            }
            _ => {
                gh_step.push_str(&format!(
                    "  run: echo 'Step type {:?} not yet supported in GitHub Actions export'\n",
                    step.step_type
                ));
            }
        }

        Ok(gh_step)
    }

    /// Convert a RustChain step to Terraform resource
    fn to_terraform(step: &MissionStep, _config: &ExportConfig) -> Result<String> {
        let mut tf_resource = String::new();

        let resource_name = Self::sanitize_terraform_name(&step.id);

        match step.step_type {
            StepType::Command => {
                tf_resource.push_str(&format!(
                    "resource \"null_resource\" \"{}\" {{\n",
                    resource_name
                ));
                tf_resource.push_str("  provisioner \"local-exec\" {\n");

                if let Some(command) = step.parameters.get("command") {
                    let cmd = command.as_str().unwrap_or("");
                    let args = step
                        .parameters
                        .get("args")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();

                    tf_resource.push_str(&format!("    command = \"{} {}\"\n", cmd, args));
                }

                tf_resource.push_str("  }\n");
                tf_resource.push('}');
            }
            StepType::CreateFile => {
                tf_resource.push_str(&format!(
                    "resource \"local_file\" \"{}\" {{\n",
                    resource_name
                ));
                if let Some(path) = step.parameters.get("path") {
                    tf_resource.push_str(&format!(
                        "  filename = \"{}\"\n",
                        path.as_str().unwrap_or("")
                    ));
                }
                if let Some(content) = step.parameters.get("content") {
                    tf_resource.push_str(&format!(
                        "  content  = \"{}\"\n",
                        content.as_str().unwrap_or("").replace("\"", "\\\"")
                    ));
                }
                tf_resource.push('}');
            }
            _ => {
                tf_resource.push_str(&format!(
                    "# Step type {:?} not yet supported in Terraform export\n",
                    step.step_type
                ));
                tf_resource.push_str(&format!(
                    "resource \"null_resource\" \"{}\" {{\n",
                    resource_name
                ));
                tf_resource.push_str("  provisioner \"local-exec\" {\n");
                tf_resource.push_str(&format!("    command = \"echo 'Step: {}'\"\n", step.name));
                tf_resource.push_str("  }\n");
                tf_resource.push('}');
            }
        }

        Ok(tf_resource)
    }

    /// Convert a RustChain step to shell command
    fn to_shell_command(step: &MissionStep) -> Result<String> {
        match step.step_type {
            StepType::Command => {
                if let Some(command) = step.parameters.get("command") {
                    let cmd = command.as_str().unwrap_or("");
                    let args = step
                        .parameters
                        .get("args")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();

                    Ok(format!("{} {}", cmd, args))
                } else {
                    Ok("echo 'No command specified'".to_string())
                }
            }
            StepType::CreateFile => {
                if let Some(path) = step.parameters.get("path") {
                    let content = step
                        .parameters
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("");
                    Ok(format!(
                        "cat > {} << 'EOF'\n{}\nEOF",
                        path.as_str().unwrap_or(""),
                        content
                    ))
                } else {
                    Ok("echo 'No file path specified'".to_string())
                }
            }
            StepType::Http => {
                if let Some(url) = step.parameters.get("url") {
                    let method = step
                        .parameters
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or("GET");
                    Ok(format!("curl -X {} {}", method, url.as_str().unwrap_or("")))
                } else {
                    Ok("echo 'No URL specified'".to_string())
                }
            }
            StepType::Noop => Ok(format!("echo 'NOOP: {}'", step.name)),
            _ => Ok(format!(
                "echo 'Step type {:?} not yet supported in shell export'",
                step.step_type
            )),
        }
    }

    /// Utility functions for name sanitization
    fn sanitize_k8s_name(name: &str) -> String {
        name.to_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .trim_matches('-')
            .to_string()
    }

    fn sanitize_service_name(name: &str) -> String {
        name.to_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .trim_matches('-')
            .to_string()
    }

    fn sanitize_terraform_name(name: &str) -> String {
        name.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_string()
    }

    fn indent_yaml(content: &str, spaces: usize) -> String {
        let indent = " ".repeat(spaces);
        content
            .lines()
            .map(|line| {
                if line.trim().is_empty() {
                    line.to_string()
                } else {
                    format!("{}{}", indent, line)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::StepType;

    fn create_test_mission() -> Mission {
        Mission {
            version: "1.0".to_string(),
            name: "Test Export Mission".to_string(),
            description: Some("A test mission for export functionality".to_string()),
            steps: vec![
                MissionStep {
                    id: "step1".to_string(),
                    name: "Create Test File".to_string(),
                    step_type: StepType::CreateFile,
                    depends_on: None,
                    timeout_seconds: None,
                    continue_on_error: Some(false),
                    parameters: serde_json::json!({
                        "path": "/tmp/test.txt",
                        "content": "Hello, World!"
                    }),
                },
                MissionStep {
                    id: "step2".to_string(),
                    name: "List Files".to_string(),
                    step_type: StepType::Command,
                    depends_on: Some(vec!["step1".to_string()]),
                    timeout_seconds: None,
                    continue_on_error: Some(false),
                    parameters: serde_json::json!({
                        "command": "ls",
                        "args": ["-la", "/tmp"]
                    }),
                },
                MissionStep {
                    id: "step3".to_string(),
                    name: "HTTP Health Check".to_string(),
                    step_type: StepType::Http,
                    depends_on: None,
                    timeout_seconds: Some(30),
                    continue_on_error: Some(true),
                    parameters: serde_json::json!({
                        "url": "https://httpbin.org/get",
                        "method": "GET"
                    }),
                },
            ],
            config: None,
        }
    }

    #[test]
    fn test_export_to_github_actions() {
        let mission = create_test_mission();
        let config = ExportConfig::default();

        let result = ExportEngine::export_to_github_actions(&mission, &config);
        assert!(result.is_ok());

        let workflow = result.unwrap();
        assert!(workflow.contains("name: 'Test Export Mission'"));
        assert!(workflow.contains("runs-on: ubuntu-latest"));
        assert!(workflow.contains("- name: 'Create Test File'"));
        assert!(workflow.contains("- name: 'List Files'"));
        assert!(workflow.contains("- name: 'HTTP Health Check'"));
        assert!(workflow.contains("cat > /tmp/test.txt"));
        assert!(workflow.contains("ls -la /tmp"));
        assert!(workflow.contains("curl -X GET"));
    }

    #[test]
    fn test_export_to_terraform() {
        let mission = create_test_mission();
        let config = ExportConfig::default();

        let result = ExportEngine::export_to_terraform(&mission, &config);
        assert!(result.is_ok());

        let terraform = result.unwrap();
        assert!(terraform.contains("terraform {"));
        assert!(terraform.contains("required_providers"));
        assert!(terraform.contains("resource \"local_file\" \"step1\""));
        assert!(terraform.contains("resource \"null_resource\" \"step2\""));
        assert!(terraform.contains("filename = \"/tmp/test.txt\""));
        assert!(terraform.contains("content  = \"Hello, World!\""));
        assert!(terraform.contains("output \"mission_name\""));
        assert!(terraform.contains("output \"steps_count\""));
        assert!(terraform.contains("value       = 3"));
    }

    #[test]
    fn test_export_to_kubernetes() {
        let mission = create_test_mission();
        let config = ExportConfig::default();

        let result = ExportEngine::export_to_kubernetes(&mission, &config);
        assert!(result.is_ok());

        let k8s = result.unwrap();
        assert!(k8s.contains("apiVersion: batch/v1"));
        assert!(k8s.contains("kind: Job"));
        assert!(k8s.contains("name: test-export-mission"));
        assert!(k8s.contains("app: rustchain-mission"));
        assert!(k8s.contains("image: rustchain/executor:latest"));
        assert!(k8s.contains("restartPolicy: OnFailure"));
        assert!(k8s.contains("echo \"Executing step: Create Test File\""));
        assert!(k8s.contains("echo \"Executing step: List Files\""));
        assert!(k8s.contains("echo \"Executing step: HTTP Health Check\""));
    }

    #[test]
    fn test_export_to_jenkins() {
        let mission = create_test_mission();
        let config = ExportConfig::default();

        let result = ExportEngine::export_to_jenkins(&mission, &config);
        assert!(result.is_ok());

        let jenkins = result.unwrap();
        assert!(jenkins.contains("pipeline {"));
        assert!(jenkins.contains("agent any"));
        assert!(jenkins.contains("stages {"));
        assert!(jenkins.contains("stage('Create Test File')"));
        assert!(jenkins.contains("stage('List Files')"));
        assert!(jenkins.contains("stage('HTTP Health Check')"));
        assert!(jenkins.contains("sh 'cat > /tmp/test.txt"));
        assert!(jenkins.contains("sh 'ls -la /tmp'"));
        assert!(jenkins.contains("sh 'curl -X GET https://httpbin.org/get'"));
        assert!(jenkins.contains("post {"));
        assert!(jenkins.contains("success {"));
        assert!(jenkins.contains("failure {"));
    }

    #[test]
    fn test_export_to_docker_compose() {
        let mission = create_test_mission();
        let config = ExportConfig::default();

        let result = ExportEngine::export_to_docker_compose(&mission, &config);
        assert!(result.is_ok());

        let compose = result.unwrap();
        assert!(compose.contains("version: '3.8'"));
        assert!(compose.contains("services:"));
        assert!(compose.contains("test-export-mission:"));
        assert!(compose.contains("image: rustchain/executor:latest"));
        assert!(compose.contains("container_name: rustchain-mission"));
        assert!(compose.contains("command: >"));
        assert!(compose.contains("bash -c"));
        assert!(compose.contains("Mission completed successfully"));
    }

    #[test]
    fn test_export_to_bash_script() {
        let mission = create_test_mission();
        let config = ExportConfig::default();

        let result = ExportEngine::export_to_bash_script(&mission, &config);
        assert!(result.is_ok());

        let script = result.unwrap();
        assert!(script.contains("#!/bin/bash"));
        assert!(script.contains("set -euo pipefail"));
        assert!(script.contains("execute_mission() {"));
        assert!(script.contains("echo \"Starting RustChain mission: Test Export Mission\""));
        assert!(script.contains("# Step 1: Create Test File"));
        assert!(script.contains("# Step 2: List Files"));
        assert!(script.contains("# Step 3: HTTP Health Check"));
        assert!(script.contains("trap 'echo \"Mission failed"));
        assert!(script.contains("execute_mission"));
    }

    #[test]
    fn test_export_config_with_environment_variables() {
        let mission = create_test_mission();
        let mut config = ExportConfig::default();
        config
            .environment_variables
            .insert("API_KEY".to_string(), "secret123".to_string());
        config
            .environment_variables
            .insert("DEBUG".to_string(), "true".to_string());

        let result = ExportEngine::export_to_github_actions(&mission, &config);
        assert!(result.is_ok());

        let workflow = result.unwrap();
        assert!(workflow.contains("env:"));
        assert!(workflow.contains("API_KEY: secret123"));
        assert!(workflow.contains("DEBUG: true"));
    }

    #[test]
    fn test_to_shell_command() {
        let command_step = MissionStep {
            id: "test".to_string(),
            name: "Test Command".to_string(),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: None,
            parameters: serde_json::json!({
                "command": "echo",
                "args": ["Hello", "World"]
            }),
        };

        let result = ExportEngine::to_shell_command(&command_step);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "echo Hello World");

        let noop_step = MissionStep {
            id: "noop".to_string(),
            name: "Do Nothing".to_string(),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: None,
            parameters: serde_json::json!({}),
        };

        let result = ExportEngine::to_shell_command(&noop_step);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "echo 'NOOP: Do Nothing'");
    }

    #[test]
    fn test_name_sanitization() {
        assert_eq!(
            ExportEngine::sanitize_k8s_name("Test Mission Name!"),
            "test-mission-name"
        );
        assert_eq!(
            ExportEngine::sanitize_service_name("My_Service@2024"),
            "my_service-2024"
        );
        assert_eq!(
            ExportEngine::sanitize_terraform_name("step-1.test"),
            "step_1_test"
        );
    }

    #[tokio::test]
    async fn test_unsupported_export_format() {
        let mission = create_test_mission();
        let config = ExportConfig {
            format: ExportFormat::AnsiblePlaybook,
            ..Default::default()
        };

        let result = ExportEngine::export_mission(&mission, &config).await;
        assert!(result.is_err());

        let error = result.unwrap_err();
        match error {
            RustChainError::Config(crate::core::error::ConfigError::PluginError { message }) => {
                assert!(message.contains("not yet implemented"));
            }
            _ => panic!("Expected PluginError"),
        }
    }

    #[test]
    fn test_export_config_default() {
        let config = ExportConfig::default();
        assert!(matches!(config.format, ExportFormat::GitHubActions));
        assert!(config.include_comments);
        assert!(config.optimize_for_readability);
        assert!(config.custom_templates.is_empty());
        assert!(config.environment_variables.is_empty());
    }
}
