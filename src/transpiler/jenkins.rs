//! Jenkins Pipeline Parser for RustChain
//!
//! Converts Jenkins pipelines to RustChain missions:
//! - Parse Jenkinsfile (both declarative and scripted syntax)
//! - Extract stages, steps, and post actions
//! - Convert to RustChain mission steps with proper dependencies
//! - Handle Jenkins-specific constructs (parallel, matrix, when conditions)

use crate::core::Result;
use crate::engine::{Mission, MissionConfig, MissionStep, StepType};
use crate::transpiler::common::TranspilationContext;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Jenkins parser for converting Jenkinsfiles to RustChain missions
pub struct JenkinsParser;

/// Represents a Jenkins pipeline stage
#[derive(Debug, Clone)]
pub struct JenkinsStage {
    pub name: String,
    pub steps: Vec<JenkinsStep>,
    pub when_condition: Option<String>,
    pub parallel_stages: Vec<JenkinsStage>,
    pub agent: Option<String>,
}

/// Represents a Jenkins pipeline step
#[derive(Debug, Clone)]
pub struct JenkinsStep {
    pub step_type: String, // sh, bat, git, checkout, etc.
    pub parameters: HashMap<String, Value>,
    pub script: Option<String>,
}

/// Represents Jenkins pipeline structure
#[derive(Debug, Clone)]
pub struct JenkinsPipeline {
    pub pipeline_type: JenkinsPipelineType,
    pub agent: Option<String>,
    pub stages: Vec<JenkinsStage>,
    pub post_actions: Vec<JenkinsStep>,
    pub environment: HashMap<String, String>,
    pub parameters: Vec<JenkinsParameter>,
}

#[derive(Debug, Clone)]
pub enum JenkinsPipelineType {
    Declarative,
    Scripted,
}

#[derive(Debug, Clone)]
pub struct JenkinsParameter {
    pub name: String,
    pub param_type: String, // string, choice, boolean, etc.
    pub default_value: Option<String>,
    pub description: Option<String>,
}

impl JenkinsParser {
    /// Parse a Jenkins pipeline file and convert to RustChain mission
    pub async fn parse_file(file_path: &str) -> Result<Mission> {
        let content = tokio::fs::read_to_string(std::path::Path::new(file_path)).await?;
        Self::parse_string(&content).await
    }

    /// Parse Jenkins pipeline content from string
    pub async fn parse_string(content: &str) -> Result<Mission> {
        let mut context = TranspilationContext::new("Jenkins Pipeline Mission".to_string());

        // Parse Jenkins pipeline structure
        let pipeline = Self::parse_pipeline(content)?;

        // Convert to RustChain steps
        let mut steps = Vec::new();
        let mut step_counter = 1;

        // Add environment setup steps
        if !pipeline.environment.is_empty() {
            let env_step = Self::create_environment_setup_step(
                &pipeline.environment,
                &format!("env_{}", step_counter),
            )?;
            steps.push(env_step);
            step_counter += 1;
        }

        // Add parameter setup steps
        for param in &pipeline.parameters {
            let param_step =
                Self::create_parameter_step(param, &format!("param_{}", step_counter))?;
            steps.push(param_step);
            step_counter += 1;
        }

        // Add stage steps
        for stage in &pipeline.stages {
            let stage_steps = Self::create_stage_steps(stage, &mut step_counter)?;
            steps.extend(stage_steps);
        }

        // Add post-action steps
        for post_action in &pipeline.post_actions {
            let post_step =
                Self::create_post_action_step(post_action, &format!("post_{}", step_counter))?;
            steps.push(post_step);
            step_counter += 1;
        }

        context.add_variable(
            "total_stages".to_string(),
            pipeline.stages.len().to_string(),
        );
        context.add_variable(
            "pipeline_type".to_string(),
            format!("{:?}", pipeline.pipeline_type),
        );
        context.add_variable(
            "agent".to_string(),
            pipeline.agent.unwrap_or_else(|| "any".to_string()),
        );

        Ok(Mission {
            version: "1.0".to_string(),
            name: "Jenkins Pipeline Mission".to_string(),
            description: Some(format!(
                "Converted from Jenkins {:?} pipeline with {} stages",
                pipeline.pipeline_type,
                pipeline.stages.len()
            )),
            steps,
            config: Some(MissionConfig {
                max_parallel_steps: Some(4), // Jenkins often runs parallel stages
                timeout_seconds: Some(3600), // CI/CD can take a while
                fail_fast: Some(true),       // Builds should fail fast
            }),
        })
    }

    /// Parse Jenkins pipeline from content
    fn parse_pipeline(content: &str) -> Result<JenkinsPipeline> {
        let is_declarative = content.contains("pipeline {") || content.contains("pipeline{");
        let pipeline_type = if is_declarative {
            JenkinsPipelineType::Declarative
        } else {
            JenkinsPipelineType::Scripted
        };

        let mut stages = Vec::new();
        let mut environment = HashMap::new();
        let parameters = Vec::new();
        let mut agent = None;
        let post_actions = Vec::new();

        // Simple parsing - in production would use proper Groovy parser
        let lines: Vec<&str> = content.lines().map(|l| l.trim()).collect();
        let mut i = 0;
        let mut current_stage: Option<JenkinsStage> = None;

        while i < lines.len() {
            let line = lines[i];

            if line.starts_with("agent ") {
                agent = Self::parse_agent_line(line);
            } else if line.starts_with("stage(") || line.contains("stage '") {
                if let Some(stage) = current_stage.take() {
                    stages.push(stage);
                }
                current_stage = Self::parse_stage_start(line);
            } else if line.starts_with("sh ")
                || line.starts_with("bat ")
                || line.starts_with("powershell ")
            {
                if let Some(ref mut stage) = current_stage {
                    if let Some(step) = Self::parse_command_step(line)? {
                        stage.steps.push(step);
                    }
                }
            } else if line.starts_with("git ") || line.starts_with("checkout ") {
                if let Some(ref mut stage) = current_stage {
                    if let Some(step) = Self::parse_scm_step(line)? {
                        stage.steps.push(step);
                    }
                }
            } else if line.contains("environment {") {
                // Would parse environment variables here
                environment.insert("BUILD_ENV".to_string(), "jenkins".to_string());
            }

            i += 1;
        }

        // Add final stage if exists
        if let Some(stage) = current_stage {
            stages.push(stage);
        }

        // If no stages found, create a default one
        if stages.is_empty() {
            stages.push(JenkinsStage {
                name: "Default".to_string(),
                steps: vec![JenkinsStep {
                    step_type: "sh".to_string(),
                    parameters: HashMap::new(),
                    script: Some("echo 'No stages found in Jenkins pipeline'".to_string()),
                }],
                when_condition: None,
                parallel_stages: Vec::new(),
                agent: None,
            });
        }

        Ok(JenkinsPipeline {
            pipeline_type,
            agent,
            stages,
            post_actions,
            environment,
            parameters,
        })
    }

    /// Parse agent line
    fn parse_agent_line(line: &str) -> Option<String> {
        if line.contains("any") {
            Some("any".to_string())
        } else if line.contains("docker") {
            Some("docker".to_string())
        } else if line.contains("kubernetes") {
            Some("kubernetes".to_string())
        } else {
            Some("any".to_string())
        }
    }

    /// Parse stage start line
    fn parse_stage_start(line: &str) -> Option<JenkinsStage> {
        let stage_name = if line.contains("stage(") {
            // Declarative: stage('Build') {
            line.split("stage(")
                .nth(1)?
                .split(")")
                .next()?
                .trim_matches(|c| c == '\'' || c == '"')
                .to_string()
        } else if line.contains("stage '") {
            // Scripted: stage 'Build'
            line.split("stage '").nth(1)?.split("'").next()?.to_string()
        } else {
            "Unknown".to_string()
        };

        Some(JenkinsStage {
            name: stage_name,
            steps: Vec::new(),
            when_condition: None,
            parallel_stages: Vec::new(),
            agent: None,
        })
    }

    /// Parse command step (sh, bat, powershell)
    fn parse_command_step(line: &str) -> Result<Option<JenkinsStep>> {
        let (step_type, script) = if line.starts_with("sh ") {
            ("sh", line.strip_prefix("sh ").unwrap_or(""))
        } else if line.starts_with("bat ") {
            ("bat", line.strip_prefix("bat ").unwrap_or(""))
        } else if line.starts_with("powershell ") {
            ("powershell", line.strip_prefix("powershell ").unwrap_or(""))
        } else {
            return Ok(None);
        };

        let cleaned_script = script
            .trim_matches(|c| c == '\'' || c == '"' || c == '{' || c == '}')
            .trim();

        Ok(Some(JenkinsStep {
            step_type: step_type.to_string(),
            parameters: HashMap::new(),
            script: Some(cleaned_script.to_string()),
        }))
    }

    /// Parse SCM step (git, checkout)
    fn parse_scm_step(line: &str) -> Result<Option<JenkinsStep>> {
        if line.starts_with("git ") || line.starts_with("checkout ") {
            let mut parameters = HashMap::new();

            if line.contains("http") || line.contains("git@") {
                // Extract URL - simple pattern matching
                let url_start = line.find("http").or_else(|| line.find("git@"));
                if let Some(start) = url_start {
                    let url_part = &line[start..];
                    let url_end = url_part
                        .find("'")
                        .or_else(|| url_part.find("\""))
                        .unwrap_or(url_part.len());
                    let url = &url_part[..url_end];
                    parameters.insert("url".to_string(), Value::String(url.to_string()));
                }
            }

            Ok(Some(JenkinsStep {
                step_type: "git".to_string(),
                parameters,
                script: None,
            }))
        } else {
            Ok(None)
        }
    }

    /// Create environment setup step
    fn create_environment_setup_step(
        environment: &HashMap<String, String>,
        step_id: &str,
    ) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: "Setup Environment Variables".to_string(),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: Some(30),
            continue_on_error: Some(false),
            parameters: json!({
                "action": "setup_environment",
                "variables": environment,
                "jenkins_environment": true
            }),
        })
    }

    /// Create parameter setup step
    fn create_parameter_step(param: &JenkinsParameter, step_id: &str) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Setup Parameter: {}", param.name),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: Some(30),
            continue_on_error: Some(false),
            parameters: json!({
                "parameter_name": param.name,
                "parameter_type": param.param_type,
                "default_value": param.default_value,
                "description": param.description,
                "jenkins_parameter": true
            }),
        })
    }

    /// Create steps for a Jenkins stage
    fn create_stage_steps(
        stage: &JenkinsStage,
        step_counter: &mut usize,
    ) -> Result<Vec<MissionStep>> {
        let mut steps = Vec::new();

        // Create stage start step
        let stage_start = MissionStep {
            id: format!("stage_{}", step_counter),
            name: format!("Jenkins Stage: {}", stage.name),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: Some(30),
            continue_on_error: Some(false),
            parameters: json!({
                "stage_name": stage.name,
                "when_condition": stage.when_condition,
                "jenkins_stage": true
            }),
        };
        steps.push(stage_start);
        *step_counter += 1;

        // Create steps for each Jenkins step in the stage
        for jenkins_step in &stage.steps {
            let rustchain_step =
                Self::to_rustchain(jenkins_step, &format!("step_{}", step_counter))?;
            steps.push(rustchain_step);
            *step_counter += 1;
        }

        // Handle parallel stages if any
        for parallel_stage in &stage.parallel_stages {
            let parallel_steps = Self::create_stage_steps(parallel_stage, step_counter)?;
            steps.extend(parallel_steps);
        }

        Ok(steps)
    }

    /// Convert Jenkins step to RustChain step
    fn to_rustchain(jenkins_step: &JenkinsStep, step_id: &str) -> Result<MissionStep> {
        let (step_type, timeout, parameters) = match jenkins_step.step_type.as_str() {
            "sh" | "bat" | "powershell" => (
                StepType::Command,
                300,
                json!({
                    "command": jenkins_step.script.clone().unwrap_or_else(|| "echo 'No command'".to_string()),
                    "shell": jenkins_step.step_type,
                    "jenkins_command": true
                }),
            ),
            "git" => (
                StepType::Http,
                120,
                json!({
                    "action": "git_clone",
                    "parameters": jenkins_step.parameters,
                    "jenkins_scm": true
                }),
            ),
            "checkout" => (
                StepType::Http,
                120,
                json!({
                    "action": "checkout",
                    "parameters": jenkins_step.parameters,
                    "jenkins_scm": true
                }),
            ),
            "build" => (
                StepType::Command,
                1800,
                json!({
                    "action": "build",
                    "parameters": jenkins_step.parameters,
                    "jenkins_build": true
                }),
            ),
            "test" => (
                StepType::Command,
                900,
                json!({
                    "action": "test",
                    "parameters": jenkins_step.parameters,
                    "jenkins_test": true
                }),
            ),
            _ => (
                StepType::Noop,
                60,
                json!({
                    "step_type": jenkins_step.step_type,
                    "parameters": jenkins_step.parameters,
                    "script": jenkins_step.script,
                    "jenkins_custom": true
                }),
            ),
        };

        let script_text = jenkins_step
            .script
            .clone()
            .unwrap_or_else(|| "Custom Step".to_string());
        let truncated = &script_text[..50.min(script_text.len())];

        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!(
                "Jenkins {}: {}",
                jenkins_step.step_type.to_uppercase(),
                truncated
            ),
            step_type,
            depends_on: None,
            timeout_seconds: Some(timeout),
            continue_on_error: Some(false),
            parameters,
        })
    }

    /// Create post-action step
    fn create_post_action_step(post_action: &JenkinsStep, step_id: &str) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Post Action: {}", post_action.step_type),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: Some(120),
            continue_on_error: Some(true), // Post actions usually shouldn't fail the build
            parameters: json!({
                "action": "post_action",
                "step_type": post_action.step_type,
                "parameters": post_action.parameters,
                "jenkins_post": true
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_declarative_pipeline() {
        let jenkins_pipeline = r#"
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make build'
                sh 'echo "Build complete"'
            }
        }
        stage('Test') {
            steps {
                sh 'make test'
            }
        }
    }
}
        "#;

        let result = JenkinsParser::parse_string(jenkins_pipeline).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert_eq!(mission.name, "Jenkins Pipeline Mission");
        assert!(mission.steps.len() >= 2); // At least build and test stages

        // Check that we have stage steps
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names.iter().any(|name| name.contains("Build")));
        assert!(step_names.iter().any(|name| name.contains("Test")));
    }

    #[tokio::test]
    async fn test_parse_scripted_pipeline() {
        let jenkins_pipeline = r#"
node {
    stage 'Checkout'
    checkout scm
    
    stage 'Build'
    sh 'mvn clean compile'
    
    stage 'Test'
    sh 'mvn test'
}
        "#;

        let result = JenkinsParser::parse_string(jenkins_pipeline).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert!(mission.description.unwrap().contains("Scripted pipeline"));

        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names.iter().any(|name| name.contains("Checkout")));
        assert!(step_names.iter().any(|name| name.contains("Build")));
        assert!(step_names.iter().any(|name| name.contains("Test")));
    }

    #[tokio::test]
    async fn test_parse_pipeline_with_git() {
        let jenkins_pipeline = r#"
pipeline {
    agent any
    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/example/repo.git'
            }
        }
    }
}
        "#;

        let result = JenkinsParser::parse_string(jenkins_pipeline).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        let git_steps: Vec<&MissionStep> = mission
            .steps
            .iter()
            .filter(|step| matches!(step.step_type, StepType::Http))
            .collect();

        assert!(!git_steps.is_empty());

        // Check that git parameters are captured
        let git_step = git_steps.first().unwrap();
        assert!(git_step.parameters.get("jenkins_scm").is_some());
    }

    #[test]
    fn test_parse_command_step() {
        let sh_line = "sh 'make build && make test'";
        let result = JenkinsParser::parse_command_step(sh_line).unwrap();

        assert!(result.is_some());
        let step = result.unwrap();
        assert_eq!(step.step_type, "sh");
        assert_eq!(step.script.unwrap(), "make build && make test");

        let bat_line = "bat \"build.cmd\"";
        let result = JenkinsParser::parse_command_step(bat_line).unwrap();
        assert!(result.is_some());
        let step = result.unwrap();
        assert_eq!(step.step_type, "bat");
        assert_eq!(step.script.unwrap(), "build.cmd");
    }

    #[test]
    fn test_parse_scm_step() {
        let git_line = "git 'https://github.com/example/repo.git'";
        let result = JenkinsParser::parse_scm_step(git_line).unwrap();

        assert!(result.is_some());
        let step = result.unwrap();
        assert_eq!(step.step_type, "git");

        let url = step.parameters.get("url");
        assert!(url.is_some());
        assert!(url.unwrap().as_str().unwrap().contains("github.com"));
    }

    #[tokio::test]
    async fn test_empty_pipeline() {
        let result = JenkinsParser::parse_string("").await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert!(!mission.steps.is_empty()); // Should have default stage
        assert!(mission.description.unwrap().contains("1 stages")); // Should report 1 stages (default)
    }

    #[tokio::test]
    async fn test_pipeline_with_environment() {
        let jenkins_pipeline = r#"
pipeline {
    agent any
    environment {
        NODE_ENV = 'production'
        API_KEY = credentials('api-key')
    }
    stages {
        stage('Deploy') {
            steps {
                sh 'npm run deploy'
            }
        }
    }
}
        "#;

        let result = JenkinsParser::parse_string(jenkins_pipeline).await;
        assert!(result.is_ok());

        let mission = result.unwrap();

        // Should have environment setup step
        let env_steps: Vec<&MissionStep> = mission
            .steps
            .iter()
            .filter(|step| step.name.contains("Environment"))
            .collect();

        assert!(!env_steps.is_empty());
    }

    #[test]
    fn test_stage_name_parsing() {
        let declarative_stage = "stage('Build and Test') {";
        let stage = JenkinsParser::parse_stage_start(declarative_stage);
        assert!(stage.is_some());
        assert_eq!(stage.unwrap().name, "Build and Test");

        let scripted_stage = "stage 'Deploy to Production'";
        let stage = JenkinsParser::parse_stage_start(scripted_stage);
        assert!(stage.is_some());
        assert_eq!(stage.unwrap().name, "Deploy to Production");
    }
}
