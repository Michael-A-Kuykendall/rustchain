//! GitHub Actions Parser
//!
//! Converts GitHub Actions workflow YAML files to RustChain missions.
//! Supports standard GitHub Actions syntax including jobs, steps, and matrix builds.

use crate::core::Result;
use crate::engine::{Mission, MissionStep, StepType};
use crate::transpiler::common::{TranspilationContext, TranspilerUtils};
use serde::{Deserialize, Serialize};
use serde_yaml;
use std::collections::HashMap;

/// GitHub Actions workflow representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubWorkflow {
    pub name: Option<String>,
    pub on: WorkflowTrigger,
    pub jobs: HashMap<String, Job>,
    pub env: Option<HashMap<String, String>>,
    pub defaults: Option<Defaults>,
}

/// GitHub Actions workflow triggers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkflowTrigger {
    Simple(String),
    List(Vec<String>),
    Complex(HashMap<String, serde_yaml::Value>),
}

/// GitHub Actions job definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub name: Option<String>,
    #[serde(rename = "runs-on")]
    pub runs_on: RunsOn,
    pub needs: Option<Dependencies>,
    pub steps: Vec<Step>,
    pub env: Option<HashMap<String, String>>,
    pub strategy: Option<Strategy>,
    #[serde(rename = "timeout-minutes")]
    pub timeout_minutes: Option<u32>,
    #[serde(rename = "continue-on-error")]
    pub continue_on_error: Option<bool>,
}

/// GitHub Actions step definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Option<String>,
    pub name: Option<String>,
    pub uses: Option<String>,
    pub run: Option<String>,
    #[serde(rename = "with")]
    pub with_params: Option<HashMap<String, serde_yaml::Value>>,
    pub env: Option<HashMap<String, String>>,
    #[serde(rename = "continue-on-error")]
    pub continue_on_error: Option<bool>,
    #[serde(rename = "timeout-minutes")]
    pub timeout_minutes: Option<u32>,
    #[serde(rename = "working-directory")]
    pub working_directory: Option<String>,
    pub shell: Option<String>,
}

/// GitHub Actions runs-on specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RunsOn {
    Simple(String),
    List(Vec<String>),
}

/// GitHub Actions job dependencies
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Dependencies {
    Single(String),
    Multiple(Vec<String>),
}

/// GitHub Actions strategy for matrix builds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strategy {
    pub matrix: Option<HashMap<String, serde_yaml::Value>>,
    #[serde(rename = "fail-fast")]
    pub fail_fast: Option<bool>,
    #[serde(rename = "max-parallel")]
    pub max_parallel: Option<u32>,
}

/// GitHub Actions workflow defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    pub run: Option<RunDefaults>,
}

/// Default settings for run steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDefaults {
    pub shell: Option<String>,
    #[serde(rename = "working-directory")]
    pub working_directory: Option<String>,
}

/// GitHub Actions parser for converting workflow YAML to RustChain missions
pub struct GitHubActionsParser;

impl GitHubActionsParser {
    /// Parse GitHub Actions workflow from YAML string content
    pub async fn parse_string(content: &str) -> Result<Mission> {
        let workflow: GitHubWorkflow = serde_yaml::from_str(content)
            .map_err(|e| format!("Failed to parse GitHub Actions workflow: {}", e))?;

        Self::to_mission(workflow).await
    }

    /// Parse GitHub Actions workflow from file
    pub async fn parse_file(file_path: &str) -> Result<Mission> {
        let content = tokio::fs::read_to_string(file_path)
            .await
            .map_err(|e| format!("Failed to read GitHub Actions workflow file: {}", e))?;
        Self::parse_string(&content).await
    }

    /// Convert GitHubWorkflow to RustChain Mission
    async fn to_mission(workflow: GitHubWorkflow) -> Result<Mission> {
        let mission_name = workflow
            .name
            .clone()
            .unwrap_or_else(|| "github_actions_workflow".to_string());
        let mut context = TranspilationContext::new(mission_name.clone());

        let mut steps = Vec::new();
        let mut job_dependencies: HashMap<String, Vec<String>> = HashMap::new();

        // Process each job in the workflow
        for (job_id, job) in &workflow.jobs {
            let job_steps = Self::to_steps(job_id, job, &mut context)?;

            // Track job dependencies
            if let Some(needs) = &job.needs {
                let deps = match needs {
                    Dependencies::Single(dep) => vec![dep.clone()],
                    Dependencies::Multiple(deps) => deps.clone(),
                };
                job_dependencies.insert(job_id.clone(), deps);
            }

            steps.extend(job_steps);
        }

        // Apply job dependencies to steps
        Self::apply_job_dependencies(&mut steps, &job_dependencies)?;

        let description = Self::generate_description(&workflow);

        let mission = TranspilerUtils::create_mission(mission_name, description, steps);

        Ok(mission)
    }

    /// Convert a single job to multiple RustChain steps
    fn to_steps(
        job_id: &str,
        job: &Job,
        context: &mut TranspilationContext,
    ) -> Result<Vec<MissionStep>> {
        let mut steps = Vec::new();

        // Create a setup step for the job environment
        let setup_step = Self::create_job_setup_step(job_id, job, context)?;
        if let Some(step) = setup_step {
            steps.push(step);
        }

        // Process each step in the job
        for (step_index, step) in job.steps.iter().enumerate() {
            let rustchain_step = Self::to_mission_step(job_id, step_index, step, job, context)?;
            steps.push(rustchain_step);
        }

        Ok(steps)
    }

    /// Create a job setup step if needed
    fn create_job_setup_step(
        job_id: &str,
        job: &Job,
        _context: &mut TranspilationContext,
    ) -> Result<Option<MissionStep>> {
        // Create setup step for runner environment
        let runner = match &job.runs_on {
            RunsOn::Simple(runner) => runner.clone(),
            RunsOn::List(runners) => runners
                .first()
                .unwrap_or(&"ubuntu-latest".to_string())
                .clone(),
        };

        let step_id = format!("{}_setup", job_id);
        let step_name = format!("Setup {} Environment", job_id);

        let parameters = serde_json::json!({
            "runner": runner,
            "job_id": job_id,
            "environment": job.env.as_ref().unwrap_or(&HashMap::new())
        });

        Ok(Some(MissionStep {
            id: step_id,
            name: step_name,
            step_type: StepType::Noop, // Setup is handled by RustChain runtime
            parameters,
            depends_on: None,
            timeout_seconds: Some(300), // 5 minutes for setup
            continue_on_error: None,
        }))
    }

    /// Convert GitHub Actions step to RustChain MissionStep
    fn to_mission_step(
        job_id: &str,
        step_index: usize,
        step: &Step,
        job: &Job,
        _context: &mut TranspilationContext,
    ) -> Result<MissionStep> {
        let step_id = step
            .id
            .clone()
            .unwrap_or_else(|| format!("{}_{}", job_id, step_index));
        let step_name = step
            .name
            .clone()
            .unwrap_or_else(|| format!("Step {}", step_index + 1));

        let (step_type, parameters) = if let Some(run_command) = &step.run {
            // Shell command step
            Self::create_command_step(run_command, step, job)?
        } else if let Some(action) = &step.uses {
            // GitHub Action step
            Self::create_action_step(action, step)?
        } else {
            // Default noop step
            (StepType::Noop, serde_json::json!({}))
        };

        // Calculate timeout
        let timeout_seconds = step
            .timeout_minutes
            .or(job.timeout_minutes)
            .map(|mins| (mins as u64) * 60)
            .or(Some(1800)); // Default 30 minutes

        Ok(MissionStep {
            id: step_id,
            name: step_name,
            step_type,
            parameters,
            depends_on: None, // Will be set later based on job dependencies
            timeout_seconds,
            continue_on_error: step.continue_on_error.or(job.continue_on_error),
        })
    }

    /// Create command step for shell commands
    fn create_command_step(
        run_command: &str,
        step: &Step,
        _job: &Job,
    ) -> Result<(StepType, serde_json::Value)> {
        let shell = step.shell.as_ref().unwrap_or(&"bash".to_string()).clone();

        let working_dir = step.working_directory.as_ref();

        let mut parameters = serde_json::json!({
            "command": shell,
            "args": ["-c", run_command]
        });

        if let Some(dir) = working_dir {
            parameters["working_directory"] = serde_json::Value::String(dir.clone());
        }

        if let Some(env) = &step.env {
            parameters["environment"] = serde_json::to_value(env)
                .map_err(|e| format!("Failed to serialize environment variables: {}", e))?;
        }

        Ok((StepType::Command, parameters))
    }

    /// Create action step for GitHub Actions
    fn create_action_step(action: &str, step: &Step) -> Result<(StepType, serde_json::Value)> {
        let mut parameters = serde_json::json!({
            "action": action
        });

        if let Some(with_params) = &step.with_params {
            parameters["parameters"] = serde_json::to_value(with_params)
                .map_err(|e| format!("Failed to serialize action parameters: {}", e))?;
        }

        if let Some(env) = &step.env {
            parameters["environment"] = serde_json::to_value(env)
                .map_err(|e| format!("Failed to serialize environment variables: {}", e))?;
        }

        // Map common GitHub Actions to RustChain step types
        let step_type = match action {
            a if a.contains("checkout") => StepType::GitStatus, // Git checkout
            a if a.contains("upload-artifact") || a.contains("download-artifact") => {
                StepType::CopyFile
            }
            a if a.contains("setup-node")
                || a.contains("setup-python")
                || a.contains("setup-java") =>
            {
                StepType::Noop
            }
            a if a.contains("cache") => StepType::Noop, // Cache handled by runtime
            _ => StepType::Tool,                        // Generic tool execution
        };

        Ok((step_type, parameters))
    }

    /// Apply job dependencies to mission steps
    fn apply_job_dependencies(
        steps: &mut [MissionStep],
        job_deps: &HashMap<String, Vec<String>>,
    ) -> Result<()> {
        // Create mapping from job IDs to their step IDs
        let mut job_to_steps: HashMap<String, Vec<String>> = HashMap::new();

        for step in steps.iter() {
            let job_id = if let Some(pos) = step.id.find('_') {
                step.id[..pos].to_string()
            } else {
                step.id.clone()
            };
            job_to_steps
                .entry(job_id)
                .or_default()
                .push(step.id.clone());
        }

        // Apply dependencies
        for step in steps.iter_mut() {
            let job_id = if let Some(pos) = step.id.find('_') {
                step.id[..pos].to_string()
            } else {
                step.id.clone()
            };

            if let Some(deps) = job_deps.get(&job_id) {
                let mut dependencies = Vec::new();
                for dep_job in deps {
                    if let Some(dep_steps) = job_to_steps.get(dep_job) {
                        // Depend on the last step of the dependency job
                        if let Some(last_step) = dep_steps.last() {
                            dependencies.push(last_step.clone());
                        }
                    }
                }
                if !dependencies.is_empty() {
                    step.depends_on = Some(dependencies);
                }
            }
        }

        Ok(())
    }

    /// Generate mission description from workflow
    fn generate_description(workflow: &GitHubWorkflow) -> Option<String> {
        let mut desc_parts = Vec::new();

        if let Some(name) = &workflow.name {
            desc_parts.push(format!("GitHub Actions Workflow: {}", name));
        } else {
            desc_parts.push("GitHub Actions Workflow".to_string());
        }

        desc_parts.push(format!("Jobs: {}", workflow.jobs.len()));

        // Add trigger information
        match &workflow.on {
            WorkflowTrigger::Simple(trigger) => {
                desc_parts.push(format!("Trigger: {}", trigger));
            }
            WorkflowTrigger::List(triggers) => {
                desc_parts.push(format!("Triggers: {}", triggers.join(", ")));
            }
            WorkflowTrigger::Complex(_) => {
                desc_parts.push("Triggers: Complex configuration".to_string());
            }
        }

        Some(desc_parts.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_simple_workflow() {
        let workflow_yaml = r#"
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      - name: Run tests
        run: npm test
"#;

        let mission = GitHubActionsParser::parse_string(workflow_yaml)
            .await
            .expect("GitHub Actions workflow parsing should succeed");

        assert_eq!(mission.name, "CI");
        assert!(mission.description.is_some());
        assert!(mission.steps.len() >= 2); // At least setup + checkout + test

        // Check for checkout step
        let checkout_step = mission.steps.iter().find(|s| s.name.contains("Checkout"));
        assert!(checkout_step.is_some());

        // Check for test step
        let test_step = mission.steps.iter().find(|s| s.name.contains("Run tests"));
        assert!(test_step.is_some());
        assert!(matches!(
            test_step.expect("Test step should exist").step_type,
            StepType::Command
        ));
    }

    #[tokio::test]
    async fn test_parse_multi_job_workflow() {
        let workflow_yaml = r#"
name: Build and Deploy
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build app
        run: npm run build
  
  deploy:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - name: Deploy app
        run: ./deploy.sh
"#;

        let mission = GitHubActionsParser::parse_string(workflow_yaml)
            .await
            .expect("Multi-job workflow parsing should succeed");

        assert_eq!(mission.name, "Build and Deploy");
        assert!(mission.steps.len() >= 4); // 2 jobs * (setup + step)

        // Check that deploy job depends on build job
        let deploy_step = mission
            .steps
            .iter()
            .find(|s| s.name.contains("Deploy app"))
            .expect("Deploy step should exist");

        assert!(deploy_step.depends_on.is_some());
        assert!(!deploy_step
            .depends_on
            .as_ref()
            .expect("Depends on should be present")
            .is_empty());
    }

    #[tokio::test]
    async fn test_parse_workflow_with_environment() {
        let workflow_yaml = r#"
name: Test with Environment
on: push
env:
  NODE_ENV: test
  API_KEY: secret
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      DATABASE_URL: postgres://test
    steps:
      - name: Run tests with env
        run: npm test
        env:
          TEST_VAR: value
"#;

        let mission = GitHubActionsParser::parse_string(workflow_yaml)
            .await
            .expect("Workflow with environment parsing should succeed");

        assert_eq!(mission.name, "Test with Environment");

        let test_step = mission
            .steps
            .iter()
            .find(|s| s.name.contains("Run tests"))
            .expect("Test step should exist");

        // Check that environment variables are included
        assert!(test_step.parameters.get("environment").is_some());
    }

    #[tokio::test]
    async fn test_parse_workflow_with_matrix() {
        let workflow_yaml = r#"
name: Matrix Build
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [14, 16, 18]
    steps:
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: ${{ matrix.node-version }}
      - name: Run tests
        run: npm test
"#;

        let mission = GitHubActionsParser::parse_string(workflow_yaml)
            .await
            .expect("Matrix workflow parsing should succeed");

        assert_eq!(mission.name, "Matrix Build");

        // Check for setup-node action
        let setup_step = mission
            .steps
            .iter()
            .find(|s| s.name.contains("Setup Node"))
            .expect("Setup step should exist");

        assert!(matches!(setup_step.step_type, StepType::Noop)); // Setup actions are noop
        assert!(setup_step.parameters.get("action").is_some());
    }

    #[tokio::test]
    async fn test_parse_workflow_with_timeout() {
        let workflow_yaml = r#"
name: Test with Timeout
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Long running task
        run: sleep 30
        timeout-minutes: 2
"#;

        let mission = GitHubActionsParser::parse_string(workflow_yaml)
            .await
            .expect("Timeout workflow parsing should succeed");

        let long_task = mission
            .steps
            .iter()
            .find(|s| s.name.contains("Long running"))
            .expect("Long task should exist");

        // Step timeout should override job timeout (2 minutes = 120 seconds)
        assert_eq!(long_task.timeout_seconds, Some(120));
    }

    #[tokio::test]
    async fn test_parse_empty_workflow() {
        let workflow_yaml = r#"
name: Empty Workflow
on: push
jobs: {}
"#;

        let mission = GitHubActionsParser::parse_string(workflow_yaml)
            .await
            .expect("Empty workflow parsing should succeed");

        assert_eq!(mission.name, "Empty Workflow");
        assert_eq!(mission.steps.len(), 0);
    }

    #[tokio::test]
    async fn test_parse_workflow_with_different_shells() {
        let workflow_yaml = r#"
name: Shell Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Bash command
        run: echo "Hello from bash"
        shell: bash
      - name: PowerShell command
        run: Write-Host "Hello from PowerShell"
        shell: pwsh
"#;

        let mission = GitHubActionsParser::parse_string(workflow_yaml)
            .await
            .expect("Workflow with different shells parsing should succeed");

        let bash_step = mission
            .steps
            .iter()
            .find(|s| s.name.contains("Bash command"))
            .expect("Bash step should exist");

        let powershell_step = mission
            .steps
            .iter()
            .find(|s| s.name.contains("PowerShell command"))
            .expect("PowerShell step should exist");

        // Both should be Command steps but with different shell configurations
        assert!(matches!(bash_step.step_type, StepType::Command));
        assert!(matches!(powershell_step.step_type, StepType::Command));

        // Check that shell is preserved in parameters
        assert!(bash_step.parameters.get("command").is_some());
        assert!(powershell_step.parameters.get("command").is_some());
    }

    #[test]
    fn test_workflow_trigger_parsing() {
        // Test simple trigger (deserialize just the value, not the full YAML)
        let simple_yaml = "push";
        let trigger: WorkflowTrigger =
            serde_yaml::from_str(simple_yaml).expect("Simple trigger parsing should succeed");
        assert!(matches!(trigger, WorkflowTrigger::Simple(_)));

        // Test list trigger
        let list_yaml = "[push, pull_request]";
        let trigger: WorkflowTrigger =
            serde_yaml::from_str(list_yaml).expect("List trigger parsing should succeed");
        assert!(matches!(trigger, WorkflowTrigger::List(_)));
    }
}
