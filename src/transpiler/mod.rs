//! Universal Transpiler System for RustChain
//!
//! Converts various workflow formats into RustChain missions:
//! - LangChain Python scripts
//! - Airflow DAGs  
//! - GitHub Actions
//! - Jenkins Pipelines
//! - Kubernetes Jobs
//! - And more...

pub mod airflow;
pub mod bash;
pub mod common;
pub mod cron;
pub mod docker_compose;
pub mod export;
pub mod github_actions;
pub mod jenkins;
pub mod kubernetes;
pub mod langchain;
pub mod terraform;

use crate::core::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Supported input formats for transpilation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputFormat {
    LangChain,
    Airflow,
    GitHubActions,
    Cron,
    Jenkins,
    Kubernetes,
    Terraform,
    DockerCompose,
    BashScript,
    AwsStepFunctions,
    AzureDevOps,
}

/// Supported output formats for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    RustChainYaml,
    GitHubActions,
    Kubernetes,
    Terraform,
    Jenkins,
}

/// Main transpiler interface
pub struct UniversalTranspiler {
    pub input_format: InputFormat,
    pub output_format: OutputFormat,
}

impl UniversalTranspiler {
    pub fn new(input: InputFormat, output: OutputFormat) -> Self {
        Self {
            input_format: input,
            output_format: output,
        }
    }

    /// Transpile a file from one format to another
    pub async fn transpile_file(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        match (&self.input_format, &self.output_format) {
            (InputFormat::LangChain, OutputFormat::RustChainYaml) => {
                let mission = langchain::LangChainParser::parse_file(input_path).await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::Airflow, OutputFormat::RustChainYaml) => {
                let mission =
                    airflow::AirflowParser::parse_file(&input_path.to_string_lossy()).await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::GitHubActions, OutputFormat::RustChainYaml) => {
                let content = tokio::fs::read_to_string(input_path).await?;
                let mission = github_actions::GitHubActionsParser::parse_string(&content).await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::Cron, OutputFormat::RustChainYaml) => {
                let content = tokio::fs::read_to_string(input_path).await?;
                let schedule = cron::CronIntegration::parse_expression(content.trim())?;
                let base_mission = crate::engine::Mission {
                    version: "1.0".to_string(),
                    name: format!("Scheduled Mission: {}", schedule.description),
                    description: Some(format!(
                        "Mission scheduled with cron expression: {}",
                        schedule.original
                    )),
                    steps: vec![cron::CronIntegration::create_schedule_wait_step(
                        &schedule.original,
                        "schedule_wait",
                    )?],
                    config: Some(crate::engine::MissionConfig {
                        max_parallel_steps: None,
                        timeout_seconds: None,
                        fail_fast: Some(false),
                    }),
                };
                base_mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::Terraform, OutputFormat::RustChainYaml) => {
                let mission =
                    terraform::TerraformParser::parse_file(&input_path.to_string_lossy()).await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::Kubernetes, OutputFormat::RustChainYaml) => {
                let mission =
                    kubernetes::KubernetesParser::parse_file(&input_path.to_string_lossy()).await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::Jenkins, OutputFormat::RustChainYaml) => {
                let mission =
                    jenkins::JenkinsParser::parse_file(&input_path.to_string_lossy()).await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::DockerCompose, OutputFormat::RustChainYaml) => {
                let mission =
                    docker_compose::DockerComposeParser::parse_file(&input_path.to_string_lossy())
                        .await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            (InputFormat::BashScript, OutputFormat::RustChainYaml) => {
                let mission = bash::BashParser::parse_file(&input_path.to_string_lossy()).await?;
                mission.save_to_file(output_path).await?;
                Ok(())
            }
            // RustChain to other formats (export functionality)
            (InputFormat::LangChain, OutputFormat::GitHubActions) => {
                let mission = langchain::LangChainParser::parse_file(input_path).await?;
                let config = export::ExportConfig {
                    format: export::ExportFormat::GitHubActions,
                    ..Default::default()
                };
                let output_content =
                    export::ExportEngine::export_mission(&mission, &config).await?;
                tokio::fs::write(output_path, output_content).await?;
                Ok(())
            }
            (InputFormat::LangChain, OutputFormat::Kubernetes) => {
                let mission = langchain::LangChainParser::parse_file(input_path).await?;
                let config = export::ExportConfig {
                    format: export::ExportFormat::Kubernetes,
                    ..Default::default()
                };
                let output_content =
                    export::ExportEngine::export_mission(&mission, &config).await?;
                tokio::fs::write(output_path, output_content).await?;
                Ok(())
            }
            (InputFormat::LangChain, OutputFormat::Jenkins) => {
                let mission = langchain::LangChainParser::parse_file(input_path).await?;
                let config = export::ExportConfig {
                    format: export::ExportFormat::Jenkins,
                    ..Default::default()
                };
                let output_content =
                    export::ExportEngine::export_mission(&mission, &config).await?;
                tokio::fs::write(output_path, output_content).await?;
                Ok(())
            }
            (InputFormat::LangChain, OutputFormat::Terraform) => {
                let mission = langchain::LangChainParser::parse_file(input_path).await?;
                let config = export::ExportConfig {
                    format: export::ExportFormat::Terraform,
                    ..Default::default()
                };
                let output_content =
                    export::ExportEngine::export_mission(&mission, &config).await?;
                tokio::fs::write(output_path, output_content).await?;
                Ok(())
            }
            _ => Err(crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!(
                        "Transpilation from {:?} to {:?} not yet implemented",
                        self.input_format, self.output_format
                    ),
                },
            )),
        }
    }

    /// Transpile from string content
    pub async fn transpile_string(&self, input_content: &str) -> Result<String> {
        // Helper function for parsing to mission
        async fn parse_to_mission(
            input_format: &InputFormat,
            content: &str,
        ) -> Result<crate::engine::Mission> {
            match input_format {
                InputFormat::LangChain => langchain::LangChainParser::parse_string(content).await,
                InputFormat::Airflow => airflow::AirflowParser::parse_string(content).await,
                InputFormat::GitHubActions => {
                    github_actions::GitHubActionsParser::parse_string(content).await
                }
                InputFormat::Cron => {
                    let schedule = cron::CronIntegration::parse_expression(content.trim())?;
                    Ok(crate::engine::Mission {
                        version: "1.0".to_string(),
                        name: format!("Scheduled Mission: {}", schedule.description),
                        description: Some(format!(
                            "Mission scheduled with cron expression: {}",
                            schedule.original
                        )),
                        steps: vec![cron::CronIntegration::create_schedule_wait_step(
                            &schedule.original,
                            "schedule_wait",
                        )?],
                        config: Some(crate::engine::MissionConfig {
                            max_parallel_steps: None,
                            timeout_seconds: None,
                            fail_fast: Some(false),
                        }),
                    })
                }
                InputFormat::Terraform => terraform::TerraformParser::parse_string(content).await,
                InputFormat::Kubernetes => {
                    kubernetes::KubernetesParser::parse_string(content).await
                }
                InputFormat::Jenkins => jenkins::JenkinsParser::parse_string(content).await,
                InputFormat::DockerCompose => {
                    docker_compose::DockerComposeParser::parse_string(content).await
                }
                InputFormat::BashScript => bash::BashParser::parse_string(content).await,
                _ => Err(crate::core::error::RustChainError::Config(
                    crate::core::error::ConfigError::PluginError {
                        message: format!("Parsing from {:?} not implemented", input_format),
                    },
                )),
            }
        }

        // Helper function for exporting mission
        async fn export_mission_to_format(
            mission: &crate::engine::Mission,
            output_format: &OutputFormat,
        ) -> Result<String> {
            let export_format = match output_format {
                OutputFormat::GitHubActions => export::ExportFormat::GitHubActions,
                OutputFormat::Kubernetes => export::ExportFormat::Kubernetes,
                OutputFormat::Jenkins => export::ExportFormat::Jenkins,
                OutputFormat::Terraform => export::ExportFormat::Terraform,
                _ => {
                    return Err(crate::core::error::RustChainError::Config(
                        crate::core::error::ConfigError::PluginError {
                            message: format!("Export to {:?} not implemented", output_format),
                        },
                    ))
                }
            };

            let config = export::ExportConfig {
                format: export_format,
                ..Default::default()
            };
            export::ExportEngine::export_mission(mission, &config).await
        }

        match (&self.input_format, &self.output_format) {
            (_, OutputFormat::RustChainYaml) => {
                let mission = parse_to_mission(&self.input_format, input_content).await?;
                Ok(mission.to_yaml()?)
            }
            (InputFormat::LangChain, _) => {
                let mission = langchain::LangChainParser::parse_string(input_content).await?;
                export_mission_to_format(&mission, &self.output_format).await
            }
            _ => Err(crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!(
                        "Transpilation from {:?} to {:?} not yet implemented",
                        self.input_format, self.output_format
                    ),
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused imports from tests

    #[tokio::test]
    async fn test_transpiler_creation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::LangChain, OutputFormat::RustChainYaml);

        assert!(matches!(transpiler.input_format, InputFormat::LangChain));
        assert!(matches!(
            transpiler.output_format,
            OutputFormat::RustChainYaml
        ));
    }

    #[tokio::test]
    async fn test_airflow_transpilation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::Airflow, OutputFormat::RustChainYaml);

        let airflow_dag = r#"
from airflow import DAG
from airflow.operators.bash import BashOperator

dag = DAG('test_dag', description='Test DAG')
task = BashOperator(task_id='test_task', bash_command='echo hello', dag=dag)
        "#;

        let result = transpiler.transpile_string(airflow_dag).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();
        assert!(yaml.contains("name: test_dag"));
        assert!(yaml.contains("id: test_task"));
    }

    #[tokio::test]
    async fn test_cron_transpilation() {
        let transpiler = UniversalTranspiler::new(InputFormat::Cron, OutputFormat::RustChainYaml);

        let cron_expression = "@daily";

        let result = transpiler.transpile_string(cron_expression).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();

        assert!(yaml.contains("Scheduled Mission: Run once a day at midnight"));
        assert!(yaml.contains("schedule_wait"));
        assert!(yaml.contains("@daily"));
    }

    #[tokio::test]
    async fn test_cron_standard_expression() {
        let transpiler = UniversalTranspiler::new(InputFormat::Cron, OutputFormat::RustChainYaml);

        let cron_expression = "*/15 * * * *";

        let result = transpiler.transpile_string(cron_expression).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();
        assert!(yaml.contains("Every 15 minutes"));
        assert!(yaml.contains("*/15 * * * *"));
    }

    #[tokio::test]
    async fn test_terraform_transpilation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::Terraform, OutputFormat::RustChainYaml);

        let terraform_content = r#"
variable "instance_type" {
  default = "t2.micro"
}

resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = var.instance_type
}

output "instance_ip" {
  value = aws_instance.web.public_ip
}
        "#;

        let result = transpiler.transpile_string(terraform_content).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();
        assert!(yaml.contains("Terraform Infrastructure Mission"));
        assert!(yaml.contains("Initialize Variable: instance_type"));
        assert!(yaml.contains("Create aws_instance: web"));
        assert!(yaml.contains("Output: instance_ip"));
    }

    #[tokio::test]
    async fn test_kubernetes_transpilation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::Kubernetes, OutputFormat::RustChainYaml);

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

        let result = transpiler.transpile_string(k8s_manifest).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();
        assert!(yaml.contains("Kubernetes Deployment Mission"));
        assert!(yaml.contains("Deploy Deployment nginx-deployment"));
        assert!(yaml.contains("Health Check Deployment nginx-deployment"));
    }

    #[tokio::test]
    async fn test_jenkins_transpilation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::Jenkins, OutputFormat::RustChainYaml);

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

        let result = transpiler.transpile_string(jenkins_pipeline).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();
        assert!(yaml.contains("Jenkins Pipeline Mission"));
        assert!(yaml.contains("Jenkins Stage: Build"));
        assert!(yaml.contains("Jenkins Stage: Test"));
        assert!(yaml.contains("make build"));
    }

    #[tokio::test]
    async fn test_docker_compose_transpilation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::DockerCompose, OutputFormat::RustChainYaml);

        let docker_compose = r#"
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
  database:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: secret
    volumes:
      - data:/var/lib/postgresql/data
volumes:
  data:
    driver: local
        "#;

        let result = transpiler.transpile_string(docker_compose).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();
        assert!(yaml.contains("Docker Compose Mission"));
        assert!(yaml.contains("Start Docker Service: web"));
        assert!(yaml.contains("Start Docker Service: database"));
        assert!(yaml.contains("Create Docker Volume: data"));
    }

    #[tokio::test]
    async fn test_bash_script_transpilation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::BashScript, OutputFormat::RustChainYaml);

        let bash_script = r#"#!/bin/bash
# Simple backup script
BACKUP_DIR="/backup"
export PATH="/usr/bin:$PATH"

echo "Starting backup..."
mkdir -p $BACKUP_DIR
cp -r /home/user $BACKUP_DIR
grep "error" /var/log/app.log > errors.txt
echo "Backup complete!"
        "#;

        let result = transpiler.transpile_string(bash_script).await;
        assert!(result.is_ok());

        let yaml = result.unwrap();
        assert!(yaml.contains("Bash Script Mission"));
        assert!(yaml.contains("Set Variable: BACKUP_DIR"));
        assert!(yaml.contains("Set Variable: PATH"));
        assert!(yaml.contains("Execute: echo"));
        assert!(yaml.contains("Execute: mkdir"));
        assert!(yaml.contains("Execute: cp"));
    }

    #[tokio::test]
    async fn test_unsupported_transpilation() {
        let transpiler =
            UniversalTranspiler::new(InputFormat::AwsStepFunctions, OutputFormat::RustChainYaml);

        let result = transpiler.transpile_string("test").await;
        assert!(result.is_err());
    }
}
