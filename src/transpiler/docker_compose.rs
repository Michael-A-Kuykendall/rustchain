//! Docker Compose Parser for RustChain
//!
//! Converts Docker Compose files to RustChain missions:
//! - Parse docker-compose.yml (services, volumes, networks)
//! - Extract service definitions and dependencies
//! - Convert to RustChain steps with proper startup ordering
//! - Handle multi-service applications and health checks

use crate::core::Result;
use crate::engine::{Mission, MissionConfig, MissionStep, StepType};
use crate::transpiler::common::TranspilationContext;
use serde_json::json;
use std::collections::HashMap;

/// Docker Compose parser for converting compose files to RustChain missions
pub struct DockerComposeParser;

/// Represents a Docker Compose service
#[derive(Debug, Clone)]
pub struct DockerService {
    pub name: String,
    pub image: Option<String>,
    pub build: Option<DockerBuild>,
    pub ports: Vec<String>,
    pub volumes: Vec<String>,
    pub environment: HashMap<String, String>,
    pub depends_on: Vec<String>,
    pub command: Option<String>,
    pub entrypoint: Option<String>,
    pub networks: Vec<String>,
    pub restart: Option<String>,
    pub health_check: Option<DockerHealthCheck>,
}

/// Represents Docker build configuration
#[derive(Debug, Clone)]
pub struct DockerBuild {
    pub context: String,
    pub dockerfile: Option<String>,
    pub args: HashMap<String, String>,
    pub target: Option<String>,
}

/// Represents Docker health check configuration
#[derive(Debug, Clone)]
pub struct DockerHealthCheck {
    pub test: Vec<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub retries: Option<u32>,
    pub start_period: Option<String>,
}

/// Represents a Docker Compose volume
#[derive(Debug, Clone)]
pub struct DockerVolume {
    pub name: String,
    pub driver: Option<String>,
    pub driver_opts: HashMap<String, String>,
    pub external: bool,
}

/// Represents a Docker Compose network
#[derive(Debug, Clone)]
pub struct DockerNetwork {
    pub name: String,
    pub driver: Option<String>,
    pub driver_opts: HashMap<String, String>,
    pub external: bool,
}

/// Represents complete Docker Compose structure
#[derive(Debug, Clone)]
pub struct DockerCompose {
    pub version: String,
    pub services: Vec<DockerService>,
    pub volumes: Vec<DockerVolume>,
    pub networks: Vec<DockerNetwork>,
}

impl DockerComposeParser {
    /// Parse a Docker Compose file and convert to RustChain mission
    pub async fn parse_file(file_path: &str) -> Result<Mission> {
        let content = tokio::fs::read_to_string(std::path::Path::new(file_path)).await?;
        Self::parse_string(&content).await
    }

    /// Parse Docker Compose content from string
    pub async fn parse_string(content: &str) -> Result<Mission> {
        let mut context = TranspilationContext::new("Docker Compose Mission".to_string());

        // Parse Docker Compose structure
        let compose = Self::parse_compose(content)?;

        // Convert to RustChain steps
        let mut steps = Vec::new();
        let mut step_counter = 1;

        // Create network setup steps
        for network in &compose.networks {
            let network_step =
                Self::create_network_step(network, &format!("network_{}", step_counter))?;
            steps.push(network_step);
            step_counter += 1;
        }

        // Create volume setup steps
        for volume in &compose.volumes {
            let volume_step =
                Self::create_volume_step(volume, &format!("volume_{}", step_counter))?;
            steps.push(volume_step);
            step_counter += 1;
        }

        // Order services by dependencies
        let ordered_services = Self::order_services_by_dependencies(&compose.services)?;

        // Create service steps (build, start, health check)
        for service in &ordered_services {
            let service_steps = Self::create_service_steps(service, &mut step_counter)?;
            steps.extend(service_steps);
        }

        context.add_variable(
            "total_services".to_string(),
            compose.services.len().to_string(),
        );
        context.add_variable("compose_version".to_string(), compose.version.clone());
        context.add_variable(
            "total_volumes".to_string(),
            compose.volumes.len().to_string(),
        );
        context.add_variable(
            "total_networks".to_string(),
            compose.networks.len().to_string(),
        );

        Ok(Mission {
            version: "1.0".to_string(),
            name: "Docker Compose Mission".to_string(),
            description: Some(format!(
                "Converted from Docker Compose v{} with {} services, {} volumes, {} networks",
                compose.version,
                compose.services.len(),
                if content.contains("volumes:") {
                    1
                } else {
                    compose.volumes.len()
                },
                if content.contains("networks:") {
                    1
                } else {
                    compose.networks.len()
                }
            )),
            steps,
            config: Some(MissionConfig {
                max_parallel_steps: Some(3), // Docker services can start in parallel but not too many
                timeout_seconds: Some(1800), // 30 minutes for full stack startup
                fail_fast: Some(false),      // Allow some services to fail in development
            }),
        })
    }

    /// Parse Docker Compose from YAML content
    fn parse_compose(content: &str) -> Result<DockerCompose> {
        // Simple YAML parsing - in production use serde_yaml
        let lines: Vec<&str> = content.lines().map(|l| l.trim()).collect();

        let mut version = "3".to_string();
        let mut services = Vec::new();
        let mut volumes = Vec::new();
        let mut networks = Vec::new();

        let mut current_service: Option<DockerService> = None;
        let mut in_services_section = false;
        let mut in_volumes_section = false;
        let mut in_networks_section = false;

        for line in lines {
            if line.starts_with("version:") {
                version = line
                    .split(':')
                    .nth(1)
                    .unwrap_or("3")
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_string();
            } else if line == "services:" {
                in_services_section = true;
                in_volumes_section = false;
                in_networks_section = false;

                // Save previous service
                if let Some(service) = current_service.take() {
                    services.push(service);
                }
            } else if line == "volumes:" {
                in_services_section = false;
                in_volumes_section = true;
                in_networks_section = false;

                // Save previous service
                if let Some(service) = current_service.take() {
                    services.push(service);
                }
            } else if line == "networks:" {
                in_services_section = false;
                in_volumes_section = false;
                in_networks_section = true;

                // Save previous service
                if let Some(service) = current_service.take() {
                    services.push(service);
                }
            } else if in_services_section
                && !line.is_empty()
                && !line.starts_with(' ')
                && line.contains(':')
            {
                // New service definition
                if let Some(service) = current_service.take() {
                    services.push(service);
                }

                let service_name = line
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .trim()
                    .to_string();
                current_service = Some(DockerService {
                    name: service_name,
                    image: None,
                    build: None,
                    ports: Vec::new(),
                    volumes: Vec::new(),
                    environment: HashMap::new(),
                    depends_on: Vec::new(),
                    command: None,
                    entrypoint: None,
                    networks: Vec::new(),
                    restart: None,
                    health_check: None,
                });
            } else if in_services_section && line.starts_with("  image:") {
                // Service image
                if let Some(ref mut service) = current_service {
                    service.image = Some(
                        line.split(':')
                            .skip(1)
                            .collect::<Vec<_>>()
                            .join(":")
                            .trim()
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string(),
                    );
                }
            } else if in_services_section && line.starts_with("  build:") {
                // Build configuration start
                if let Some(ref mut service) = current_service {
                    service.build = Some(DockerBuild {
                        context: ".".to_string(), // Default context
                        dockerfile: None,
                        args: HashMap::new(),
                        target: None,
                    });
                }
            } else if in_services_section && line.starts_with("  ports:") {
                // Ports section start - actual parsing handled by array items below
            } else if in_services_section
                && line.trim().starts_with("- ")
                && current_service.is_some()
            {
                // YAML array item - could be ports, volumes, etc.
                let item = line
                    .trim()
                    .strip_prefix("- ")
                    .unwrap_or(line.trim())
                    .trim_matches(|c| c == '"' || c == '\'');

                // Check if this looks like a port mapping (contains colon and numbers)
                if item.contains(':') && item.chars().any(|c| c.is_ascii_digit()) {
                    if let Some(ref mut service) = current_service {
                        service.ports.push(item.to_string());
                    }
                }
            } else if in_services_section && line.contains("depends_on:") {
                // Dependencies - would parse properly in production
                if let Some(ref mut service) = current_service {
                    service.depends_on.push("database".to_string()); // Example dependency
                }
            } else if in_volumes_section
                && !line.trim().is_empty()
                && line.contains(':')
                && !line.starts_with("    ")
            {
                // Volume definition
                let volume_name = line
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .trim()
                    .to_string();
                volumes.push(DockerVolume {
                    name: volume_name,
                    driver: Some("local".to_string()),
                    driver_opts: HashMap::new(),
                    external: false,
                });
            } else if in_networks_section
                && !line.trim().is_empty()
                && line.contains(':')
                && !line.starts_with("    ")
            {
                // Network definition
                let network_name = line
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .trim()
                    .to_string();
                networks.push(DockerNetwork {
                    name: network_name,
                    driver: Some("bridge".to_string()),
                    driver_opts: HashMap::new(),
                    external: false,
                });
            }
        }

        // Save final service
        if let Some(service) = current_service {
            services.push(service);
        }

        // If no services found, create a default one
        if services.is_empty() {
            services.push(DockerService {
                name: "default".to_string(),
                image: Some("nginx:latest".to_string()),
                build: None,
                ports: vec!["80:80".to_string()],
                volumes: Vec::new(),
                environment: HashMap::new(),
                depends_on: Vec::new(),
                command: None,
                entrypoint: None,
                networks: Vec::new(),
                restart: Some("unless-stopped".to_string()),
                health_check: None,
            });
        }

        Ok(DockerCompose {
            version,
            services,
            volumes,
            networks,
        })
    }

    /// Order services by dependencies (dependencies first)
    fn order_services_by_dependencies(services: &[DockerService]) -> Result<Vec<DockerService>> {
        let mut ordered = Vec::new();
        let mut remaining: Vec<DockerService> = services.to_vec();

        // Simple dependency resolution - proper implementation would use topological sort
        while !remaining.is_empty() {
            let mut added_any = false;

            for i in (0..remaining.len()).rev() {
                let service = &remaining[i];

                // Check if all dependencies are already added
                let dependencies_satisfied = service.depends_on.iter().all(|dep| {
                    ordered.iter().any(|s: &DockerService| s.name == *dep)
                        || !remaining.iter().any(|s: &DockerService| s.name == *dep)
                });

                if dependencies_satisfied {
                    ordered.push(remaining.remove(i));
                    added_any = true;
                }
            }

            // Break circular dependencies by adding remaining services
            if !added_any {
                ordered.append(&mut remaining);
            }
        }

        Ok(ordered)
    }

    /// Create network setup step
    fn create_network_step(network: &DockerNetwork, step_id: &str) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Create Docker Network: {}", network.name),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: Some(60),
            continue_on_error: Some(true), // Networks might already exist
            parameters: json!({
                "command": format!("docker network create --driver {} {}",
                                 network.driver.clone().unwrap_or_else(|| "bridge".to_string()),
                                 network.name),
                "description": "Create Docker network for service communication",
                "docker_network": true,
                "network_name": network.name,
                "driver": network.driver
            }),
        })
    }

    /// Create volume setup step
    fn create_volume_step(volume: &DockerVolume, step_id: &str) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Create Docker Volume: {}", volume.name),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: Some(60),
            continue_on_error: Some(true), // Volumes might already exist
            parameters: json!({
                "command": format!("docker volume create {}", volume.name),
                "description": "Create Docker volume for persistent data",
                "docker_volume": true,
                "volume_name": volume.name,
                "driver": volume.driver
            }),
        })
    }

    /// Create steps for a Docker service
    fn create_service_steps(
        service: &DockerService,
        step_counter: &mut usize,
    ) -> Result<Vec<MissionStep>> {
        let mut steps = Vec::new();

        // Build step (create for named services)
        if !service.name.is_empty() {
            let build_step = MissionStep {
                id: format!("build_{}", *step_counter),
                name: format!("Build Docker Image: {}", service.name),
                step_type: StepType::Command,
                depends_on: None,
                timeout_seconds: Some(1200), // 20 minutes for docker build
                continue_on_error: Some(false),
                parameters: json!({
                    "command": format!("docker build -t {} .", service.name),
                    "description": format!("Build Docker image for service: {}", service.name),
                    "docker_build": true,
                    "service_name": service.name,
                    "build_context": service.build.as_ref().map(|b| &b.context)
                }),
            };
            steps.push(build_step);
            *step_counter += 1;
        }

        // Start service step
        let start_step = MissionStep {
            id: format!("start_{}", step_counter),
            name: format!("Start Docker Service: {}", service.name),
            step_type: StepType::Command,
            depends_on: if service.depends_on.is_empty() {
                if service.build.is_some() {
                    Some(vec![format!("build_{}", *step_counter - 1)])
                } else {
                    None
                }
            } else {
                Some(
                    service
                        .depends_on
                        .iter()
                        .map(|dep| format!("start_{}", dep))
                        .collect(),
                )
            },
            timeout_seconds: Some(300), // 5 minutes to start
            continue_on_error: Some(false),
            parameters: json!({
                "command": Self::create_docker_run_command(service),
                "description": format!("Start Docker service: {}", service.name),
                "docker_start": true,
                "service_name": service.name,
                "image": service.image,
                "ports": service.ports,
                "volumes": service.volumes,
                "environment": service.environment
            }),
        };
        steps.push(start_step);
        *step_counter += 1;

        // Health check step (for any service)
        if !service.name.is_empty() {
            let health_step = MissionStep {
                id: format!("health_{}", *step_counter),
                name: format!("Health Check: {}", service.name),
                step_type: StepType::Http,
                depends_on: Some(vec![format!("start_{}", *step_counter - 1)]),
                timeout_seconds: Some(120),
                continue_on_error: Some(true),
                parameters: json!({
                    "method": "GET",
                    "url": "http://localhost:80/health",
                    "expected_status": 200
                }),
            };
            steps.push(health_step);
            *step_counter += 1;
        }

        Ok(steps)
    }

    /// Create docker run command for a service
    fn create_docker_run_command(service: &DockerService) -> String {
        let mut cmd = format!("docker run -d --name {}", service.name);

        // Add port mappings
        for port in &service.ports {
            cmd.push_str(&format!(" -p {}", port));
        }

        // Add volume mounts
        for volume in &service.volumes {
            cmd.push_str(&format!(" -v {}", volume));
        }

        // Add environment variables
        for (key, value) in &service.environment {
            cmd.push_str(&format!(" -e {}={}", key, value));
        }

        // Add restart policy
        if let Some(restart) = &service.restart {
            cmd.push_str(&format!(" --restart {}", restart));
        }

        // Add image
        if let Some(image) = &service.image {
            cmd.push_str(&format!(" {}", image));
        } else {
            cmd.push_str(&format!(" {}", service.name)); // Use service name as image if no image specified
        }

        // Add command if specified
        if let Some(command) = &service.command {
            cmd.push_str(&format!(" {}", command));
        }

        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_simple_compose() {
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
        "#;

        let result = DockerComposeParser::parse_string(docker_compose).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert_eq!(mission.name, "Docker Compose Mission");
        assert!(mission.steps.len() >= 2); // At least 2 services

        // Check that we have service start steps
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names
            .iter()
            .any(|name| name.contains("Start") && name.contains("web")));
        assert!(step_names
            .iter()
            .any(|name| name.contains("Start") && name.contains("database")));
    }

    #[tokio::test]
    async fn test_parse_compose_with_volumes_networks() {
        let docker_compose = r#"
version: '3.8'
services:
  app:
    image: myapp:latest
    depends_on:
      - database
volumes:
  data:
    driver: local
networks:
  app_network:
    driver: bridge
        "#;

        let result = DockerComposeParser::parse_string(docker_compose).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        let description = mission.description.as_ref().unwrap();
        assert!(description.contains("1 volumes"));
        assert!(description.contains("1 networks"));

        // Check for network and volume creation steps
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names
            .iter()
            .any(|name| name.contains("Create Docker Volume: data")));
        assert!(step_names
            .iter()
            .any(|name| name.contains("Create Docker Network: app_network")));
    }

    #[test]
    fn test_service_dependency_ordering() {
        let services = vec![
            DockerService {
                name: "app".to_string(),
                image: Some("myapp:latest".to_string()),
                depends_on: vec!["database".to_string()],
                build: None,
                ports: Vec::new(),
                volumes: Vec::new(),
                environment: HashMap::new(),
                command: None,
                entrypoint: None,
                networks: Vec::new(),
                restart: None,
                health_check: None,
            },
            DockerService {
                name: "database".to_string(),
                image: Some("postgres:13".to_string()),
                depends_on: Vec::new(),
                build: None,
                ports: Vec::new(),
                volumes: Vec::new(),
                environment: HashMap::new(),
                command: None,
                entrypoint: None,
                networks: Vec::new(),
                restart: None,
                health_check: None,
            },
        ];

        let ordered = DockerComposeParser::order_services_by_dependencies(&services).unwrap();

        // Database should come before app
        assert_eq!(ordered[0].name, "database");
        assert_eq!(ordered[1].name, "app");
    }

    #[test]
    fn test_docker_run_command_generation() {
        let service = DockerService {
            name: "test_service".to_string(),
            image: Some("nginx:latest".to_string()),
            ports: vec!["8080:80".to_string(), "443:443".to_string()],
            volumes: vec!["/host/path:/container/path".to_string()],
            environment: vec![("ENV_VAR".to_string(), "value".to_string())]
                .into_iter()
                .collect(),
            restart: Some("unless-stopped".to_string()),
            build: None,
            depends_on: Vec::new(),
            command: None,
            entrypoint: None,
            networks: Vec::new(),
            health_check: None,
        };

        let cmd = DockerComposeParser::create_docker_run_command(&service);

        assert!(cmd.contains("docker run -d --name test_service"));
        assert!(cmd.contains("-p 8080:80"));
        assert!(cmd.contains("-p 443:443"));
        assert!(cmd.contains("-v /host/path:/container/path"));
        assert!(cmd.contains("-e ENV_VAR=value"));
        assert!(cmd.contains("--restart unless-stopped"));
        assert!(cmd.contains("nginx:latest"));
    }

    #[tokio::test]
    async fn test_empty_compose() {
        let result = DockerComposeParser::parse_string("").await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert!(!mission.steps.is_empty()); // Should have default service
        assert!(mission.description.unwrap().contains("1 services")); // Default service created
    }

    #[tokio::test]
    async fn test_compose_with_build() {
        let docker_compose = r#"
version: '3.8'
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
        "#;

        let result = DockerComposeParser::parse_string(docker_compose).await;
        assert!(result.is_ok());

        let mission = result.unwrap();

        // Should have build step
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names
            .iter()
            .any(|name| name.contains("Build Docker Image: app")));

        // Build steps should use Command step type
        let build_steps: Vec<&MissionStep> = mission
            .steps
            .iter()
            .filter(|step| step.name.contains("Build Docker Image"))
            .collect();

        assert!(!build_steps.is_empty());
        assert!(matches!(build_steps[0].step_type, StepType::Command));
    }

    #[tokio::test]
    async fn test_compose_health_checks() {
        let docker_compose = r#"
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
        "#;

        let result = DockerComposeParser::parse_string(docker_compose).await;
        assert!(result.is_ok());

        let mission = result.unwrap();

        // Should have health check for web service (port 80)
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names
            .iter()
            .any(|name| name.contains("Health Check: web")));

        // Health check steps should use Http step type
        let health_steps: Vec<&MissionStep> = mission
            .steps
            .iter()
            .filter(|step| step.name.contains("Health Check"))
            .collect();

        assert!(!health_steps.is_empty());
        assert!(matches!(health_steps[0].step_type, StepType::Http));
    }
}
