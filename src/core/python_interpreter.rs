// Python Code Interpreter Implementation
use crate::core::error::{RustChainError, ToolError};
use crate::core::tools::{Tool, ToolCapability, ToolResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use tempfile::TempDir;
use tokio::fs;
use tokio::process::Command as AsyncCommand;
use tracing::{debug, info, warn};

/// Python Code Interpreter for executing Python code safely in a sandboxed environment
pub struct PythonInterpreter {
    python_path: String,
    working_directory: Option<PathBuf>,
    timeout_seconds: u64,
    max_output_size: usize,
    environment_vars: HashMap<String, String>,
    allowed_imports: Vec<String>,
}

impl PythonInterpreter {
    pub fn new(python_path: String) -> Self {
        Self {
            python_path,
            working_directory: None,
            timeout_seconds: 30,
            max_output_size: 1024 * 1024, // 1MB max output
            environment_vars: HashMap::new(),
            allowed_imports: vec![
                // Standard library modules (safe)
                "os".to_string(),
                "sys".to_string(),
                "json".to_string(),
                "math".to_string(),
                "datetime".to_string(),
                "collections".to_string(),
                "itertools".to_string(),
                "functools".to_string(),
                "operator".to_string(),
                "random".to_string(),
                "re".to_string(),
                "string".to_string(),
                "time".to_string(),
                "uuid".to_string(),
                // Data science libraries
                "numpy".to_string(),
                "pandas".to_string(),
                "matplotlib".to_string(),
                "seaborn".to_string(),
                "scipy".to_string(),
                "sklearn".to_string(),
                "requests".to_string(),
                "urllib".to_string(),
                // Utilities
                "base64".to_string(),
                "hashlib".to_string(),
                "csv".to_string(),
                "xml".to_string(),
                "html".to_string(),
            ],
        }
    }

    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    pub fn with_working_directory(mut self, dir: PathBuf) -> Self {
        self.working_directory = Some(dir);
        self
    }

    pub fn with_environment_var(mut self, key: String, value: String) -> Self {
        self.environment_vars.insert(key, value);
        self
    }

    pub fn with_allowed_imports(mut self, imports: Vec<String>) -> Self {
        self.allowed_imports = imports;
        self
    }

    async fn validate_code(&self, code: &str) -> Result<(), RustChainError> {
        // Basic security checks
        let dangerous_patterns = vec![
            "import subprocess",
            "import os.system",
            "__import__",
            "exec(",
            "eval(",
            "compile(",
            "open(",
            "file(",
            "input(",
            "raw_input(",
            "reload(",
            "globals(",
            "locals(",
            "vars(",
            "dir(",
            "getattr(",
            "setattr(",
            "delattr(",
            "hasattr(",
        ];

        for pattern in dangerous_patterns {
            if code.contains(pattern) {
                return Err(RustChainError::Tool(ToolError::InvalidParameters {
                    tool_name: "python_interpreter".to_string(),
                    details: format!("Code contains potentially dangerous pattern: {}", pattern),
                }));
            }
        }

        // Check for allowed imports
        for line in code.lines() {
            let line = line.trim();
            if line.starts_with("import ") || line.starts_with("from ") {
                let module_name = if line.starts_with("import ") {
                    line.strip_prefix("import ")
                        .unwrap_or("")
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                } else {
                    line.strip_prefix("from ")
                        .unwrap_or("")
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                };

                let base_module = module_name.split('.').next().unwrap_or("");
                if !self.allowed_imports.contains(&base_module.to_string()) {
                    return Err(RustChainError::Tool(ToolError::InvalidParameters {
                        tool_name: "python_interpreter".to_string(),
                        details: format!("Import not allowed: {}", base_module),
                    }));
                }
            }
        }

        Ok(())
    }

    pub async fn execute_code(
        &self,
        request: PythonExecutionRequest,
    ) -> Result<PythonExecutionResult, RustChainError> {
        debug!(
            "Executing Python code with timeout: {}s",
            self.timeout_seconds
        );

        // Validate code security
        self.validate_code(&request.code).await?;

        // Create temporary directory for execution
        let temp_dir = TempDir::new().map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "python_interpreter".to_string(),
                reason: format!("Failed to create temporary directory: {}", e),
            })
        })?;

        // Write code to temporary file
        let script_path = temp_dir.path().join("script.py");
        fs::write(&script_path, &request.code).await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "python_interpreter".to_string(),
                reason: format!("Failed to write script file: {}", e),
            })
        })?;

        // Prepare working directory
        let work_dir = self
            .working_directory
            .as_ref()
            .map_or(temp_dir.path(), |p| p.as_path());

        // Execute Python script
        let mut cmd = AsyncCommand::new(&self.python_path);
        cmd.arg(&script_path)
            .current_dir(work_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Set environment variables
        for (key, value) in &self.environment_vars {
            cmd.env(key, value);
        }

        // Add security environment variables
        cmd.env("PYTHONDONTWRITEBYTECODE", "1"); // Don't create .pyc files
        cmd.env("PYTHONPATH", ""); // Clear Python path for security

        let start_time = std::time::Instant::now();

        debug!("Starting Python execution");
        let child = cmd.spawn().map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "python_interpreter".to_string(),
                reason: format!("Failed to start Python process: {}", e),
            })
        })?;

        // Wait for completion with timeout
        let timeout_duration = tokio::time::Duration::from_secs(self.timeout_seconds);
        let output_result = tokio::time::timeout(timeout_duration, child.wait_with_output()).await;

        let execution_time = start_time.elapsed();

        let output = match output_result {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "python_interpreter".to_string(),
                    reason: format!("Python execution failed: {}", e),
                }));
            }
            Err(_) => {
                return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "python_interpreter".to_string(),
                    reason: format!(
                        "Python execution timed out after {} seconds",
                        self.timeout_seconds
                    ),
                }));
            }
        };

        // Convert output to strings and check size limits
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let stdout = if stdout.len() > self.max_output_size {
            format!(
                "{}... (truncated, {} bytes total)",
                &stdout[..self.max_output_size],
                stdout.len()
            )
        } else {
            stdout.to_string()
        };

        let stderr = if stderr.len() > self.max_output_size {
            format!(
                "{}... (truncated, {} bytes total)",
                &stderr[..self.max_output_size],
                stderr.len()
            )
        } else {
            stderr.to_string()
        };

        let result = PythonExecutionResult {
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout,
            stderr,
            execution_time_ms: execution_time.as_millis() as u64,
        };

        if result.success {
            info!(
                "Python code executed successfully in {}ms",
                result.execution_time_ms
            );
        } else {
            warn!(
                "Python code execution failed with exit code: {:?}",
                result.exit_code
            );
            debug!("Error output: {}", result.stderr);
        }

        Ok(result)
    }

    pub async fn execute_code_with_files(
        &self,
        request: PythonExecutionWithFilesRequest,
    ) -> Result<PythonExecutionWithFilesResult, RustChainError> {
        debug!(
            "Executing Python code with {} input files",
            request.input_files.len()
        );

        // Validate code security
        self.validate_code(&request.code).await?;

        // Create temporary directory for execution
        let temp_dir = TempDir::new().map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "python_interpreter".to_string(),
                reason: format!("Failed to create temporary directory: {}", e),
            })
        })?;

        // Write input files to temporary directory
        for (filename, content) in &request.input_files {
            let file_path = temp_dir.path().join(filename);

            // Ensure file path is within temp directory (security check)
            if !file_path.starts_with(temp_dir.path()) {
                return Err(RustChainError::Tool(ToolError::InvalidParameters {
                    tool_name: "python_interpreter".to_string(),
                    details: format!("Invalid file path: {}", filename),
                }));
            }

            // Create parent directories if needed
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    RustChainError::Tool(ToolError::ExecutionFailed {
                        tool_name: "python_interpreter".to_string(),
                        reason: format!("Failed to create directory for file {}: {}", filename, e),
                    })
                })?;
            }

            fs::write(&file_path, content).await.map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "python_interpreter".to_string(),
                    reason: format!("Failed to write input file {}: {}", filename, e),
                })
            })?;
        }

        // Execute the code
        let execution_request = PythonExecutionRequest { code: request.code };

        let temp_interpreter = PythonInterpreter {
            python_path: self.python_path.clone(),
            working_directory: Some(temp_dir.path().to_path_buf()),
            timeout_seconds: self.timeout_seconds,
            max_output_size: self.max_output_size,
            environment_vars: self.environment_vars.clone(),
            allowed_imports: self.allowed_imports.clone(),
        };

        let execution_result = temp_interpreter.execute_code(execution_request).await?;

        // Read output files if they were created
        let mut output_files = HashMap::new();
        if let Some(expected_files) = request.expected_output_files {
            for filename in expected_files {
                let file_path = temp_dir.path().join(&filename);
                if file_path.exists() {
                    match fs::read_to_string(&file_path).await {
                        Ok(content) => {
                            output_files.insert(filename, content);
                        }
                        Err(e) => {
                            warn!("Failed to read expected output file {}: {}", filename, e);
                        }
                    }
                }
            }
        }

        Ok(PythonExecutionWithFilesResult {
            execution_result,
            output_files,
        })
    }

    pub async fn get_installed_packages(&self) -> Result<Vec<PythonPackage>, RustChainError> {
        debug!("Getting installed Python packages");

        let mut cmd = AsyncCommand::new(&self.python_path);
        cmd.args(["-m", "pip", "list", "--format=json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Timeout after 60 seconds to prevent indefinite hangs
        let output = tokio::time::timeout(std::time::Duration::from_secs(60), cmd.output())
            .await
            .map_err(|_| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "python_interpreter".to_string(),
                    reason: "pip list timed out after 60 seconds".to_string(),
                })
            })?
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "python_interpreter".to_string(),
                    reason: format!("Failed to get package list: {}", e),
                })
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "python_interpreter".to_string(),
                reason: format!("pip list failed: {}", stderr),
            }));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let packages: Vec<PythonPackage> = serde_json::from_str(&stdout).map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "python_interpreter".to_string(),
                reason: format!("Failed to parse package list: {}", e),
            })
        })?;

        info!("Found {} installed Python packages", packages.len());
        Ok(packages)
    }
}

#[async_trait]
impl Tool for PythonInterpreter {
    fn name(&self) -> &'static str {
        "python_interpreter"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::SystemAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let operation: PythonOperation = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "python_interpreter".to_string(),
                details: format!("Invalid operation parameters: {}", e),
            })
        })?;

        match operation {
            PythonOperation::Execute { code } => {
                let request = PythonExecutionRequest { code };
                let result = self.execute_code(request).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(result)?))
            }
            PythonOperation::ExecuteWithFiles {
                code,
                input_files,
                expected_output_files,
            } => {
                let request = PythonExecutionWithFilesRequest {
                    code,
                    input_files,
                    expected_output_files,
                };
                let result = self.execute_code_with_files(request).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(result)?))
            }
            PythonOperation::ListPackages => {
                let packages = self.get_installed_packages().await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(packages)?))
            }
        }
    }
}

// Data structures for Python operations

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum PythonOperation {
    #[serde(rename = "execute")]
    Execute { code: String },
    #[serde(rename = "execute_with_files")]
    ExecuteWithFiles {
        code: String,
        input_files: HashMap<String, String>,
        expected_output_files: Option<Vec<String>>,
    },
    #[serde(rename = "list_packages")]
    ListPackages,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PythonExecutionRequest {
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PythonExecutionResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub execution_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PythonExecutionWithFilesRequest {
    pub code: String,
    pub input_files: HashMap<String, String>,
    pub expected_output_files: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PythonExecutionWithFilesResult {
    pub execution_result: PythonExecutionResult,
    pub output_files: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PythonPackage {
    pub name: String,
    pub version: String,
}

// Helper function to create Python interpreter from environment
pub fn create_python_interpreter_from_env() -> Result<PythonInterpreter, RustChainError> {
    let python_path = std::env::var("PYTHON_PATH")
        .or_else(|_| std::env::var("PYTHON"))
        .unwrap_or_else(|_| {
            // Try common Python paths
            if cfg!(windows) {
                "python".to_string() // Windows usually has python in PATH
            } else {
                "python3".to_string() // Unix-like systems prefer python3
            }
        });

    let mut interpreter = PythonInterpreter::new(python_path);

    // Configure from environment variables
    if let Ok(timeout) = std::env::var("PYTHON_TIMEOUT_SECONDS") {
        if let Ok(seconds) = timeout.parse::<u64>() {
            interpreter = interpreter.with_timeout(seconds);
        }
    }

    if let Ok(work_dir) = std::env::var("PYTHON_WORK_DIR") {
        interpreter = interpreter.with_working_directory(PathBuf::from(work_dir));
    }

    // Add custom environment variables with PYTHON_ENV_ prefix
    for (key, value) in std::env::vars() {
        if let Some(env_key) = key.strip_prefix("PYTHON_ENV_") {
            interpreter = interpreter.with_environment_var(env_key.to_string(), value);
        }
    }

    Ok(interpreter)
}

// Tool registry helper function
pub fn register_python_interpreter(registry: &mut crate::core::tools::ToolRegistry) {
    match create_python_interpreter_from_env() {
        Ok(interpreter) => {
            registry.register(Box::new(interpreter));
            info!("Registered Python Interpreter");
        }
        Err(e) => {
            warn!("Python Interpreter not registered: {}", e);
            debug!("To enable Python interpreter, ensure Python is available in PATH or set PYTHON_PATH environment variable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_python_execution_request_serialization() {
        let request = PythonExecutionRequest {
            code: "print('hello world')".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: PythonExecutionRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.code, deserialized.code);
    }

    #[test]
    fn test_python_execution_result_serialization() {
        let result = PythonExecutionResult {
            success: true,
            exit_code: Some(0),
            stdout: "hello world\n".to_string(),
            stderr: "".to_string(),
            execution_time_ms: 150,
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["stdout"], "hello world\n");
        assert_eq!(json["execution_time_ms"], 150);
    }

    #[test]
    fn test_python_operation_serialization() {
        let operation = PythonOperation::Execute {
            code: "import math\nprint(math.pi)".to_string(),
        };

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: PythonOperation = serde_json::from_str(&json).unwrap();

        match deserialized {
            PythonOperation::Execute { code } => {
                assert!(code.contains("import math"));
                assert!(code.contains("print(math.pi)"));
            }
            _ => panic!("Wrong operation type deserialized"),
        }
    }

    #[test]
    fn test_python_execution_with_files_request() {
        let mut input_files = HashMap::new();
        input_files.insert("data.txt".to_string(), "test data".to_string());

        let request = PythonExecutionWithFilesRequest {
            code: "with open('data.txt') as f: print(f.read())".to_string(),
            input_files,
            expected_output_files: Some(vec!["output.txt".to_string()]),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: PythonExecutionWithFilesRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.code, deserialized.code);
        assert_eq!(
            request.input_files.get("data.txt"),
            deserialized.input_files.get("data.txt")
        );
        assert_eq!(
            request.expected_output_files,
            deserialized.expected_output_files
        );
    }

    #[test]
    fn test_python_package_deserialization() {
        let json = r#"[
            {"name": "numpy", "version": "1.21.0"},
            {"name": "pandas", "version": "1.3.0"}
        ]"#;

        let packages: Vec<PythonPackage> = serde_json::from_str(json).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "numpy");
        assert_eq!(packages[0].version, "1.21.0");
        assert_eq!(packages[1].name, "pandas");
        assert_eq!(packages[1].version, "1.3.0");
    }

    #[test]
    fn test_python_interpreter_creation() {
        let interpreter = PythonInterpreter::new("python".to_string());

        assert_eq!(interpreter.name(), "python_interpreter");
        assert!(interpreter.capabilities().contains(&ToolCapability::Basic));
        assert!(interpreter
            .capabilities()
            .contains(&ToolCapability::SystemAccess));
        assert_eq!(interpreter.timeout_seconds, 30);
        assert_eq!(interpreter.max_output_size, 1024 * 1024);
    }

    #[test]
    fn test_python_interpreter_configuration() {
        let interpreter = PythonInterpreter::new("python3".to_string())
            .with_timeout(60)
            .with_environment_var("TEST_VAR".to_string(), "test_value".to_string())
            .with_allowed_imports(vec!["custom_module".to_string()]);

        assert_eq!(interpreter.timeout_seconds, 60);
        assert_eq!(
            interpreter.environment_vars.get("TEST_VAR"),
            Some(&"test_value".to_string())
        );
        assert!(interpreter
            .allowed_imports
            .contains(&"custom_module".to_string()));
    }

    #[tokio::test]
    async fn test_validate_code_dangerous_patterns() {
        let interpreter = PythonInterpreter::new("python".to_string());

        // Test dangerous patterns
        let dangerous_codes = vec![
            "import subprocess",
            "exec('malicious code')",
            "eval('1+1')",
            "__import__('os')",
        ];

        for code in dangerous_codes {
            let result = interpreter.validate_code(code).await;
            assert!(result.is_err());
            assert!(format!("{:?}", result.unwrap_err()).contains("dangerous pattern"));
        }
    }

    #[tokio::test]
    async fn test_validate_code_allowed_imports() {
        let interpreter = PythonInterpreter::new("python".to_string());

        // Test allowed imports
        let safe_code = "import math\nimport json\nimport numpy as np\nprint(math.pi)";
        let result = interpreter.validate_code(safe_code).await;
        assert!(result.is_ok());

        // Test disallowed import
        let unsafe_code = "import unknown_module\nprint('test')";
        let result = interpreter.validate_code(unsafe_code).await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Import not allowed"));
    }

    #[tokio::test]
    async fn test_invalid_operation_parameters() {
        let interpreter = PythonInterpreter::new("python".to_string());

        let result = interpreter.invoke("invalid json").await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Invalid operation parameters"));
    }

    #[test]
    fn test_create_python_interpreter_from_env() {
        // Test creating interpreter with default settings
        let result = create_python_interpreter_from_env();
        assert!(result.is_ok());

        let interpreter = result.unwrap();
        assert!(interpreter.python_path.contains("python"));
    }

    #[test]
    fn test_python_operations_all_variants() {
        // Test that all variants can be created and serialized
        let operations = vec![
            PythonOperation::Execute {
                code: "print('test')".to_string(),
            },
            PythonOperation::ExecuteWithFiles {
                code: "print('test')".to_string(),
                input_files: HashMap::new(),
                expected_output_files: None,
            },
            PythonOperation::ListPackages,
        ];

        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            let _deserialized: PythonOperation = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_python_execution_result_failure() {
        let result = PythonExecutionResult {
            success: false,
            exit_code: Some(1),
            stdout: "".to_string(),
            stderr: "NameError: name 'undefined_var' is not defined".to_string(),
            execution_time_ms: 50,
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["exit_code"], 1);
        assert!(json["stderr"].as_str().unwrap().contains("NameError"));
    }

    #[test]
    fn test_large_output_handling() {
        let large_stdout = "x".repeat(2 * 1024 * 1024); // 2MB output
        let interpreter = PythonInterpreter::new("python".to_string());

        // Simulate truncation behavior
        let truncated = if large_stdout.len() > interpreter.max_output_size {
            format!(
                "{}... (truncated, {} bytes total)",
                &large_stdout[..interpreter.max_output_size],
                large_stdout.len()
            )
        } else {
            large_stdout.clone()
        };

        assert!(truncated.contains("truncated"));
        assert!(truncated.len() < large_stdout.len());
    }
}
