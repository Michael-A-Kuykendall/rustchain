use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

/// Sandbox with directory-based isolation and resource limits
pub struct EnhancedSandbox {
    sessions: Arc<RwLock<HashMap<String, SandboxSession>>>,
    temp_dir: PathBuf,
}

impl Default for EnhancedSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl EnhancedSandbox {
    pub fn new() -> Self {
        let temp_dir = std::env::temp_dir().join("rustchain_sandbox");
        if let Err(e) = std::fs::create_dir_all(&temp_dir) {
            tracing::warn!(
                "Failed to create sandbox temp directory {}: {}",
                temp_dir.display(),
                e
            );
        }

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            temp_dir,
        }
    }

    pub async fn create_session(&self, config: SandboxConfig) -> Result<String> {
        let session_id = Uuid::new_v4().to_string();
        let session_dir = self.temp_dir.join(&session_id);

        // Create isolated directory for this session
        tokio::fs::create_dir_all(&session_dir).await?;

        let session = SandboxSession {
            session_id: session_id.clone(),
            config,
            root_dir: session_dir,
            created_at: Utc::now(),
            status: SandboxStatus::Active,
            files: Vec::new(),
        };

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);

        info!("Created sandbox session: {}", session_id);
        Ok(session_id)
    }

    pub async fn execute_command(
        &self,
        session_id: &str,
        command: &str,
        args: Vec<String>,
    ) -> Result<CommandResult> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        // Check if command is allowed
        if !session.config.allowed_commands.is_empty()
            && !session
                .config
                .allowed_commands
                .contains(&command.to_string())
        {
            return Err(anyhow!("Command not allowed: {}", command));
        }

        debug!(
            "Executing command in sandbox {}: {} {:?}",
            session_id, command, args
        );

        let start = std::time::Instant::now();

        // Execute with resource limits
        let mut cmd = Command::new(command);
        cmd.args(&args)
            .current_dir(&session.root_dir)
            .kill_on_drop(true);

        // Apply environment restrictions
        cmd.env_clear();
        cmd.env("HOME", &session.root_dir);
        cmd.env("TMPDIR", &session.root_dir);
        cmd.env("PATH", "/usr/bin:/bin"); // Minimal PATH

        // Execute with timeout
        let timeout = std::time::Duration::from_secs(session.config.timeout_seconds);
        let output = match tokio::time::timeout(timeout, cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => return Err(anyhow!("Command execution failed: {}", e)),
            Err(_) => {
                return Err(anyhow!(
                    "Command timed out after {} seconds",
                    session.config.timeout_seconds
                ))
            }
        };

        let duration = start.elapsed();

        Ok(CommandResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            execution_time_ms: duration.as_millis() as u64,
        })
    }

    pub async fn write_file(
        &self,
        session_id: &str,
        relative_path: &str,
        content: &[u8],
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        // Ensure path is relative and doesn't escape sandbox
        let path = Path::new(relative_path);
        if path.is_absolute()
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow!("Invalid path: must be relative and within sandbox"));
        }

        let full_path = session.root_dir.join(path);

        // Canonicalize and verify the path is within the sandbox root
        let canonical_path = full_path
            .canonicalize()
            .map_err(|e| anyhow!("Path canonicalization failed: {}", e))?;
        let canonical_root = session
            .root_dir
            .canonicalize()
            .map_err(|e| anyhow!("Root canonicalization failed: {}", e))?;

        if !canonical_path.starts_with(&canonical_root) {
            return Err(anyhow!(
                "Path escapes sandbox: resolved path is outside sandbox root"
            ));
        }

        // Create parent directories if needed
        if let Some(parent) = full_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&full_path, content).await?;

        // Track file in session
        session.files.push(relative_path.to_string());

        debug!("Wrote file in sandbox {}: {}", session_id, relative_path);
        Ok(())
    }

    pub async fn read_file(&self, session_id: &str, relative_path: &str) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        // Ensure path is relative and doesn't escape sandbox
        let path = Path::new(relative_path);
        if path.is_absolute()
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow!("Invalid path: must be relative and within sandbox"));
        }

        let full_path = session.root_dir.join(path);

        // Canonicalize and verify the path is within the sandbox root
        let canonical_path = full_path
            .canonicalize()
            .map_err(|e| anyhow!("Path canonicalization failed: {}", e))?;
        let canonical_root = session
            .root_dir
            .canonicalize()
            .map_err(|e| anyhow!("Root canonicalization failed: {}", e))?;

        if !canonical_path.starts_with(&canonical_root) {
            return Err(anyhow!(
                "Path escapes sandbox: resolved path is outside sandbox root"
            ));
        }

        let content = tokio::fs::read(&full_path).await?;

        debug!("Read file from sandbox {}: {}", session_id, relative_path);
        Ok(content)
    }

    pub async fn list_files(&self, session_id: &str) -> Result<Vec<String>> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        let mut files = Vec::new();
        let mut stack = vec![session.root_dir.clone()];

        while let Some(dir) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&dir).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let relative = path
                    .strip_prefix(&session.root_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                if entry.file_type().await?.is_dir() {
                    stack.push(path);
                    files.push(format!("{}/", relative));
                } else {
                    files.push(relative);
                }
            }
        }

        Ok(files)
    }

    pub async fn destroy_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        if let Some(mut session) = sessions.remove(session_id) {
            session.status = SandboxStatus::Destroyed;

            // Clean up filesystem
            if session.root_dir.exists() {
                tokio::fs::remove_dir_all(&session.root_dir).await?;
            }

            info!("Destroyed sandbox session: {}", session_id);
            Ok(())
        } else {
            Err(anyhow!("Session not found: {}", session_id))
        }
    }

    pub async fn get_session_info(&self, session_id: &str) -> Result<SandboxInfo> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        Ok(SandboxInfo {
            session_id: session.session_id.clone(),
            status: session.status.clone(),
            created_at: session.created_at,
            config: session.config.clone(),
            files_count: session.files.len(),
            root_dir: session.root_dir.to_string_lossy().to_string(),
        })
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        let mut cleaned = 0;

        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| {
                let age = now.signed_duration_since(session.created_at);
                age.num_seconds() > session.config.timeout_seconds as i64
            })
            .map(|(id, _)| id.clone())
            .collect();

        for session_id in expired {
            if let Some(session) = sessions.remove(&session_id) {
                if session.root_dir.exists() {
                    if let Err(e) = tokio::fs::remove_dir_all(&session.root_dir).await {
                        tracing::warn!("Failed to cleanup sandbox session {}: {}", session_id, e);
                    }
                }
                cleaned += 1;
                info!("Cleaned up expired sandbox: {}", session_id);
            }
        }

        Ok(cleaned)
    }
}

/// Result of sandbox command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time_ms: u64,
}

/// Create a default sandbox manager
pub fn create_default_sandbox() -> SandboxManager {
    SandboxManager::new()
}

/// Sandbox manager for managing multiple sandbox sessions
pub struct SandboxManager {
    sandbox: Arc<EnhancedSandbox>,
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxManager {
    pub fn new() -> Self {
        Self {
            sandbox: Arc::new(EnhancedSandbox::new()),
        }
    }

    pub async fn create_sandbox(&self, config: SandboxConfig) -> Result<String> {
        self.sandbox.create_session(config).await
    }

    pub async fn execute_in_sandbox(
        &self,
        session_id: &str,
        command: &str,
        args: Vec<String>,
    ) -> Result<CommandResult> {
        self.sandbox
            .execute_command(session_id, command, args)
            .await
    }

    pub async fn write_file(&self, session_id: &str, path: &str, content: &[u8]) -> Result<()> {
        self.sandbox.write_file(session_id, path, content).await
    }

    pub async fn read_file(&self, session_id: &str, path: &str) -> Result<Vec<u8>> {
        self.sandbox.read_file(session_id, path).await
    }

    pub async fn list_files(&self, session_id: &str) -> Result<Vec<String>> {
        self.sandbox.list_files(session_id).await
    }

    pub async fn get_sandbox_info(&self, session_id: &str) -> Result<SandboxInfo> {
        self.sandbox.get_session_info(session_id).await
    }

    pub async fn destroy_sandbox(&self, session_id: &str) -> Result<()> {
        self.sandbox.destroy_session(session_id).await
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxInfo>> {
        let sessions = self.sandbox.sessions.read().await;
        let mut infos = Vec::new();

        for session in sessions.values() {
            infos.push(SandboxInfo {
                session_id: session.session_id.clone(),
                status: session.status.clone(),
                created_at: session.created_at,
                config: session.config.clone(),
                files_count: session.files.len(),
                root_dir: session.root_dir.to_string_lossy().to_string(),
            });
        }

        Ok(infos)
    }

    pub async fn cleanup_sandbox(&self, session_id: &str) -> Result<()> {
        let sessions = self.sandbox.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        // Clear files but keep session alive
        let root_dir = session.root_dir.clone();
        drop(sessions);

        // Remove all files but keep directory
        let mut entries = tokio::fs::read_dir(&root_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if entry.file_type().await?.is_dir() {
                tokio::fs::remove_dir_all(path).await?;
            } else {
                tokio::fs::remove_file(path).await?;
            }
        }

        // Clear file list
        let mut sessions = self.sandbox.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.files.clear();
        }

        Ok(())
    }

    pub async fn cleanup_all(&self) -> Result<usize> {
        self.sandbox.cleanup_expired_sessions().await
    }
}

/// Configuration for a sandbox session
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub memory_limit_mb: usize,
    pub cpu_limit_percent: f32,
    pub timeout_seconds: u64,
    pub allowed_commands: Vec<String>,
    pub network_enabled: bool,
    pub filesystem_access: Vec<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit_mb: 256,
            cpu_limit_percent: 25.0,
            timeout_seconds: 300,
            allowed_commands: vec![
                "echo".to_string(),
                "cat".to_string(),
                "ls".to_string(),
                "pwd".to_string(),
                "date".to_string(),
            ],
            network_enabled: false,
            filesystem_access: vec![],
        }
    }
}

/// Information about a sandbox session
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub session_id: String,
    pub status: SandboxStatus,
    pub created_at: DateTime<Utc>,
    pub config: SandboxConfig,
    pub files_count: usize,
    pub root_dir: String,
}

/// Status of a sandbox session
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SandboxStatus {
    Active,
    Suspended,
    Destroyed,
}

/// Result of a command execution in sandbox
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time_ms: u64,
}

/// Internal sandbox session state
struct SandboxSession {
    session_id: String,
    config: SandboxConfig,
    root_dir: PathBuf,
    created_at: DateTime<Utc>,
    status: SandboxStatus,
    files: Vec<String>,
}

/// Simple sandbox for basic isolation (legacy compatibility)
pub struct AgentSandbox {
    allowed_paths: Vec<PathBuf>,
    timeout_seconds: u64,
    allowed_commands: Vec<String>,
}

impl AgentSandbox {
    pub fn new() -> Self {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        Self {
            allowed_paths: vec![current_dir],
            timeout_seconds: 30,
            allowed_commands: vec!["echo".to_string(), "cat".to_string(), "ls".to_string()],
        }
    }

    pub fn execute(&self, code: &str) -> Result<String, String> {
        // Parse the code to determine action
        if code.starts_with("create_file:") {
            let path = code
                .strip_prefix("create_file:")
                .ok_or_else(|| "Invalid create_file command format".to_string())?;
            if self.is_path_allowed(Path::new(path)) {
                Ok(format!("File creation allowed: {}", path))
            } else {
                Err(format!("Path not allowed: {}", path))
            }
        } else if code.starts_with("command:") {
            let command = code
                .strip_prefix("command:")
                .ok_or_else(|| "Invalid command format".to_string())?;
            if self.is_command_allowed(command) {
                Ok(format!("Command allowed: {}", command))
            } else {
                Err(format!("Command not allowed: {}", command))
            }
        } else {
            Ok(format!("Sandbox check passed: {}", code))
        }
    }

    fn is_path_allowed(&self, path: &Path) -> bool {
        // Check if path is under any allowed directory
        for allowed in &self.allowed_paths {
            if path.starts_with(allowed) {
                // Also check for path traversal attempts
                let canonical = path.canonicalize().ok();
                if let Some(canonical_path) = canonical {
                    if canonical_path.starts_with(allowed) {
                        return true;
                    }
                } else {
                    tracing::warn!(
                        "Failed to canonicalize path {} during validation",
                        path.display()
                    );
                }
            }
        }
        false
    }

    fn is_command_allowed(&self, command: &str) -> bool {
        // Extract just the command name (before any arguments)
        let cmd_name = command.split_whitespace().next().unwrap_or("");
        self.allowed_commands
            .iter()
            .any(|allowed| allowed == cmd_name)
    }

    pub fn add_allowed_path(&mut self, path: PathBuf) {
        self.allowed_paths.push(path);
    }

    pub fn add_allowed_command(&mut self, command: String) {
        self.allowed_commands.push(command);
    }

    pub fn set_timeout(&mut self, seconds: u64) {
        self.timeout_seconds = seconds;
    }
}

impl Default for AgentSandbox {
    fn default() -> Self {
        Self::new()
    }
}
