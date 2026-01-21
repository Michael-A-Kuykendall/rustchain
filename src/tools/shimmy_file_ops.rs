use crate::tools::{RuntimeContext, ToolCall, ToolExecutor, ToolResult};
use anyhow::anyhow;
use async_trait::async_trait;
#[allow(unused_imports)]
// PathBuf is used in to_path_buf() calls but compiler doesn't detect it
use std::path::{Path, PathBuf};

// NOTE: Path security validation removed as of snap-in implementation.
// Per the new security model, file_ops tools have full filesystem access by default.
// Future opt-in restrictions may be added via per-tool permissions in snap-in definitions.
// See SNAPIN_READ_IMAGE_PLAN.md Section 3 for details.

pub struct ReadFileTool;
pub struct WriteFileTool;
pub struct ListFilesTool;
pub struct SearchFilesTool;

#[async_trait]
impl ToolExecutor for ReadFileTool {
    async fn execute(
        &self,
        call: ToolCall,
        _context: &RuntimeContext,
    ) -> anyhow::Result<ToolResult> {
        let start = std::time::Instant::now();

        let file_path = call
            .parameters
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("path parameter required"))?;

        // Security: Sanitize file path to prevent path traversal attacks
        use crate::engine::sanitize_file_path;
        let sanitized_path = sanitize_file_path(file_path)?;

        // Resolve path (absolute or relative to current working directory)
        let working_dir = std::env::current_dir()
            .map_err(|e| anyhow!("Failed to get current directory: {}", e))?;
        let target_path = if Path::new(&sanitized_path).is_absolute() {
            PathBuf::from(&sanitized_path)
        } else {
            working_dir.join(&sanitized_path)
        };

        // Additional security: Check file size to prevent memory exhaustion
        let metadata = tokio::fs::metadata(&target_path).await;
        match metadata {
            Ok(meta) => {
                let file_size = meta.len();
                let max_file_size = 10 * 1024 * 1024; // 10MB limit
                if file_size > max_file_size {
                    return Ok(ToolResult {
                        success: false,
                        output: serde_json::json!({
                            "error": format!("File too large: {} bytes (max: {} bytes)", file_size, max_file_size)
                        }),
                        error: Some("File size exceeds security limit".to_string()),
                        execution_time_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: serde_json::json!({"error": format!("Failed to access file: {}", e)}),
                    error: Some(format!("Failed to access file: {}", e)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                });
            }
        }

        match tokio::fs::read_to_string(&target_path).await {
            Ok(content) => {
                let content_len = content.len();
                Ok(ToolResult {
                    success: true,
                    output: serde_json::json!({
                        "content": content,
                        "file_path": target_path.to_string_lossy(),
                        "size_bytes": content_len
                    }),
                    error: None,
                    execution_time_ms: start.elapsed().as_millis() as u64,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: serde_json::json!({"error": format!("Failed to read file: {}", e)}),
                error: Some(format!("Failed to read file: {}", e)),
                execution_time_ms: start.elapsed().as_millis() as u64,
            }),
        }
    }

    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "Read contents of a file"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to read"
                }
            },
            "required": ["path"]
        })
    }
}

#[async_trait]
impl ToolExecutor for WriteFileTool {
    async fn execute(
        &self,
        call: ToolCall,
        _context: &RuntimeContext,
    ) -> anyhow::Result<ToolResult> {
        let start = std::time::Instant::now();

        let file_path = call
            .parameters
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("path parameter required"))?;
        let content = call
            .parameters
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Security: Sanitize file path to prevent path traversal attacks
        use crate::engine::sanitize_file_path;
        let sanitized_path = sanitize_file_path(file_path)?;

        // Security: Limit content size to prevent memory exhaustion
        let max_content_size = 10 * 1024 * 1024; // 10MB limit
        if content.len() > max_content_size {
            return Ok(ToolResult {
                success: false,
                output: serde_json::json!({
                    "error": format!("Content too large: {} bytes (max: {} bytes)", content.len(), max_content_size)
                }),
                error: Some("Content size exceeds security limit".to_string()),
                execution_time_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Resolve path (absolute or relative to current working directory)
        let working_dir = std::env::current_dir()
            .map_err(|e| anyhow!("Failed to get current directory: {}", e))?;
        let target_path = if Path::new(&sanitized_path).is_absolute() {
            PathBuf::from(&sanitized_path)
        } else {
            working_dir.join(&sanitized_path)
        };

        // Create parent directories if needed (with security check)
        if let Some(parent) = target_path.parent() {
            // Ensure parent directory is within allowed bounds
            let parent_str = parent.to_string_lossy();
            if parent_str.contains("..") || parent_str.len() > 4096 {
                return Ok(ToolResult {
                    success: false,
                    output: serde_json::json!({"error": "Invalid parent directory path"}),
                    error: Some(
                        "Parent directory path contains invalid characters or is too long"
                            .to_string(),
                    ),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                });
            }
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| anyhow!("Failed to create directories: {}", e))?;
        }

        match tokio::fs::write(&target_path, content).await {
            Ok(_) => Ok(ToolResult {
                success: true,
                output: serde_json::json!({
                    "message": "File written successfully",
                    "file_path": target_path.to_string_lossy(),
                    "size_bytes": content.len()
                }),
                error: None,
                execution_time_ms: start.elapsed().as_millis() as u64,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: serde_json::json!({"error": format!("Failed to write file: {}", e)}),
                error: Some(format!("Failed to write file: {}", e)),
                execution_time_ms: start.elapsed().as_millis() as u64,
            }),
        }
    }

    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "Write content to a file"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to write to"
                },
                "content": {
                    "type": "string",
                    "description": "The content to write to the file"
                }
            },
            "required": ["path"]
        })
    }
}

#[async_trait]
impl ToolExecutor for ListFilesTool {
    async fn execute(
        &self,
        call: ToolCall,
        _context: &RuntimeContext,
    ) -> anyhow::Result<ToolResult> {
        let start = std::time::Instant::now();

        let dir_path = call
            .parameters
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(".");

        // Resolve path (absolute or relative to current working directory)
        let working_dir = std::env::current_dir()
            .map_err(|e| anyhow!("Failed to get current directory: {}", e))?;
        let target_path = if Path::new(dir_path).is_absolute() {
            PathBuf::from(dir_path)
        } else {
            working_dir.join(dir_path)
        };

        match tokio::fs::read_dir(&target_path).await {
            Ok(mut entries) => {
                let mut files = Vec::new();
                while let Some(entry) = entries
                    .next_entry()
                    .await
                    .map_err(|e| anyhow!("Error reading directory: {}", e))?
                {
                    let metadata = entry
                        .metadata()
                        .await
                        .map_err(|e| anyhow!("Error reading metadata: {}", e))?;

                    files.push(serde_json::json!({
                        "name": entry.file_name().to_string_lossy(),
                        "is_dir": metadata.is_dir(),
                        "size": metadata.len(),
                    }));
                }

                Ok(ToolResult {
                    success: true,
                    output: serde_json::json!({
                        "directory": target_path.to_string_lossy(),
                        "files": files,
                        "count": files.len()
                    }),
                    error: None,
                    execution_time_ms: start.elapsed().as_millis() as u64,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: serde_json::json!({"error": format!("Failed to list directory: {}", e)}),
                error: Some(format!("Failed to list directory: {}", e)),
                execution_time_ms: start.elapsed().as_millis() as u64,
            }),
        }
    }

    fn name(&self) -> &str {
        "list_files"
    }

    fn description(&self) -> &str {
        "List files in a directory"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The directory path to list (defaults to current directory)"
                }
            }
        })
    }
}

#[async_trait]
impl ToolExecutor for SearchFilesTool {
    async fn execute(
        &self,
        call: ToolCall,
        _context: &RuntimeContext,
    ) -> anyhow::Result<ToolResult> {
        let start = std::time::Instant::now();

        let pattern = call
            .parameters
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("pattern parameter required"))?;
        let dir_path = call
            .parameters
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(".");

        // Resolve path (absolute or relative to current working directory)
        let working_dir = std::env::current_dir()
            .map_err(|e| anyhow!("Failed to get current directory: {}", e))?;
        let target_path = if Path::new(dir_path).is_absolute() {
            PathBuf::from(dir_path)
        } else {
            working_dir.join(dir_path)
        };

        let mut matches = Vec::new();

        if let Ok(mut entries) = tokio::fs::read_dir(&target_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = tokio::fs::read_to_string(&path).await {
                        for (line_num, line) in content.lines().enumerate() {
                            if line.contains(pattern) {
                                matches.push(serde_json::json!({
                                    "file": path.file_name().unwrap_or_default().to_string_lossy(),
                                    "line": line_num + 1,
                                    "content": line.trim()
                                }));
                            }
                        }
                    }
                }
            }
        }

        Ok(ToolResult {
            success: true,
            output: serde_json::json!({
                "pattern": pattern,
                "directory": target_path.to_string_lossy(),
                "matches": matches,
                "count": matches.len()
            }),
            error: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn name(&self) -> &str {
        "search_files"
    }

    fn description(&self) -> &str {
        "Search for files by pattern"
    }

    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "The text pattern to search for"
                },
                "path": {
                    "type": "string",
                    "description": "The directory path to search in (defaults to current directory)"
                }
            },
            "required": ["pattern"]
        })
    }
}
