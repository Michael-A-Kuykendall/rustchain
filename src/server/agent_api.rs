use anyhow::Result;
use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

// Future imports for when we implement full agent reasoning
// use crate::core::agent::{Agent, AgentAction, AgentState, MultiAgentSystem};
// use crate::core::memory::{InMemoryStore, MemoryStore};
// use crate::core::tools::ToolRegistry;
use crate::core::RuntimeContext;
#[cfg(feature = "llm")]
use crate::llm::{create_default_llm_manager, ChatMessage, LLMRequest, MessageRole};
use crate::server::{ApiResponse, AppState};
#[cfg(feature = "tools")]
use crate::tools::{create_default_tool_manager, ToolCall, ToolResult as ToolsToolResult};

/// Agent API request types
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentMessageRequest {
    pub message: String,
    pub context: Option<SessionContext>,
    pub options: Option<MessageOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionContext {
    pub current_directory: Option<String>,
    pub session_id: Option<String>,
    pub conversation_history: Option<Vec<String>>,
    pub active_files: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageOptions {
    pub model: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: Option<bool>,
}

impl Default for MessageOptions {
    fn default() -> Self {
        Self {
            model: Some("shimmy:phi3-mini".to_string()),
            temperature: Some(0.7),
            max_tokens: Some(2000),
            stream: Some(false),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolExecutionRequest {
    pub tool: String,
    pub parameters: serde_json::Value,
    pub context: Option<SessionContext>,
}

/// Agent API response types
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentMessageResponse {
    pub response: String,
    pub session_id: String,
    pub message_id: String,
    pub tokens_used: u32,
    pub processing_time_ms: u64,
    pub tools_called: Vec<ToolCallInfo>,
    pub agent_actions: Vec<AgentActionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolCallInfo {
    pub tool: String,
    pub parameters: serde_json::Value,
    pub result: serde_json::Value,
    pub success: bool,
    pub execution_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentActionInfo {
    pub action_type: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolExecutionResponse {
    pub tool: String,
    pub result: serde_json::Value,
    pub execution_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionContextResponse {
    pub session_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub message_count: usize,
    pub context: SessionContextData,
    pub conversation_history: Vec<ConversationMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContextData {
    pub current_directory: Option<String>,
    pub active_files: Vec<String>,
    pub project_type: Option<String>,
    pub conversation_summary: String,
    pub available_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub id: String,
    pub role: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// File operations request/response types
#[derive(Debug, Serialize, Deserialize)]
pub struct FileReadRequest {
    pub path: String,
    pub encoding: Option<String>, // utf-8, binary, base64
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileWriteRequest {
    pub path: String,
    pub content: String,
    pub encoding: Option<String>,
    pub create_directories: Option<bool>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEditRequest {
    pub path: String,
    pub edits: Vec<FileEdit>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEdit {
    pub line_start: usize,
    pub line_end: usize,
    pub new_content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDeleteRequest {
    pub path: String,
    pub force: Option<bool>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileListRequest {
    pub path: String,
    pub recursive: Option<bool>,
    pub include_hidden: Option<bool>,
    pub max_depth: Option<usize>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileReadResponse {
    pub path: String,
    pub content: String,
    pub size_bytes: u64,
    pub encoding: String,
    pub last_modified: chrono::DateTime<chrono::Utc>,
    pub is_binary: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileWriteResponse {
    pub path: String,
    pub size_bytes: u64,
    pub created: bool, // true if file was created, false if updated
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEditResponse {
    pub path: String,
    pub edits_applied: usize,
    pub new_size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileDeleteResponse {
    pub path: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileListResponse {
    pub path: String,
    pub entries: Vec<FileEntry>,
    pub total_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size_bytes: Option<u64>,
    pub last_modified: chrono::DateTime<chrono::Utc>,
    pub permissions: Option<String>,
}

/// Agent session management
#[derive(Debug, Clone)]
pub struct AgentSession {
    pub session_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub message_count: usize,
    pub context: SessionContextData,
    pub conversation_history: Vec<ConversationMessage>,
}

impl AgentSession {
    pub fn new(session_id: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            session_id,
            created_at: now,
            last_activity: now,
            message_count: 0,
            context: SessionContextData {
                current_directory: std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(|s| s.to_string())),
                active_files: Vec::new(),
                project_type: None,
                conversation_summary: "New conversation started".to_string(),
                available_tools: vec![
                    "file_read".to_string(),
                    "file_write".to_string(),
                    "directory_list".to_string(),
                    "command_execute".to_string(),
                    "punch_discover".to_string(),
                    "git_status".to_string(),
                ],
            },
            conversation_history: Vec::new(),
        }
    }

    pub fn add_message(&mut self, role: &str, content: &str) -> String {
        let message_id = format!("msg_{}", Uuid::new_v4().simple());
        let message = ConversationMessage {
            id: message_id.clone(),
            role: role.to_string(),
            content: content.to_string(),
            timestamp: chrono::Utc::now(),
        };

        self.conversation_history.push(message);
        self.message_count += 1;
        self.last_activity = chrono::Utc::now();

        // Keep only last 50 messages for memory efficiency
        if self.conversation_history.len() > 50 {
            self.conversation_history
                .drain(..self.conversation_history.len() - 50);
        }

        message_id
    }

    pub fn update_context(&mut self, context: &SessionContext) {
        if let Some(dir) = &context.current_directory {
            self.context.current_directory = Some(dir.clone());
        }
        if let Some(files) = &context.active_files {
            self.context.active_files = files.clone();
        }
        self.last_activity = chrono::Utc::now();
    }
}

/// Agent session store
pub type AgentSessionStore = Arc<RwLock<HashMap<String, AgentSession>>>;

/// Create agent API router
pub fn create_agent_router() -> Router<AppState> {
    Router::new()
        .route("/agent/message", post(handle_agent_message))
        .route("/agent/tool", post(handle_tool_execution))
        .route("/agent/context/:session_id", get(handle_get_context))
        .route("/agent/context", post(handle_create_context))
        .route("/agent/sessions", get(handle_list_sessions))
        .route("/agent/sessions/cleanup", post(handle_cleanup_sessions))
        // OpenAI-compatible endpoint for Shimmy integration
        .route("/v1/chat/completions", post(handle_openai_chat_completions))
        // File operations API
        .route("/agent/file/read", post(handle_file_read))
        .route("/agent/file/write", post(handle_file_write))
        .route("/agent/file/edit", post(handle_file_edit))
        .route("/agent/file/delete", post(handle_file_delete))
        .route("/agent/file/list", post(handle_file_list))
        // Code analysis API (PUNCH integration for project understanding)
        .route("/agent/analyze", post(handle_project_analysis))
        // System commands API (safe shell execution with output)
        .route("/agent/execute", post(handle_command_execution))
        // Git operations API (status, commit, push, pull, branch)
        .route("/agent/git", post(handle_git_operation))
}

/// Handle agent message processing
pub async fn handle_agent_message(
    State(app_state): State<AppState>,
    Json(request): Json<AgentMessageRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();

    info!(
        "Processing agent message: {}",
        &request.message[..request.message.len().min(100)]
    );

    // Get or create session
    let session_id = request
        .context
        .as_ref()
        .and_then(|c| c.session_id.clone())
        .unwrap_or_else(|| format!("sess_{}", Uuid::new_v4().simple()));

    // Get or create session from persistent store
    let mut session = match get_session_from_store(&session_id, &app_state).await {
        Ok(existing_session) => existing_session,
        Err(_) => {
            // Create new session if not found
            let new_session = AgentSession::new(session_id.clone());
            if let Err(e) = store_session_in_store(new_session.clone(), &app_state).await {
                warn!("Failed to store new session: {}", e);
            }
            new_session
        }
    };

    // Update session context if provided
    if let Some(context) = &request.context {
        session.update_context(context);
    }

    // Add user message to conversation history
    let _user_message_id = session.add_message("user", &request.message);

    match process_agent_message(&request, &session, &app_state).await {
        Ok(mut response) => {
            response.session_id = session_id.clone();
            response.processing_time_ms = start_time.elapsed().as_millis() as u64;

            // Add assistant response to conversation history
            session.add_message("assistant", &response.response);

            // Update session in persistent store
            if let Err(e) = store_session_in_store(session, &app_state).await {
                warn!("Failed to update session in store: {}", e);
            }

            info!(
                "Agent message processed successfully in {}ms",
                response.processing_time_ms
            );

            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Agent message processing failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Agent processing failed: {}",
                    e
                ))),
            )
                .into_response()
        }
    }
}

/// Process agent message with full ReAct pattern
#[cfg(feature = "llm")]
async fn process_agent_message(
    request: &AgentMessageRequest,
    session: &AgentSession,
    _app_state: &AppState,
) -> Result<AgentMessageResponse> {
    let default_options = MessageOptions::default();
    let options = request.options.as_ref().unwrap_or(&default_options);

    // Create LLM manager
    let llm_manager = create_default_llm_manager()
        .map_err(|e| anyhow::anyhow!("Failed to create LLM manager: {}", e))?;

    // Prepare conversation context
    let mut messages = Vec::new();

    // Add system prompt
    let system_prompt = format!(
        "You are an AI coding assistant powered by RustChain. You have access to powerful tools for file operations, code analysis, git operations, and system commands.

Current context:
- Directory: {}
- Active files: {}
- Available tools: {}
- Conversation: {}

When you need to use tools, describe your plan first, then use the tools to accomplish the task. Be thorough and helpful.",
        session.context.current_directory.as_deref().unwrap_or("unknown"),
        session.context.active_files.join(", "),
        session.context.available_tools.join(", "),
        session.context.conversation_summary
    );

    messages.push(ChatMessage {
        role: MessageRole::System,
        content: system_prompt,
        name: None,
        tool_calls: None,
        tool_call_id: None,
    });

    // Add recent conversation history (last 10 messages for context)
    for msg in session.conversation_history.iter().rev().take(10).rev() {
        let role = match msg.role.as_str() {
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            _ => MessageRole::User,
        };

        messages.push(ChatMessage {
            role,
            content: msg.content.clone(),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });
    }

    // Add current user message
    messages.push(ChatMessage {
        role: MessageRole::User,
        content: request.message.clone(),
        name: None,
        tool_calls: None,
        tool_call_id: None,
    });

    // Create LLM request
    let llm_request = LLMRequest {
        messages,
        model: options.model.clone(),
        temperature: options.temperature,
        max_tokens: options.max_tokens,
        stream: options.stream.unwrap_or(false),
        tools: None, // Tool definitions integration planned - requires full ReAct pattern implementation
        metadata: HashMap::new(),
    };

    // Get LLM response
    let llm_response = llm_manager
        .complete(llm_request, None)
        .await
        .map_err(|e| anyhow::anyhow!("LLM request failed: {}", e))?;

    // Calculate dynamic confidence based on response characteristics
    let response_length = llm_response.content.len();
    let confidence = if response_length > 1000 {
        0.95 // Long, detailed responses are likely more confident
    } else if response_length > 500 {
        0.85
    } else if response_length > 100 {
        0.75
    } else {
        0.60 // Short responses might be less confident
    };

    Ok(AgentMessageResponse {
        response: llm_response.content,
        session_id: session.session_id.clone(),
        message_id: uuid::Uuid::new_v4().to_string(),
        tokens_used: llm_response.usage.total_tokens,
        processing_time_ms: 0,    // Will be set by caller
        tools_called: Vec::new(), // Tool call tracking integration planned with ReAct pattern
        agent_actions: vec![AgentActionInfo {
            action_type: "llm_response".to_string(),
            description: "Generated response using LLM".to_string(),
            confidence,
        }],
    })
}

/// Process agent message fallback when LLM feature is disabled
#[cfg(not(feature = "llm"))]
async fn process_agent_message(
    request: &AgentMessageRequest,
    session: &AgentSession,
    _app_state: &AppState,
) -> Result<AgentMessageResponse> {
    let message_id = format!("msg_{}", Uuid::new_v4().simple());

    Ok(AgentMessageResponse {
        response: "Agent processing requires LLM feature to be enabled".to_string(),
        session_id: session.session_id.clone(),
        message_id,
        tokens_used: 0,
        processing_time_ms: 0, // Will be set by caller
        tools_called: Vec::new(),
        agent_actions: vec![AgentActionInfo {
            action_type: "feature_disabled".to_string(),
            description: "LLM feature not enabled".to_string(),
            confidence: 1.0,
        }],
    })
}

/// Execute tool with runtime context
#[cfg(feature = "tools")]
async fn execute_tool_with_context(
    request: &ToolExecutionRequest,
    _app_state: &AppState,
) -> Result<ToolsToolResult> {
    // Create a runtime context for tool execution
    let runtime_context = RuntimeContext::new();

    // Create tool manager with all available tools
    let tool_manager = create_default_tool_manager();

    // Create tool call from request
    let mut tool_call = ToolCall::new(request.tool.clone(), request.parameters.clone());

    // Add session context as metadata if provided
    if let Some(context) = &request.context {
        if let Some(session_id) = &context.session_id {
            tool_call
                .metadata
                .insert("session_id".to_string(), serde_json::json!(session_id));
        }
        if let Some(current_dir) = &context.current_directory {
            tool_call.metadata.insert(
                "current_directory".to_string(),
                serde_json::json!(current_dir),
            );
        }
    }

    // Execute the tool
    tool_manager.execute_tool(tool_call, &runtime_context).await
}

/// Execute tool fallback when tools feature is disabled  
#[cfg(not(feature = "tools"))]
async fn execute_tool_with_context(
    _request: &ToolExecutionRequest,
    _app_state: &AppState,
) -> Result<MockToolResult> {
    Ok(MockToolResult {
        success: false,
        output: serde_json::json!({"error": "Tools feature not enabled"}),
        error: Some("Tools feature not enabled".to_string()),
        execution_time_ms: 0,
    })
}

/// Mock tool result when tools feature is disabled
#[cfg(not(feature = "tools"))]
#[derive(Debug, Serialize, Deserialize)]
struct MockToolResult {
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

/// Handle tool execution
pub async fn handle_tool_execution(
    State(app_state): State<AppState>,
    Json(request): Json<ToolExecutionRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();

    info!(
        "Executing tool: {} with parameters: {}",
        request.tool, request.parameters
    );

    match execute_tool_with_context(&request, &app_state).await {
        Ok(result) => {
            let response = ToolExecutionResponse {
                tool: request.tool,
                result: result.output,
                execution_time_ms: result.execution_time_ms,
                success: result.success,
                error: result.error,
            };

            info!(
                "Tool execution completed in {}ms",
                response.execution_time_ms
            );
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Tool execution failed: {}", e);
            let response = ToolExecutionResponse {
                tool: request.tool,
                result: serde_json::json!({"error": e.to_string()}),
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                success: false,
                error: Some(e.to_string()),
            };

            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::success(response)), // Return as success but with error details
            )
                .into_response()
        }
    }
}

/// Handle context retrieval
pub async fn handle_get_context(
    State(app_state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    info!("Retrieving context for session: {}", session_id);

    match get_session_from_store(&session_id, &app_state).await {
        Ok(session) => {
            let response = SessionContextResponse {
                session_id: session.session_id,
                created_at: session.created_at,
                last_activity: session.last_activity,
                message_count: session.message_count,
                context: session.context,
                conversation_history: session.conversation_history,
            };

            Json(ApiResponse::success(response)).into_response()
        }
        Err(_) => {
            // Session not found, return error
            (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::<()>::error(format!(
                    "Session '{}' not found",
                    session_id
                ))),
            )
                .into_response()
        }
    }
}

/// Handle context creation
pub async fn handle_create_context(
    State(app_state): State<AppState>,
    Json(context): Json<SessionContext>,
) -> impl IntoResponse {
    let session_id = context
        .session_id
        .unwrap_or_else(|| format!("sess_{}", Uuid::new_v4().simple()));

    info!("Creating new context for session: {}", session_id);

    // Create new session
    let mut new_session = AgentSession::new(session_id.clone());

    // Update with provided context
    if let Some(dir) = context.current_directory {
        new_session.context.current_directory = Some(dir);
    }
    if let Some(files) = context.active_files {
        new_session.context.active_files = files;
    }

    // Store in session store
    match store_session_in_store(new_session.clone(), &app_state).await {
        Ok(_) => {
            let response = SessionContextResponse {
                session_id: new_session.session_id,
                created_at: new_session.created_at,
                last_activity: new_session.last_activity,
                message_count: new_session.message_count,
                context: new_session.context,
                conversation_history: new_session.conversation_history,
            };

            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Failed to store session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(
                    "Failed to create session".to_string(),
                )),
            )
                .into_response()
        }
    }
}

/// Global session store management functions
async fn get_session_from_store(session_id: &str, app_state: &AppState) -> Result<AgentSession> {
    // Use in-memory session store for community edition
    app_state
        .session_store
        .get(session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))
}

async fn store_session_in_store(session: AgentSession, app_state: &AppState) -> Result<()> {
    // Use in-memory session store for community edition
    app_state.session_store.store(session).await
}

/// Enhanced session store that will be part of AppState
pub struct PersistentSessionStore {
    sessions: Arc<RwLock<HashMap<String, AgentSession>>>,
}

impl Default for PersistentSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, session_id: &str) -> Option<AgentSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn store(&self, session: AgentSession) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    pub async fn update(&self, session_id: &str, session: AgentSession) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.to_string(), session);
        Ok(())
    }

    pub async fn list_sessions(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }

    pub async fn cleanup_old_sessions(&self, max_age_hours: u64) -> usize {
        let mut sessions = self.sessions.write().await;
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(max_age_hours as i64);

        let old_sessions: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| session.last_activity < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        for session_id in &old_sessions {
            sessions.remove(session_id);
        }

        old_sessions.len()
    }
}

/// Handle session listing
pub async fn handle_list_sessions(State(_app_state): State<AppState>) -> impl IntoResponse {
    info!("Listing all active sessions");

    // Community edition: session persistence not implemented
    Json(ApiResponse::<()>::error("Session persistence requires enterprise features. Use --features enterprise to enable session management.".to_string()))
        .into_response()
}

/// Handle session cleanup
pub async fn handle_cleanup_sessions(State(_app_state): State<AppState>) -> impl IntoResponse {
    info!("Session cleanup requested but requires enterprise features");

    // Community edition: session persistence not implemented
    Json(ApiResponse::<()>::error("Session cleanup requires enterprise features. Use --features enterprise to enable session management.".to_string()))
        .into_response()
}

/// File operations handlers
use std::path::Path;
use tokio::fs as async_fs;

/// Handle file read operation
pub async fn handle_file_read(
    State(app_state): State<AppState>,
    Json(request): Json<FileReadRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!(
        "Reading file: {} (host: {})",
        request.path, app_state.config.host
    );

    // Path safety validation
    if request.path.contains("..") || request.path.contains("~") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Invalid path: path traversal not allowed".to_string(),
            )),
        )
            .into_response();
    }

    match read_file_safe(&request.path, request.encoding.as_deref()).await {
        Ok(response) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!(
                "File read completed in {}ms, size: {} bytes",
                processing_time, response.size_bytes
            );
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("File read failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Failed to read file: {}",
                    e
                ))),
            )
                .into_response()
        }
    }
}

/// Handle file write operation
pub async fn handle_file_write(
    State(_app_state): State<AppState>,
    Json(request): Json<FileWriteRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!("Writing file: {}", request.path);

    // Path safety validation
    if request.path.contains("..") || request.path.contains("~") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Invalid path: path traversal not allowed".to_string(),
            )),
        )
            .into_response();
    }

    match write_file_safe(
        &request.path,
        &request.content,
        request.create_directories.unwrap_or(false),
    )
    .await
    {
        Ok(response) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!(
                "File write completed in {}ms, size: {} bytes",
                processing_time, response.size_bytes
            );
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("File write failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Failed to write file: {}",
                    e
                ))),
            )
                .into_response()
        }
    }
}

/// Handle file edit operation
pub async fn handle_file_edit(
    State(_app_state): State<AppState>,
    Json(request): Json<FileEditRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!(
        "Editing file: {} with {} edits",
        request.path,
        request.edits.len()
    );

    // Path safety validation
    if request.path.contains("..") || request.path.contains("~") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Invalid path: path traversal not allowed".to_string(),
            )),
        )
            .into_response();
    }

    match edit_file_safe(&request.path, &request.edits).await {
        Ok(response) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!(
                "File edit completed in {}ms, {} edits applied",
                processing_time, response.edits_applied
            );
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("File edit failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Failed to edit file: {}",
                    e
                ))),
            )
                .into_response()
        }
    }
}

/// Handle file delete operation
pub async fn handle_file_delete(
    State(_app_state): State<AppState>,
    Json(request): Json<FileDeleteRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!("Deleting file: {}", request.path);

    // Path safety validation
    if request.path.contains("..") || request.path.contains("~") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Invalid path: path traversal not allowed".to_string(),
            )),
        )
            .into_response();
    }

    match delete_file_safe(&request.path, request.force.unwrap_or(false)).await {
        Ok(response) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!("File delete completed in {}ms", processing_time);
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("File delete failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Failed to delete file: {}",
                    e
                ))),
            )
                .into_response()
        }
    }
}

/// Handle file list operation
pub async fn handle_file_list(
    State(_app_state): State<AppState>,
    Json(request): Json<FileListRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!("Listing directory: {}", request.path);

    // Path safety validation
    if request.path.contains("..") && !request.path.starts_with("./..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Invalid path: path traversal not allowed".to_string(),
            )),
        )
            .into_response();
    }

    match list_directory_safe(
        &request.path,
        request.recursive.unwrap_or(false),
        request.include_hidden.unwrap_or(false),
        request.max_depth.unwrap_or(10),
    )
    .await
    {
        Ok(response) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!(
                "Directory list completed in {}ms, {} entries",
                processing_time, response.total_count
            );
            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Directory list failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::<()>::error(format!(
                    "Failed to list directory: {}",
                    e
                ))),
            )
                .into_response()
        }
    }
}

/// Safe file operation implementations
async fn read_file_safe(file_path: &str, encoding: Option<&str>) -> Result<FileReadResponse> {
    let path = Path::new(file_path);

    // Check if file exists
    if !path.exists() {
        return Err(anyhow::anyhow!("File does not exist: {}", file_path));
    }

    if !path.is_file() {
        return Err(anyhow::anyhow!("Path is not a file: {}", file_path));
    }

    // Get file metadata
    let metadata = async_fs::metadata(path).await?;
    let size_bytes = metadata.len();
    let last_modified = metadata.modified()?;
    let last_modified = chrono::DateTime::<chrono::Utc>::from(last_modified);

    // Read file content
    let encoding_str = encoding.unwrap_or("utf-8");
    let (content, is_binary) = match encoding_str {
        "binary" => {
            let bytes = async_fs::read(path).await?;
            (hex::encode(&bytes), true)
        }
        "base64" => {
            let bytes = async_fs::read(path).await?;
            (base64_encode(&bytes), true)
        }
        _ => {
            // Try to read as UTF-8
            match async_fs::read_to_string(path).await {
                Ok(content) => (content, false),
                Err(_) => {
                    // If UTF-8 fails, treat as binary and base64 encode
                    let bytes = async_fs::read(path).await?;
                    (base64_encode(&bytes), true)
                }
            }
        }
    };

    Ok(FileReadResponse {
        path: file_path.to_string(),
        content,
        size_bytes,
        encoding: encoding_str.to_string(),
        last_modified,
        is_binary,
    })
}

async fn write_file_safe(
    file_path: &str,
    content: &str,
    create_directories: bool,
) -> Result<FileWriteResponse> {
    let path = Path::new(file_path);

    // Create parent directories if requested
    if create_directories {
        if let Some(parent) = path.parent() {
            async_fs::create_dir_all(parent).await?;
        }
    }

    // Check if file already exists
    let file_exists = path.exists();

    // Write the file
    async_fs::write(path, content).await?;

    // Get new file size
    let metadata = async_fs::metadata(path).await?;
    let size_bytes = metadata.len();

    Ok(FileWriteResponse {
        path: file_path.to_string(),
        size_bytes,
        created: !file_exists,
    })
}

async fn edit_file_safe(file_path: &str, edits: &[FileEdit]) -> Result<FileEditResponse> {
    let path = Path::new(file_path);

    // Check if file exists
    if !path.exists() {
        return Err(anyhow::anyhow!("File does not exist: {}", file_path));
    }

    // Read current content
    let content = async_fs::read_to_string(path).await?;
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    // Apply edits in reverse order to maintain line numbers
    let mut sorted_edits = edits.to_vec();
    sorted_edits.sort_by(|a, b| b.line_start.cmp(&a.line_start));

    let mut edits_applied = 0;
    for edit in sorted_edits {
        if edit.line_start > 0 && edit.line_start <= lines.len() + 1 {
            let start_idx = edit.line_start.saturating_sub(1);
            let end_idx = edit.line_end.min(lines.len());

            // Remove old lines
            lines.drain(start_idx..end_idx);

            // Insert new content
            let new_lines: Vec<String> = edit.new_content.lines().map(|s| s.to_string()).collect();
            for (i, line) in new_lines.into_iter().enumerate() {
                lines.insert(start_idx + i, line);
            }

            edits_applied += 1;
        }
    }

    // Write the modified content back
    let new_content = lines.join("\n");
    async_fs::write(path, &new_content).await?;

    let metadata = async_fs::metadata(path).await?;
    let new_size_bytes = metadata.len();

    Ok(FileEditResponse {
        path: file_path.to_string(),
        edits_applied,
        new_size_bytes,
    })
}

async fn delete_file_safe(file_path: &str, force: bool) -> Result<FileDeleteResponse> {
    let path = Path::new(file_path);

    if !path.exists() {
        return Ok(FileDeleteResponse {
            path: file_path.to_string(),
            deleted: false,
        });
    }

    // Safety check: don't delete system files or directories without force
    if !force {
        if path.is_dir() {
            return Err(anyhow::anyhow!(
                "Cannot delete directory without force flag: {}",
                file_path
            ));
        }

        // Check for system files
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        if file_name.starts_with('.') && !file_name.starts_with(".rustchain") {
            return Err(anyhow::anyhow!(
                "Cannot delete hidden system file without force flag: {}",
                file_path
            ));
        }
    }

    // Delete the file or directory
    if path.is_dir() {
        async_fs::remove_dir_all(path).await?;
    } else {
        async_fs::remove_file(path).await?;
    }

    Ok(FileDeleteResponse {
        path: file_path.to_string(),
        deleted: true,
    })
}

async fn list_directory_safe(
    dir_path: &str,
    recursive: bool,
    include_hidden: bool,
    max_depth: usize,
) -> Result<FileListResponse> {
    let path = Path::new(dir_path);

    if !path.exists() {
        return Err(anyhow::anyhow!("Directory does not exist: {}", dir_path));
    }

    if !path.is_dir() {
        return Err(anyhow::anyhow!("Path is not a directory: {}", dir_path));
    }

    let mut entries = Vec::new();

    if recursive {
        collect_entries_with_recursion(path, &mut entries, include_hidden, max_depth).await?;
    } else {
        collect_entries_single(path, &mut entries, include_hidden).await?;
    }

    // Sort entries by name
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let total_count = entries.len();

    Ok(FileListResponse {
        path: dir_path.to_string(),
        entries,
        total_count,
    })
}

async fn collect_entries_single(
    dir_path: &Path,
    entries: &mut Vec<FileEntry>,
    include_hidden: bool,
) -> Result<()> {
    let mut dir_entries = async_fs::read_dir(dir_path).await?;

    while let Some(entry) = dir_entries.next_entry().await? {
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        // Skip hidden files unless requested
        if !include_hidden && file_name.starts_with('.') {
            continue;
        }

        let metadata = entry.metadata().await?;
        let is_directory = metadata.is_dir();
        let size_bytes = if is_directory {
            None
        } else {
            Some(metadata.len())
        };
        let last_modified = chrono::DateTime::<chrono::Utc>::from(metadata.modified()?);

        entries.push(FileEntry {
            name: file_name,
            path: path.to_string_lossy().to_string(),
            is_directory,
            size_bytes,
            last_modified,
            permissions: None, // File permission reading planned - requires platform-specific implementation
        });
    }

    Ok(())
}

async fn collect_entries_with_recursion(
    root_path: &Path,
    entries: &mut Vec<FileEntry>,
    include_hidden: bool,
    max_depth: usize,
) -> Result<()> {
    use std::collections::VecDeque;

    let mut queue = VecDeque::new();
    queue.push_back((root_path.to_path_buf(), 0));

    while let Some((current_path, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        // Process current directory
        let mut dir_entries = async_fs::read_dir(&current_path).await?;

        while let Some(entry) = dir_entries.next_entry().await? {
            let path = entry.path();
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            // Skip hidden files unless requested
            if !include_hidden && file_name.starts_with('.') {
                continue;
            }

            let metadata = entry.metadata().await?;
            let is_directory = metadata.is_dir();
            let size_bytes = if is_directory {
                None
            } else {
                Some(metadata.len())
            };
            let last_modified = chrono::DateTime::<chrono::Utc>::from(metadata.modified()?);

            entries.push(FileEntry {
                name: file_name,
                path: path.to_string_lossy().to_string(),
                is_directory,
                size_bytes,
                last_modified,
                permissions: None,
            });

            // Add subdirectories to the queue for recursive processing
            if is_directory && depth + 1 < max_depth {
                queue.push_back((path, depth + 1));
            }
        }
    }

    Ok(())
}

/// Project analysis request/response types (PUNCH integration)
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectAnalysisRequest {
    pub path: String,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectAnalysisResponse {
    pub path: String,
    pub analysis_time_ms: u64,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

/// Handle project analysis via PUNCH integration
pub async fn handle_project_analysis(
    State(_app_state): State<AppState>,
    Json(request): Json<ProjectAnalysisRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!("Analyzing project: {}", request.path);

    // Path safety validation
    if request.path.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Invalid path: path traversal not allowed".to_string(),
            )),
        )
            .into_response();
    }

    match execute_punch_analysis(&request.path).await {
        Ok(output) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!("Project analysis completed in {}ms", processing_time);

            let response = ProjectAnalysisResponse {
                path: request.path,
                analysis_time_ms: processing_time,
                success: true,
                output,
                error: None,
            };

            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Project analysis failed: {}", e);
            let processing_time = start_time.elapsed().as_millis() as u64;

            let response = ProjectAnalysisResponse {
                path: request.path,
                analysis_time_ms: processing_time,
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            };

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::success(response)),
            )
                .into_response()
        }
    }
}

/// Execute PUNCH analysis on project path
async fn execute_punch_analysis(project_path: &str) -> Result<String> {
    use tokio::process::Command;

    // Execute PUNCH discovery command as documented in CLAUDE.md
    let output = Command::new("punch")
        .args([
            "discover",
            project_path,
            "--languages=rust,go,typescript,python",
            "--patterns",
            "--output=json",
        ])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to execute PUNCH command: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!("PUNCH analysis failed: {}", stderr))
    }
}

/// Command execution request/response types (safe shell execution)
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandExecutionRequest {
    pub command: String,
    pub args: Option<Vec<String>>,
    pub working_directory: Option<String>,
    pub timeout_seconds: Option<u64>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandExecutionResponse {
    pub command: String,
    pub args: Vec<String>,
    pub working_directory: String,
    pub execution_time_ms: u64,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

/// Handle command execution via safe shell execution
pub async fn handle_command_execution(
    State(_app_state): State<AppState>,
    Json(request): Json<CommandExecutionRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!("Executing command: {} {:?}", request.command, request.args);

    // Command safety validation
    if is_dangerous_command(&request.command) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(
                "Dangerous command blocked for security".to_string(),
            )),
        )
            .into_response();
    }

    match execute_safe_command(&request).await {
        Ok(response) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!(
                "Command execution completed in {}ms, exit code: {:?}",
                processing_time, response.exit_code
            );

            let mut final_response = response;
            final_response.execution_time_ms = processing_time;

            Json(ApiResponse::success(final_response)).into_response()
        }
        Err(e) => {
            error!("Command execution failed: {}", e);
            let processing_time = start_time.elapsed().as_millis() as u64;

            let response = CommandExecutionResponse {
                command: request.command.clone(),
                args: request.args.unwrap_or_default(),
                working_directory: request
                    .working_directory
                    .unwrap_or_else(|| "unknown".to_string()),
                execution_time_ms: processing_time,
                success: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(e.to_string()),
            };

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::success(response)),
            )
                .into_response()
        }
    }
}

/// Execute command safely with validation and timeout
async fn execute_safe_command(
    request: &CommandExecutionRequest,
) -> Result<CommandExecutionResponse> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let working_dir = request.working_directory.as_deref().unwrap_or(".");

    let args = request.args.as_deref().unwrap_or(&[]);
    let timeout_duration = Duration::from_secs(request.timeout_seconds.unwrap_or(30));

    let mut command = Command::new(&request.command);
    command.args(args).current_dir(working_dir);

    let output = timeout(timeout_duration, command.output())
        .await
        .map_err(|_| anyhow::anyhow!("Command execution timed out"))?
        .map_err(|e| anyhow::anyhow!("Failed to execute command: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(CommandExecutionResponse {
        command: request.command.clone(),
        args: args.to_vec(),
        working_directory: working_dir.to_string(),
        execution_time_ms: 0, // Will be set by caller
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout,
        stderr,
        error: None,
    })
}

/// Check if command is dangerous and should be blocked
fn is_dangerous_command(command: &str) -> bool {
    let dangerous_commands = [
        "rm",
        "del",
        "format",
        "fdisk",
        "mkfs",
        "dd",
        "shutdown",
        "reboot",
        "halt",
        "chmod",
        "chown",
        "passwd",
        "sudo",
        "su",
        "systemctl",
        "service",
        "init",
        "killall",
    ];

    dangerous_commands.contains(&command)
}

/// Git operations request/response types
#[derive(Debug, Serialize, Deserialize)]
pub struct GitOperationRequest {
    pub operation: String, // status, commit, push, pull, branch
    pub repository_path: Option<String>,
    pub parameters: Option<serde_json::Value>,
    pub session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitOperationResponse {
    pub operation: String,
    pub repository_path: String,
    pub execution_time_ms: u64,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

/// Handle Git operations
pub async fn handle_git_operation(
    State(_app_state): State<AppState>,
    Json(request): Json<GitOperationRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!("Executing git operation: {}", request.operation);

    let repo_path = request.repository_path.as_deref().unwrap_or(".");

    match execute_git_operation(&request.operation, repo_path, &request.parameters).await {
        Ok(output) => {
            let processing_time = start_time.elapsed().as_millis() as u64;
            info!(
                "Git operation {} completed in {}ms",
                request.operation, processing_time
            );

            let response = GitOperationResponse {
                operation: request.operation,
                repository_path: repo_path.to_string(),
                execution_time_ms: processing_time,
                success: true,
                output,
                error: None,
            };

            Json(ApiResponse::success(response)).into_response()
        }
        Err(e) => {
            error!("Git operation {} failed: {}", request.operation, e);
            let processing_time = start_time.elapsed().as_millis() as u64;

            let response = GitOperationResponse {
                operation: request.operation,
                repository_path: repo_path.to_string(),
                execution_time_ms: processing_time,
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            };

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::success(response)),
            )
                .into_response()
        }
    }
}

/// Execute Git operation safely
async fn execute_git_operation(
    operation: &str,
    repo_path: &str,
    parameters: &Option<serde_json::Value>,
) -> Result<String> {
    use tokio::process::Command;

    let mut command = Command::new("git");
    command.current_dir(repo_path);

    match operation {
        "status" => {
            command.args(["status", "--porcelain"]);
        }
        "commit" => {
            if let Some(params) = parameters {
                if let Some(message) = params.get("message").and_then(|m| m.as_str()) {
                    command.args(["commit", "-m", message]);
                } else {
                    return Err(anyhow::anyhow!(
                        "Commit operation requires 'message' parameter"
                    ));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Commit operation requires parameters with message"
                ));
            }
        }
        "push" => {
            command.args(["push"]);
            if let Some(params) = parameters {
                if let Some(remote) = params.get("remote").and_then(|r| r.as_str()) {
                    command.arg(remote);
                    if let Some(branch) = params.get("branch").and_then(|b| b.as_str()) {
                        command.arg(branch);
                    }
                }
            }
        }
        "pull" => {
            command.args(["pull"]);
            if let Some(params) = parameters {
                if let Some(remote) = params.get("remote").and_then(|r| r.as_str()) {
                    command.arg(remote);
                    if let Some(branch) = params.get("branch").and_then(|b| b.as_str()) {
                        command.arg(branch);
                    }
                }
            }
        }
        "branch" => {
            if let Some(params) = parameters {
                if let Some(branch_name) = params.get("name").and_then(|n| n.as_str()) {
                    if params
                        .get("create")
                        .and_then(|c| c.as_bool())
                        .unwrap_or(false)
                    {
                        command.args(["checkout", "-b", branch_name]);
                    } else if params
                        .get("switch")
                        .and_then(|s| s.as_bool())
                        .unwrap_or(false)
                    {
                        command.args(["checkout", branch_name]);
                    } else {
                        command.args(["branch", branch_name]);
                    }
                } else {
                    command.args(["branch", "-a"]);
                }
            } else {
                command.args(["branch", "-a"]);
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported git operation: {}", operation));
        }
    }

    let output = command
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to execute git command: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!("Git operation failed: {}", stderr))
    }
}

/// Base64 encoding helper
fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(data)
}

/// OpenAI-compatible API types for Shimmy integration
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenAIChatCompletionsRequest {
    pub model: String,
    pub messages: Vec<OpenAIChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: Option<bool>,
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenAIChatMessage {
    pub role: String,
    pub content: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenAIChatCompletionsResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIChoice>,
    pub usage: OpenAIUsage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenAIChoice {
    pub index: u32,
    pub message: OpenAIChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenAIUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Handle OpenAI-compatible chat completions for Shimmy integration
pub async fn handle_openai_chat_completions(
    State(app_state): State<AppState>,
    Json(request): Json<OpenAIChatCompletionsRequest>,
) -> impl IntoResponse {
    let start_time = Instant::now();
    info!(
        "Processing OpenAI-compatible chat completion for model: {}",
        request.model
    );

    // Extract user message (last message with role "user")
    let user_message = request
        .messages
        .iter()
        .rev()
        .find(|msg| msg.role == "user")
        .map(|msg| msg.content.clone())
        .unwrap_or_default();

    if user_message.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "message": "No user message found in request",
                    "type": "invalid_request_error"
                }
            })),
        )
            .into_response();
    }

    // Create agent request from OpenAI format
    let agent_request = AgentMessageRequest {
        message: user_message,
        context: Some(SessionContext {
            current_directory: std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string())),
            session_id: request.user.clone(),
            conversation_history: Some(
                request
                    .messages
                    .iter()
                    .take(request.messages.len().saturating_sub(1))
                    .map(|msg| format!("{}: {}", msg.role, msg.content))
                    .collect(),
            ),
            active_files: None,
        }),
        options: Some(MessageOptions {
            model: Some(request.model.clone()),
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            stream: request.stream,
        }),
    };

    // Process with RustChain agent
    let session_id = agent_request
        .context
        .as_ref()
        .and_then(|c| c.session_id.clone())
        .unwrap_or_else(|| format!("shimmy_{}", Uuid::new_v4().simple()));

    let session = match get_session_from_store(&session_id, &app_state).await {
        Ok(existing_session) => existing_session,
        Err(_) => {
            let new_session = AgentSession::new(session_id.clone());
            if let Err(e) = store_session_in_store(new_session.clone(), &app_state).await {
                warn!("Failed to store new session: {}", e);
            }
            new_session
        }
    };

    match process_agent_message(&agent_request, &session, &app_state).await {
        Ok(agent_response) => {
            let processing_time = start_time.elapsed().as_millis() as u64;

            // Convert RustChain response to OpenAI format
            let openai_response = OpenAIChatCompletionsResponse {
                id: format!("chatcmpl-{}", Uuid::new_v4().simple()),
                object: "chat.completion".to_string(),
                created: chrono::Utc::now().timestamp() as u64,
                model: request.model,
                choices: vec![OpenAIChoice {
                    index: 0,
                    message: OpenAIChatMessage {
                        role: "assistant".to_string(),
                        content: agent_response.response,
                        name: None,
                    },
                    finish_reason: "stop".to_string(),
                }],
                usage: OpenAIUsage {
                    prompt_tokens: (request
                        .messages
                        .iter()
                        .map(|m| m.content.len())
                        .sum::<usize>()
                        / 4)
                    .max(1) as u32, // Rough estimate: ~4 chars per token
                    completion_tokens: agent_response.tokens_used,
                    total_tokens: agent_response.tokens_used
                        + ((request
                            .messages
                            .iter()
                            .map(|m| m.content.len())
                            .sum::<usize>()
                            / 4)
                        .max(1) as u32),
                },
            };

            info!(
                "OpenAI-compatible response generated in {}ms",
                processing_time
            );
            Json(openai_response).into_response()
        }
        Err(e) => {
            error!("Agent processing failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": {
                        "message": format!("Agent processing failed: {}", e),
                        "type": "server_error"
                    }
                })),
            )
                .into_response()
        }
    }
}
