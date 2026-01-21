use crate::core::http_client::create_http_client;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use tracing::{debug, info, warn};

#[cfg(feature = "llm")]
pub mod test_connectivity;

#[cfg(feature = "llm")]
pub mod shimmy_provider;

#[cfg(feature = "llm")]
pub mod google_gemini_provider;

#[cfg(feature = "llm")]
pub mod aws_bedrock_provider;

#[cfg(feature = "llm")]
pub mod azure_openai_provider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMRequest {
    pub messages: Vec<ChatMessage>,
    pub model: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: bool,
    pub tools: Option<Vec<ToolDefinition>>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: MessageRole,
    pub content: String,
    pub name: Option<String>,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MessageRole {
    #[serde(rename = "system")]
    System,
    #[serde(rename = "user")]
    User,
    #[serde(rename = "assistant")]
    Assistant,
    #[serde(rename = "tool")]
    Tool,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageRole::System => write!(f, "system"),
            MessageRole::User => write!(f, "user"),
            MessageRole::Assistant => write!(f, "assistant"),
            MessageRole::Tool => write!(f, "tool"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMResponse {
    pub content: String,
    pub role: MessageRole,
    pub model: String,
    pub usage: TokenUsage,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub finish_reason: FinishReason,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FinishReason {
    #[serde(rename = "stop")]
    Stop,
    #[serde(rename = "length")]
    Length,
    #[serde(rename = "tool_calls")]
    ToolCalls,
    #[serde(rename = "content_filter")]
    ContentFilter,
    #[serde(rename = "error")]
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub context_length: u32,
    pub max_output_tokens: u32,
    pub supports_tools: bool,
    pub supports_streaming: bool,
    pub cost_per_input_token: Option<f64>,
    pub cost_per_output_token: Option<f64>,
}

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse>;
    async fn stream<'a>(
        &'a self,
        request: LLMRequest,
    ) -> Result<Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>>;
    async fn list_models(&self) -> Result<Vec<ModelInfo>>;
    fn provider_name(&self) -> &str;
    fn supports_streaming(&self) -> bool;
    fn supports_tools(&self) -> bool;
}

/// OpenAI-compatible provider
pub struct OpenAIProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: create_http_client(None),
            api_key,
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4".to_string(),
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse> {
        let url = format!("{}/chat/completions", self.base_url);

        let mut openai_request = serde_json::json!({
            "model": request.model.unwrap_or(self.model.clone()),
            "messages": request.messages,
            "stream": false
        });

        if let Some(temp) = request.temperature {
            openai_request["temperature"] = serde_json::json!(temp);
        }

        if let Some(max_tokens) = request.max_tokens {
            openai_request["max_tokens"] = serde_json::Value::Number(max_tokens.into());
        }

        if let Some(tools) = request.tools {
            let openai_tools: Vec<serde_json::Value> = tools
                .iter()
                .map(|tool| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.parameters
                        }
                    })
                })
                .collect();
            openai_request["tools"] = serde_json::Value::Array(openai_tools);
        }

        debug!("Sending request to OpenAI: {}", url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&openai_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("OpenAI API error: {}", error_text));
        }

        let openai_response: serde_json::Value = response.json().await?;

        // Extract the response
        let choice = openai_response["choices"][0].clone();
        let message = &choice["message"];
        let usage = &openai_response["usage"];

        let content = message["content"].as_str().unwrap_or("").to_string();

        let tool_calls = message["tool_calls"].as_array().map(|calls| {
            calls
                .iter()
                .filter_map(|call| {
                    Some(ToolCall {
                        id: call["id"].as_str()?.to_string(),
                        function: FunctionCall {
                            name: call["function"]["name"].as_str()?.to_string(),
                            arguments: call["function"]["arguments"].as_str()?.to_string(),
                        },
                    })
                })
                .collect()
        });

        let finish_reason = match choice["finish_reason"].as_str().unwrap_or("stop") {
            "stop" => FinishReason::Stop,
            "length" => FinishReason::Length,
            "tool_calls" => FinishReason::ToolCalls,
            "content_filter" => FinishReason::ContentFilter,
            _ => FinishReason::Error,
        };

        Ok(LLMResponse {
            content,
            role: MessageRole::Assistant,
            model: openai_response["model"]
                .as_str()
                .unwrap_or(&self.model)
                .to_string(),
            usage: TokenUsage {
                prompt_tokens: usage["prompt_tokens"].as_u64().unwrap_or(0) as u32,
                completion_tokens: usage["completion_tokens"].as_u64().unwrap_or(0) as u32,
                total_tokens: usage["total_tokens"].as_u64().unwrap_or(0) as u32,
            },
            tool_calls,
            finish_reason,
            metadata: HashMap::new(),
        })
    }

    async fn stream<'a>(
        &'a self,
        request: LLMRequest,
    ) -> Result<Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>> {
        use futures::stream::StreamExt;

        // OpenAI streaming implementation
        let url = format!("{}/chat/completions", self.base_url);

        let mut openai_request = serde_json::json!({
            "model": request.model.unwrap_or_else(|| self.model.clone()),
            "messages": request.messages,
            "stream": true // Enable streaming
        });

        // Add optional parameters
        if let Some(temp) = request.temperature {
            openai_request["temperature"] = serde_json::Value::from(temp);
        }
        if let Some(max_tokens) = request.max_tokens {
            openai_request["max_tokens"] = serde_json::Value::from(max_tokens);
        }

        debug!("Making streaming request to OpenAI: {}", url);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&openai_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!(
                "OpenAI streaming request failed with status {}: {}",
                status,
                error_text
            ));
        }

        // Convert response stream to LLMResponse stream
        let stream = response
            .bytes_stream()
            .map(|chunk_result| {
                match chunk_result {
                    Ok(chunk) => {
                        // Parse SSE chunk
                        let chunk_str = String::from_utf8_lossy(&chunk);

                        // Handle SSE format: data: {...}
                        for line in chunk_str.lines() {
                            if let Some(data_line) = line.strip_prefix("data: ") {
                                if data_line == "[DONE]" {
                                    continue;
                                }

                                match serde_json::from_str::<serde_json::Value>(data_line) {
                                    Ok(response_json) => {
                                        if let Some(choices) =
                                            response_json.get("choices").and_then(|c| c.as_array())
                                        {
                                            if let Some(choice) = choices.first() {
                                                if let Some(delta) = choice.get("delta") {
                                                    if let Some(content) = delta
                                                        .get("content")
                                                        .and_then(|c| c.as_str())
                                                    {
                                                        return Ok(LLMResponse {
                                                            content: content.to_string(),
                                                            role: MessageRole::Assistant,
                                                            model: response_json
                                                                .get("model")
                                                                .and_then(|m| m.as_str())
                                                                .unwrap_or("unknown")
                                                                .to_string(),
                                                            usage: TokenUsage {
                                                                prompt_tokens: 0,
                                                                completion_tokens: 0,
                                                                total_tokens: 0,
                                                            },
                                                            tool_calls: None,
                                                            finish_reason: match choice
                                                                .get("finish_reason")
                                                                .and_then(|r| r.as_str())
                                                            {
                                                                Some("stop") => FinishReason::Stop,
                                                                Some("length") => {
                                                                    FinishReason::Length
                                                                }
                                                                _ => FinishReason::Stop,
                                                            },
                                                            metadata: HashMap::new(),
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        debug!("Failed to parse streaming response: {}", e);
                                        continue;
                                    }
                                }
                            }
                        }

                        // If no valid data found, return empty response
                        Ok(LLMResponse {
                            content: String::new(),
                            role: MessageRole::Assistant,
                            model: "unknown".to_string(),
                            usage: TokenUsage {
                                prompt_tokens: 0,
                                completion_tokens: 0,
                                total_tokens: 0,
                            },
                            tool_calls: None,
                            finish_reason: FinishReason::Stop,
                            metadata: HashMap::new(),
                        })
                    }
                    Err(e) => Err(anyhow!("Stream chunk error: {}", e)),
                }
            })
            .filter_map(|result| async move {
                match result {
                    Ok(response) if response.content.is_empty() => None, // Filter empty chunks
                    other => Some(other),
                }
            });

        Ok(Box::pin(stream))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let url = format!("{}/models", self.base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("OpenAI models API error: {}", error_text));
        }

        let models_response: serde_json::Value = response.json().await?;
        let models = models_response["data"]
            .as_array()
            .ok_or_else(|| anyhow!("Invalid models response"))?;

        let model_infos = models
            .iter()
            .filter_map(|model| {
                let id = model["id"].as_str()?;
                if id.starts_with("gpt-") {
                    Some(ModelInfo {
                        id: id.to_string(),
                        name: id.to_string(),
                        provider: "openai".to_string(),
                        context_length: match id {
                            "gpt-4" => 8192,
                            "gpt-4-turbo" => 128000,
                            "gpt-3.5-turbo" => 4096,
                            _ => 4096,
                        },
                        max_output_tokens: 4096,
                        supports_tools: true,
                        supports_streaming: true,
                        cost_per_input_token: None, // Would be filled from pricing API
                        cost_per_output_token: None,
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(model_infos)
    }

    fn provider_name(&self) -> &str {
        "openai"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }
}

/// Anthropic Claude provider
pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
    model: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: create_http_client(None),
            api_key,
            model: "claude-3-sonnet-20240229".to_string(),
        }
    }

    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }
}

#[async_trait]
impl LLMProvider for AnthropicProvider {
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse> {
        let url = "https://api.anthropic.com/v1/messages";

        // Convert messages to Anthropic format
        let mut system_message = String::new();
        let mut messages = Vec::new();

        for msg in request.messages {
            match msg.role {
                MessageRole::System => {
                    system_message.push_str(&msg.content);
                    system_message.push('\n');
                }
                MessageRole::User => {
                    messages.push(serde_json::json!({
                        "role": "user",
                        "content": msg.content
                    }));
                }
                MessageRole::Assistant => {
                    messages.push(serde_json::json!({
                        "role": "assistant",
                        "content": msg.content
                    }));
                }
                MessageRole::Tool => {
                    // Anthropic handles tool responses differently
                    continue;
                }
            }
        }

        let mut anthropic_request = serde_json::json!({
            "model": request.model.unwrap_or(self.model.clone()),
            "messages": messages,
            "max_tokens": request.max_tokens.unwrap_or(4096)
        });

        if !system_message.trim().is_empty() {
            anthropic_request["system"] =
                serde_json::Value::String(system_message.trim().to_string());
        }

        if let Some(temp) = request.temperature {
            anthropic_request["temperature"] = serde_json::json!(temp);
        }

        debug!("Sending request to Anthropic: {}", url);

        let response = self
            .client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&anthropic_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Anthropic API error: {}", error_text));
        }

        let anthropic_response: serde_json::Value = response.json().await?;

        let content = anthropic_response["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let usage = &anthropic_response["usage"];

        Ok(LLMResponse {
            content,
            role: MessageRole::Assistant,
            model: anthropic_response["model"]
                .as_str()
                .unwrap_or(&self.model)
                .to_string(),
            usage: TokenUsage {
                prompt_tokens: usage["input_tokens"].as_u64().unwrap_or(0) as u32,
                completion_tokens: usage["output_tokens"].as_u64().unwrap_or(0) as u32,
                total_tokens: (usage["input_tokens"].as_u64().unwrap_or(0)
                    + usage["output_tokens"].as_u64().unwrap_or(0))
                    as u32,
            },
            tool_calls: None, // Anthropic tool calls would need separate handling
            finish_reason: FinishReason::Stop, // Would need to parse actual finish reason
            metadata: HashMap::new(),
        })
    }

    async fn stream<'a>(
        &'a self,
        request: LLMRequest,
    ) -> Result<Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>> {
        let url = "https://api.anthropic.com/v1/messages";

        // Convert messages to Anthropic format (same as complete method)
        let mut system_message = String::new();
        let mut messages = Vec::new();

        for msg in request.messages {
            match msg.role {
                MessageRole::System => {
                    system_message.push_str(&msg.content);
                    system_message.push('\n');
                }
                MessageRole::User => {
                    messages.push(serde_json::json!({
                        "role": "user",
                        "content": msg.content
                    }));
                }
                MessageRole::Assistant => {
                    messages.push(serde_json::json!({
                        "role": "assistant",
                        "content": msg.content
                    }));
                }
                MessageRole::Tool => {
                    continue;
                }
            }
        }

        let model = request.model.clone().unwrap_or_else(|| self.model.clone());

        let mut anthropic_request = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": request.max_tokens.unwrap_or(4096),
            "stream": true
        });

        if !system_message.trim().is_empty() {
            anthropic_request["system"] =
                serde_json::Value::String(system_message.trim().to_string());
        }

        if let Some(temp) = request.temperature {
            anthropic_request["temperature"] = serde_json::json!(temp);
        }

        let response = self
            .client
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&anthropic_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Anthropic streaming API error: {}", error_text));
        }

        let stream = response
            .bytes_stream()
            .filter_map(move |chunk_result| {
                let model = model.clone();
                async move {
                    match chunk_result {
                        Ok(chunk) => {
                            let chunk_str = String::from_utf8_lossy(&chunk);

                            // Parse Anthropic SSE format: event: {...}
                            for line in chunk_str.lines() {
                                if let Some(event_line) = line.strip_prefix("data: ") {
                                    match serde_json::from_str::<serde_json::Value>(event_line) {
                                        Ok(event) => {
                                            // Handle different event types
                                            if let Some(event_type) =
                                                event.get("type").and_then(|t| t.as_str())
                                            {
                                                match event_type {
                                                    "content_block_delta" => {
                                                        if let Some(delta) = event.get("delta") {
                                                            if let Some(text) = delta
                                                                .get("text")
                                                                .and_then(|t| t.as_str())
                                                            {
                                                                return Some(Ok(LLMResponse {
                                                                    content: text.to_string(),
                                                                    role: MessageRole::Assistant,
                                                                    model: model.clone(),
                                                                    usage: TokenUsage {
                                                                        prompt_tokens: 0,
                                                                        completion_tokens: 0,
                                                                        total_tokens: 0,
                                                                    },
                                                                    tool_calls: None,
                                                                    finish_reason:
                                                                        FinishReason::Stop,
                                                                    metadata: HashMap::new(),
                                                                }));
                                                            }
                                                        }
                                                    }
                                                    _ => continue, // Skip other event types for now
                                                }
                                            }
                                        }
                                        Err(_) => continue, // Skip parsing errors
                                    }
                                }
                            }

                            // If no valid data found, return empty response
                            Some(Ok(LLMResponse {
                                content: String::new(),
                                role: MessageRole::Assistant,
                                model: model.clone(),
                                usage: TokenUsage {
                                    prompt_tokens: 0,
                                    completion_tokens: 0,
                                    total_tokens: 0,
                                },
                                tool_calls: None,
                                finish_reason: FinishReason::Stop,
                                metadata: HashMap::new(),
                            }))
                        }
                        Err(e) => Some(Err(anyhow!("Stream chunk error: {}", e))),
                    }
                }
            })
            .filter_map(|result| async move {
                match result {
                    Ok(response) if response.content.is_empty() => None, // Filter empty chunks
                    other => Some(other),
                }
            });

        Ok(Box::pin(stream))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        // Anthropic doesn't have a models endpoint, return known models
        Ok(vec![
            ModelInfo {
                id: "claude-3-opus-20240229".to_string(),
                name: "Claude 3 Opus".to_string(),
                provider: "anthropic".to_string(),
                context_length: 200000,
                max_output_tokens: 4096,
                supports_tools: true,
                supports_streaming: true,
                cost_per_input_token: Some(0.000015),
                cost_per_output_token: Some(0.000075),
            },
            ModelInfo {
                id: "claude-3-sonnet-20240229".to_string(),
                name: "Claude 3 Sonnet".to_string(),
                provider: "anthropic".to_string(),
                context_length: 200000,
                max_output_tokens: 4096,
                supports_tools: true,
                supports_streaming: true,
                cost_per_input_token: Some(0.000003),
                cost_per_output_token: Some(0.000015),
            },
            ModelInfo {
                id: "claude-3-haiku-20240307".to_string(),
                name: "Claude 3 Haiku".to_string(),
                provider: "anthropic".to_string(),
                context_length: 200000,
                max_output_tokens: 4096,
                supports_tools: true,
                supports_streaming: true,
                cost_per_input_token: Some(0.00000025),
                cost_per_output_token: Some(0.00000125),
            },
        ])
    }

    fn provider_name(&self) -> &str {
        "anthropic"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }
}

/// Local/Ollama provider for self-hosted models
pub struct OllamaProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl OllamaProvider {
    pub fn new(base_url: Option<String>) -> Self {
        Self {
            client: create_http_client(None),
            base_url: base_url.unwrap_or_else(|| "http://localhost:11434".to_string()),
            model: "llama2".to_string(),
        }
    }

    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse> {
        let url = format!("{}/api/chat", self.base_url);

        let ollama_request = serde_json::json!({
            "model": request.model.unwrap_or(self.model.clone()),
            "messages": request.messages,
            "stream": false,
            "options": {
                "temperature": request.temperature.unwrap_or(0.7),
                "num_predict": request.max_tokens.unwrap_or(4096)
            }
        });

        debug!("Sending request to Ollama: {}", url);

        let response = self.client.post(&url).json(&ollama_request).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Ollama API error: {}", error_text));
        }

        let ollama_response: serde_json::Value = response.json().await?;

        let content = ollama_response["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Ollama doesn't provide detailed token counts, estimate
        let prompt_tokens = request
            .messages
            .iter()
            .map(|m| m.content.len() / 4) // Rough estimate: 4 chars per token
            .sum::<usize>();
        let prompt_tokens = u32::try_from(prompt_tokens).unwrap_or(u32::MAX);
        let completion_tokens = u32::try_from(content.len() / 4).unwrap_or(u32::MAX);

        Ok(LLMResponse {
            content,
            role: MessageRole::Assistant,
            model: ollama_response["model"]
                .as_str()
                .unwrap_or(&self.model)
                .to_string(),
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
            tool_calls: None, // Ollama doesn't natively support tool calls
            finish_reason: FinishReason::Stop,
            metadata: HashMap::new(),
        })
    }

    async fn stream<'a>(
        &'a self,
        request: LLMRequest,
    ) -> Result<Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>> {
        let url = format!("{}/api/chat", self.base_url);

        let ollama_request = serde_json::json!({
            "model": request.model.unwrap_or(self.model.clone()),
            "messages": request.messages,
            "stream": true,
            "options": {
                "temperature": request.temperature.unwrap_or(0.7),
                "num_predict": request.max_tokens.unwrap_or(4096)
            }
        });

        let response = self.client.post(&url).json(&ollama_request).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Ollama streaming API error: {}", error_text));
        }

        let stream = response
            .bytes_stream()
            .filter_map(move |chunk_result| async move {
                match chunk_result {
                    Ok(chunk) => {
                        let chunk_str = String::from_utf8_lossy(&chunk);

                        // Ollama returns JSON objects, one per line
                        for line in chunk_str.lines() {
                            if line.trim().is_empty() {
                                continue;
                            }

                            match serde_json::from_str::<serde_json::Value>(line) {
                                Ok(ollama_chunk) => {
                                    // Check if this is the final message (done: true)
                                    if ollama_chunk
                                        .get("done")
                                        .and_then(|d| d.as_bool())
                                        .unwrap_or(false)
                                    {
                                        continue; // Skip the final done message
                                    }

                                    if let Some(content) =
                                        ollama_chunk["message"]["content"].as_str()
                                    {
                                        return Some(Ok(LLMResponse {
                                            content: content.to_string(),
                                            role: MessageRole::Assistant,
                                            model: ollama_chunk["model"]
                                                .as_str()
                                                .unwrap_or(&self.model)
                                                .to_string(),
                                            usage: TokenUsage {
                                                prompt_tokens: 0, // Streaming doesn't provide token counts
                                                completion_tokens: 0,
                                                total_tokens: 0,
                                            },
                                            tool_calls: None,
                                            finish_reason: FinishReason::Stop,
                                            metadata: HashMap::new(),
                                        }));
                                    }
                                }
                                Err(_) => continue, // Skip parsing errors
                            }
                        }

                        // If no valid data found, return empty response
                        Some(Ok(LLMResponse {
                            content: String::new(),
                            role: MessageRole::Assistant,
                            model: "unknown".to_string(),
                            usage: TokenUsage {
                                prompt_tokens: 0,
                                completion_tokens: 0,
                                total_tokens: 0,
                            },
                            tool_calls: None,
                            finish_reason: FinishReason::Stop,
                            metadata: HashMap::new(),
                        }))
                    }
                    Err(e) => Some(Err(anyhow!("Stream chunk error: {}", e))),
                }
            })
            .filter_map(|result| async move {
                match result {
                    Ok(response) if response.content.is_empty() => None, // Filter empty chunks
                    other => Some(other),
                }
            });

        Ok(Box::pin(stream))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let url = format!("{}/api/tags", self.base_url);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Ollama models API error: {}", error_text));
        }

        let models_response: serde_json::Value = response.json().await?;
        let models = models_response["models"]
            .as_array()
            .ok_or_else(|| anyhow!("Invalid models response"))?;

        let model_infos = models
            .iter()
            .filter_map(|model| {
                let name = model["name"].as_str()?;
                Some(ModelInfo {
                    id: name.to_string(),
                    name: name.to_string(),
                    provider: "ollama".to_string(),
                    context_length: 4096, // Default, varies by model
                    max_output_tokens: 4096,
                    supports_tools: false,
                    supports_streaming: true,
                    cost_per_input_token: Some(0.0), // Local models are free
                    cost_per_output_token: Some(0.0),
                })
            })
            .collect();

        Ok(model_infos)
    }

    fn provider_name(&self) -> &str {
        "ollama"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        false
    }
}

/// LLM Manager for handling multiple providers
pub struct LLMManager {
    providers: HashMap<String, Box<dyn LLMProvider>>,
    default_provider: Option<String>,
}

impl Default for LLMManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LLMManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            default_provider: None,
        }
    }

    pub fn add_provider(&mut self, name: String, provider: Box<dyn LLMProvider>) {
        info!("Adding LLM provider: {}", name);
        self.providers.insert(name.clone(), provider);

        if self.default_provider.is_none() {
            self.default_provider = Some(name);
        }
    }

    pub fn set_default_provider(&mut self, name: String) -> Result<()> {
        if !self.providers.contains_key(&name) {
            return Err(anyhow!("Provider not found: {}", name));
        }
        self.default_provider = Some(name);
        Ok(())
    }

    pub async fn complete(
        &self,
        request: LLMRequest,
        provider: Option<&str>,
    ) -> Result<LLMResponse> {
        let provider_name = provider
            .or(self.default_provider.as_deref())
            .ok_or_else(|| anyhow!("No provider specified and no default provider set"))?;

        let provider = self
            .providers
            .get(provider_name)
            .ok_or_else(|| anyhow!("Provider not found: {}", provider_name))?;

        provider.complete(request).await
    }

    pub async fn list_all_models(&self) -> Result<Vec<ModelInfo>> {
        let mut all_models = Vec::new();

        for provider in self.providers.values() {
            match provider.list_models().await {
                Ok(mut models) => all_models.append(&mut models),
                Err(e) => warn!(
                    "Failed to list models for provider {}: {}",
                    provider.provider_name(),
                    e
                ),
            }
        }

        Ok(all_models)
    }

    pub fn get_providers(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }
}

/// Create a default LLM manager with common providers
pub fn create_default_llm_manager() -> Result<LLMManager> {
    let mut manager = LLMManager::new();

    // Add Shimmy provider (local-first) - PRIORITY #1 for privacy
    #[cfg(feature = "llm")]
    {
        let shimmy = shimmy_provider::ShimmyProvider::new(None);
        manager.add_provider("shimmy".to_string(), Box::new(shimmy));
    }

    // Add Ollama provider (local)
    let ollama = OllamaProvider::new(None);
    manager.add_provider("ollama".to_string(), Box::new(ollama));

    // Add OpenAI provider if API key is available
    if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
        let openai = OpenAIProvider::new(api_key);
        manager.add_provider("openai".to_string(), Box::new(openai));
    }

    // Add Anthropic provider if API key is available
    if let Ok(api_key) = std::env::var("ANTHROPIC_API_KEY") {
        let anthropic = AnthropicProvider::new(api_key);
        manager.add_provider("anthropic".to_string(), Box::new(anthropic));
    }

    // Add Google Gemini provider if API key is available
    #[cfg(feature = "llm")]
    if let Ok(api_key) = std::env::var("GOOGLE_API_KEY") {
        let gemini = google_gemini_provider::GoogleGeminiProvider::new(api_key);
        manager.add_provider("google-gemini".to_string(), Box::new(gemini));
    }

    // Add AWS Bedrock provider if credentials are available
    #[cfg(feature = "llm")]
    if let (Ok(access_key), Ok(secret_key)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) {
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let mut bedrock =
            aws_bedrock_provider::AWSBedrockProvider::new(access_key, secret_key, region);

        if let Ok(session_token) = std::env::var("AWS_SESSION_TOKEN") {
            bedrock = bedrock.with_session_token(session_token);
        }

        manager.add_provider("aws-bedrock".to_string(), Box::new(bedrock));
    }

    // Add Azure OpenAI provider if credentials are available
    #[cfg(feature = "llm")]
    if let (Ok(api_key), Ok(endpoint), Ok(deployment)) = (
        std::env::var("AZURE_OPENAI_API_KEY"),
        std::env::var("AZURE_OPENAI_ENDPOINT"),
        std::env::var("AZURE_OPENAI_DEPLOYMENT_NAME"),
    ) {
        let mut azure =
            azure_openai_provider::AzureOpenAIProvider::new(api_key, endpoint, deployment);

        if let Ok(api_version) = std::env::var("AZURE_OPENAI_API_VERSION") {
            azure = azure.with_api_version(api_version);
        }

        manager.add_provider("azure-openai".to_string(), Box::new(azure));
    }

    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Mock LLM Provider for testing
    #[derive(Debug)]
    struct MockLLMProvider {
        name: String,
        responses: Arc<Mutex<HashMap<String, LLMResponse>>>,
        model_list: Vec<ModelInfo>,
        should_fail: bool,
    }

    impl MockLLMProvider {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                responses: Arc::new(Mutex::new(HashMap::new())),
                model_list: vec![ModelInfo {
                    id: format!("{}-model-1", name),
                    name: format!("{} Model 1", name.to_uppercase()),
                    provider: name.to_string(),
                    context_length: 4096,
                    max_output_tokens: 4096,
                    supports_tools: true,
                    supports_streaming: true,
                    cost_per_input_token: Some(0.001),
                    cost_per_output_token: Some(0.002),
                }],
                should_fail: false,
            }
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }

        async fn add_response(&self, input: String, response: LLMResponse) {
            self.responses.lock().await.insert(input, response);
        }
    }

    #[async_trait]
    impl LLMProvider for MockLLMProvider {
        async fn complete(&self, request: LLMRequest) -> Result<LLMResponse> {
            if self.should_fail {
                return Err(anyhow!("Mock provider failure"));
            }

            let input_key = request
                .messages
                .first()
                .map(|m| m.content.clone())
                .unwrap_or_default();

            let responses = self.responses.lock().await;
            if let Some(response) = responses.get(&input_key) {
                Ok(response.clone())
            } else {
                Ok(LLMResponse {
                    content: format!("Mock response from {}", self.name),
                    role: MessageRole::Assistant,
                    model: format!("{}-model-1", self.name),
                    usage: TokenUsage {
                        prompt_tokens: 10,
                        completion_tokens: 20,
                        total_tokens: 30,
                    },
                    tool_calls: None,
                    finish_reason: FinishReason::Stop,
                    metadata: HashMap::new(),
                })
            }
        }

        async fn stream<'a>(
            &'a self,
            _request: LLMRequest,
        ) -> Result<
            Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>,
            anyhow::Error,
        > {
            Err(anyhow!("Streaming not implemented in mock"))
        }

        async fn list_models(&self) -> Result<Vec<ModelInfo>> {
            if self.should_fail {
                return Err(anyhow!("Mock provider failure"));
            }
            Ok(self.model_list.clone())
        }

        fn provider_name(&self) -> &str {
            &self.name
        }

        fn supports_streaming(&self) -> bool {
            true
        }

        fn supports_tools(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_llm_request_creation() {
        let request = LLMRequest {
            messages: vec![
                ChatMessage {
                    role: MessageRole::System,
                    content: "You are a helpful assistant.".to_string(),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
                ChatMessage {
                    role: MessageRole::User,
                    content: "Hello, world!".to_string(),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                },
            ],
            model: Some("gpt-4".to_string()),
            temperature: Some(0.7),
            max_tokens: Some(100),
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.model, Some("gpt-4".to_string()));
        assert_eq!(request.temperature, Some(0.7));
        assert_eq!(request.max_tokens, Some(100));
        assert!(!request.stream);
    }

    #[tokio::test]
    async fn test_message_role_display() {
        assert_eq!(format!("{}", MessageRole::System), "system");
        assert_eq!(format!("{}", MessageRole::User), "user");
        assert_eq!(format!("{}", MessageRole::Assistant), "assistant");
        assert_eq!(format!("{}", MessageRole::Tool), "tool");
    }

    #[tokio::test]
    async fn test_llm_response_creation() {
        let response = LLMResponse {
            content: "Hello! How can I help you today?".to_string(),
            role: MessageRole::Assistant,
            model: "gpt-4".to_string(),
            usage: TokenUsage {
                prompt_tokens: 15,
                completion_tokens: 8,
                total_tokens: 23,
            },
            tool_calls: None,
            finish_reason: FinishReason::Stop,
            metadata: HashMap::new(),
        };

        assert_eq!(response.content, "Hello! How can I help you today?");
        assert_eq!(response.usage.total_tokens, 23);
        assert!(matches!(response.finish_reason, FinishReason::Stop));
    }

    #[tokio::test]
    async fn test_tool_definition_creation() {
        let tool = ToolDefinition {
            name: "get_weather".to_string(),
            description: "Get current weather for a location".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City and state, e.g. San Francisco, CA"
                    }
                },
                "required": ["location"]
            }),
        };

        assert_eq!(tool.name, "get_weather");
        assert!(tool.parameters.is_object());
    }

    #[tokio::test]
    async fn test_mock_provider_basic_completion() {
        let provider = MockLLMProvider::new("test");

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "Hello".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let response = provider.complete(request).await.unwrap();
        assert_eq!(response.content, "Mock response from test");
        assert_eq!(response.model, "test-model-1");
        assert_eq!(response.usage.total_tokens, 30);
    }

    #[tokio::test]
    async fn test_mock_provider_custom_response() {
        let provider = MockLLMProvider::new("test");

        let custom_response = LLMResponse {
            content: "Custom response".to_string(),
            role: MessageRole::Assistant,
            model: "test-model".to_string(),
            usage: TokenUsage {
                prompt_tokens: 5,
                completion_tokens: 10,
                total_tokens: 15,
            },
            tool_calls: None,
            finish_reason: FinishReason::Stop,
            metadata: HashMap::new(),
        };

        provider
            .add_response("test input".to_string(), custom_response.clone())
            .await;

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "test input".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let response = provider.complete(request).await.unwrap();
        assert_eq!(response.content, "Custom response");
        assert_eq!(response.usage.total_tokens, 15);
    }

    #[tokio::test]
    async fn test_mock_provider_failure() {
        let provider = MockLLMProvider::new("test").with_failure();

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "Hello".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let result = provider.complete(request).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Mock provider failure"));
    }

    #[tokio::test]
    async fn test_mock_provider_list_models() {
        let provider = MockLLMProvider::new("test");

        let models = provider.list_models().await.unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "test-model-1");
        assert_eq!(models[0].provider, "test");
        assert!(models[0].supports_tools);
        assert!(models[0].supports_streaming);
    }

    #[tokio::test]
    async fn test_llm_manager_creation() {
        let manager = LLMManager::new();
        assert_eq!(manager.get_providers().len(), 0);
        assert!(manager.default_provider.is_none());
    }

    #[tokio::test]
    async fn test_llm_manager_add_provider() {
        let mut manager = LLMManager::new();
        let provider = MockLLMProvider::new("test");

        manager.add_provider("test".to_string(), Box::new(provider));

        assert_eq!(manager.get_providers().len(), 1);
        assert!(manager.get_providers().contains(&"test"));
        assert_eq!(manager.default_provider, Some("test".to_string()));
    }

    #[tokio::test]
    async fn test_llm_manager_multiple_providers() {
        let mut manager = LLMManager::new();

        let provider1 = MockLLMProvider::new("provider1");
        let provider2 = MockLLMProvider::new("provider2");

        manager.add_provider("provider1".to_string(), Box::new(provider1));
        manager.add_provider("provider2".to_string(), Box::new(provider2));

        let providers = manager.get_providers();
        assert_eq!(providers.len(), 2);
        assert!(providers.contains(&"provider1"));
        assert!(providers.contains(&"provider2"));
        assert_eq!(manager.default_provider, Some("provider1".to_string()));
    }

    #[tokio::test]
    async fn test_llm_manager_set_default_provider() {
        let mut manager = LLMManager::new();
        let provider = MockLLMProvider::new("test");

        manager.add_provider("test".to_string(), Box::new(provider));
        manager.set_default_provider("test".to_string()).unwrap();

        assert_eq!(manager.default_provider, Some("test".to_string()));
    }

    #[tokio::test]
    async fn test_llm_manager_set_invalid_default_provider() {
        let mut manager = LLMManager::new();

        let result = manager.set_default_provider("nonexistent".to_string());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Provider not found"));
    }

    #[tokio::test]
    async fn test_llm_manager_complete_with_default_provider() {
        let mut manager = LLMManager::new();
        let provider = MockLLMProvider::new("test");

        manager.add_provider("test".to_string(), Box::new(provider));

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "Hello".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let response = manager.complete(request, None).await.unwrap();
        assert_eq!(response.content, "Mock response from test");
    }

    #[tokio::test]
    async fn test_llm_manager_complete_with_specific_provider() {
        let mut manager = LLMManager::new();
        let provider1 = MockLLMProvider::new("provider1");
        let provider2 = MockLLMProvider::new("provider2");

        manager.add_provider("provider1".to_string(), Box::new(provider1));
        manager.add_provider("provider2".to_string(), Box::new(provider2));

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "Hello".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let response = manager.complete(request, Some("provider2")).await.unwrap();
        assert_eq!(response.content, "Mock response from provider2");
    }

    #[tokio::test]
    async fn test_llm_manager_complete_no_provider() {
        let manager = LLMManager::new();

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "Hello".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let result = manager.complete(request, None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No provider specified"));
    }

    #[tokio::test]
    async fn test_llm_manager_complete_nonexistent_provider() {
        let mut manager = LLMManager::new();
        let provider = MockLLMProvider::new("test");

        manager.add_provider("test".to_string(), Box::new(provider));

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "Hello".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let result = manager.complete(request, Some("nonexistent")).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Provider not found"));
    }

    #[tokio::test]
    async fn test_llm_manager_list_all_models() {
        let mut manager = LLMManager::new();
        let provider1 = MockLLMProvider::new("provider1");
        let provider2 = MockLLMProvider::new("provider2");

        manager.add_provider("provider1".to_string(), Box::new(provider1));
        manager.add_provider("provider2".to_string(), Box::new(provider2));

        let models = manager.list_all_models().await.unwrap();
        assert_eq!(models.len(), 2);

        let provider1_models = models.iter().filter(|m| m.provider == "provider1").count();
        let provider2_models = models.iter().filter(|m| m.provider == "provider2").count();
        assert_eq!(provider1_models, 1);
        assert_eq!(provider2_models, 1);
    }

    #[tokio::test]
    async fn test_llm_manager_list_models_with_failure() {
        let mut manager = LLMManager::new();
        let working_provider = MockLLMProvider::new("working");
        let failing_provider = MockLLMProvider::new("failing").with_failure();

        manager.add_provider("working".to_string(), Box::new(working_provider));
        manager.add_provider("failing".to_string(), Box::new(failing_provider));

        let models = manager.list_all_models().await.unwrap();
        // Should only return models from the working provider
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].provider, "working");
    }
}
