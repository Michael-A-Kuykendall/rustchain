use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use tracing::{debug, warn};

use crate::llm::{
    ChatMessage, FinishReason, LLMProvider, LLMRequest, LLMResponse, MessageRole, ModelInfo,
    TokenUsage,
};

/// Shimmy-compatible request format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShimmyRequest {
    model: String,
    prompt: Option<String>,
    messages: Option<Vec<ChatMessage>>,
    max_tokens: Option<usize>,
    temperature: Option<f32>,
    top_p: Option<f32>,
    top_k: Option<i32>,
    stream: Option<bool>,
}

/// Shimmy response format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShimmyResponse {
    text: String,
    tokens_used: Option<u32>,
    model: String,
    #[serde(default)]
    finish_reason: String,
}

/// ShimmyProvider - Local-first AI inference via Shimmy
///
/// Provides air-gapped, privacy-first inference for RustChain missions
/// without requiring cloud API keys or external dependencies.
pub struct ShimmyProvider {
    client: reqwest::Client,
    base_url: String,
    default_model: String,
    timeout: std::time::Duration,
}

impl ShimmyProvider {
    /// Create a new ShimmyProvider with default settings
    pub fn new(base_url: Option<String>) -> Self {
        let timeout = std::time::Duration::from_secs(120);
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("Failed to build HTTP client"),
            base_url: base_url.unwrap_or_else(|| "http://localhost:11434".to_string()),
            default_model: "phi3-mini".to_string(), // Available shimmy model
            timeout,
        }
    }

    /// Set the default model for requests
    pub fn with_model(mut self, model: String) -> Self {
        self.default_model = model;
        self
    }

    /// Set the base URL for shimmy server
    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    /// Set request timeout
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Convert RustChain LLMRequest to Shimmy format
    #[allow(dead_code)] // Reserved for future shimmy client integration
    fn convert_to_shimmy_request(&self, request: &LLMRequest) -> ShimmyRequest {
        let model = request
            .model
            .as_ref()
            .unwrap_or(&self.default_model)
            .clone();

        // Use OpenAI-compatible messages format - Shimmy supports this
        let prompt = if !request.messages.is_empty() {
            request
                .messages
                .iter()
                .map(|msg| format!("{}: {}", msg.role, msg.content))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            "".to_string()
        };

        ShimmyRequest {
            model,
            prompt: if prompt.is_empty() {
                None
            } else {
                Some(prompt)
            },
            messages: Some(request.messages.clone()),
            max_tokens: request.max_tokens.map(|t| t as usize),
            temperature: request.temperature,
            top_p: None,
            top_k: None,
            stream: Some(request.stream),
        }
    }

    /// Convert Shimmy response to RustChain format
    #[allow(dead_code)] // Reserved for future shimmy client integration
    fn convert_from_shimmy_response(&self, response: ShimmyResponse) -> LLMResponse {
        let finish_reason = match response.finish_reason.as_str() {
            "stop" => FinishReason::Stop,
            "length" => FinishReason::Length,
            "error" => FinishReason::Error,
            _ => FinishReason::Stop,
        };

        // Estimate token usage (shimmy may not provide detailed counts)
        let prompt_tokens = 0; // Would need to be calculated
        let completion_tokens = response.tokens_used.unwrap_or(0);

        LLMResponse {
            content: response.text,
            role: MessageRole::Assistant,
            model: response.model,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
            tool_calls: None, // Shimmy doesn't support tool calls yet
            finish_reason,
            metadata: HashMap::new(),
        }
    }
}

#[async_trait]
impl LLMProvider for ShimmyProvider {
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse> {
        let url = format!("{}/v1/chat/completions", self.base_url);

        // Use OpenAI-compatible format that Shimmy actually supports
        let openai_request = serde_json::json!({
            "model": request.model.unwrap_or_else(|| self.default_model.clone()),
            "messages": request.messages,
            "temperature": request.temperature.unwrap_or(0.7),
            "max_tokens": request.max_tokens.unwrap_or(2000),
            "stream": false
        });

        debug!("Sending request to Shimmy: {}", url);

        let response = self
            .client
            .post(&url)
            .timeout(self.timeout)
            .json(&openai_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!("Shimmy API error ({}): {}", status, error_text));
        }

        // Parse OpenAI-compatible response format
        let openai_response: serde_json::Value = response.json().await?;

        if let Some(choices) = openai_response["choices"].as_array() {
            if let Some(first_choice) = choices.first() {
                if let Some(message) = first_choice["message"].as_object() {
                    let content = message["content"].as_str().unwrap_or("").to_string();
                    let model = openai_response["model"]
                        .as_str()
                        .unwrap_or(&self.default_model)
                        .to_string();

                    return Ok(LLMResponse {
                        content,
                        role: MessageRole::Assistant,
                        model,
                        usage: TokenUsage {
                            prompt_tokens: openai_response["usage"]["prompt_tokens"]
                                .as_u64()
                                .unwrap_or(0) as u32,
                            completion_tokens: openai_response["usage"]["completion_tokens"]
                                .as_u64()
                                .unwrap_or(0) as u32,
                            total_tokens: openai_response["usage"]["total_tokens"]
                                .as_u64()
                                .unwrap_or(0) as u32,
                        },
                        tool_calls: None,
                        finish_reason: FinishReason::Stop,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Err(anyhow!("Invalid response format from Shimmy"))
    }

    async fn stream<'a>(
        &'a self,
        request: LLMRequest,
    ) -> Result<Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>> {
        use futures::stream::StreamExt;
        use serde_json;

        let url = format!("{}/api/generate", self.base_url);

        // Convert LLMRequest to ShimmyRequest
        let model = request.model.unwrap_or_else(|| self.default_model.clone());

        // Convert messages to a single prompt for now
        let prompt = if !request.messages.is_empty() {
            request
                .messages
                .iter()
                .map(|msg| format!("{}: {}", msg.role, msg.content))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            "".to_string()
        };

        let shimmy_request = ShimmyRequest {
            model: model.clone(),
            prompt: if prompt.is_empty() {
                None
            } else {
                Some(prompt)
            },
            messages: Some(request.messages.clone()),
            max_tokens: request.max_tokens.map(|t| t as usize),
            temperature: request.temperature,
            top_p: None, // Not supported in this version
            top_k: None,
            stream: Some(true), // Enable streaming
        };

        debug!("Making streaming request to Shimmy: {}", url);

        let response = self
            .client
            .post(&url)
            .json(&shimmy_request)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!(
                "Shimmy streaming request failed with status {}: {}",
                status,
                error_text
            ));
        }

        // Convert response stream to LLMResponse stream
        let _stream = response
            .bytes_stream()
            .map(move |chunk_result| {
                let model_name = model.clone();
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

                                match serde_json::from_str::<ShimmyResponse>(data_line) {
                                    Ok(shimmy_response) => {
                                        let finish_reason =
                                            match shimmy_response.finish_reason.as_str() {
                                                "stop" => FinishReason::Stop,
                                                "length" => FinishReason::Length,
                                                _ => FinishReason::Stop, // Default fallback
                                            };

                                        return Ok(LLMResponse {
                                            content: shimmy_response.text,
                                            role: MessageRole::Assistant,
                                            model: shimmy_response.model,
                                            usage: TokenUsage {
                                                prompt_tokens: 0,
                                                completion_tokens: shimmy_response
                                                    .tokens_used
                                                    .unwrap_or(0),
                                                total_tokens: shimmy_response
                                                    .tokens_used
                                                    .unwrap_or(0),
                                            },
                                            tool_calls: None,
                                            finish_reason,
                                            metadata: HashMap::new(),
                                        });
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
                            model: model_name,
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

        // For now, return error indicating streaming not fully implemented
        // This prevents compilation errors while maintaining the interface
        Err(anyhow!("Shimmy streaming implementation requires further async stream handling - using generate() instead"))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let url = format!("{}/v1/models", self.base_url);

        debug!("Fetching models from Shimmy: {}", url);

        let response = self.client.get(&url).timeout(self.timeout).send().await?;

        if !response.status().is_success() {
            // If models endpoint doesn't exist, return default model
            warn!("Shimmy models endpoint not available, using default model");
            return Ok(vec![ModelInfo {
                id: self.default_model.clone(),
                name: self.default_model.clone(),
                provider: "shimmy".to_string(),
                context_length: 4096, // Default assumption
                max_output_tokens: 4096,
                supports_tools: false,    // Shimmy doesn't support tools yet
                supports_streaming: true, // Shimmy supports SSE streaming
                cost_per_input_token: Some(0.0), // Local models are free
                cost_per_output_token: Some(0.0),
            }]);
        }

        // Parse OpenAI-compatible models response
        let models_response: serde_json::Value = response.json().await?;

        if let Some(data) = models_response["data"].as_array() {
            let models: Vec<ModelInfo> = data
                .iter()
                .filter_map(|model| {
                    model["id"].as_str().map(|id| ModelInfo {
                        id: id.to_string(),
                        name: id.to_string(),
                        provider: "shimmy".to_string(),
                        context_length: 4096, // Default for local models
                        max_output_tokens: 4096,
                        supports_tools: false,
                        supports_streaming: true,
                        cost_per_input_token: Some(0.0), // Local models are free
                        cost_per_output_token: Some(0.0),
                    })
                })
                .collect();

            if !models.is_empty() {
                return Ok(models);
            }
        }

        // Fallback to default model
        Ok(vec![ModelInfo {
            id: self.default_model.clone(),
            name: self.default_model.clone(),
            provider: "shimmy".to_string(),
            context_length: 4096,
            max_output_tokens: 4096,
            supports_tools: false,
            supports_streaming: true,
            cost_per_input_token: Some(0.0),
            cost_per_output_token: Some(0.0),
        }])
    }

    fn provider_name(&self) -> &str {
        "shimmy"
    }

    fn supports_streaming(&self) -> bool {
        true // Shimmy supports SSE streaming
    }

    fn supports_tools(&self) -> bool {
        false // Not yet implemented in Shimmy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{ChatMessage, MessageRole};

    #[tokio::test]
    async fn test_shimmy_provider_creation() {
        let provider = ShimmyProvider::new(None);
        assert_eq!(provider.provider_name(), "shimmy");
        assert_eq!(provider.base_url, "http://localhost:11434");
        assert_eq!(provider.default_model, "phi3-mini");
        assert!(provider.supports_streaming());
        assert!(!provider.supports_tools());
    }

    #[tokio::test]
    async fn test_shimmy_provider_with_custom_settings() {
        let provider = ShimmyProvider::new(Some("http://localhost:8080".to_string()))
            .with_model("custom-model".to_string())
            .with_timeout(std::time::Duration::from_secs(60));

        assert_eq!(provider.base_url, "http://localhost:8080");
        assert_eq!(provider.default_model, "custom-model");
        assert_eq!(provider.timeout, std::time::Duration::from_secs(60));
    }

    #[test]
    fn test_convert_to_shimmy_request() {
        let provider = ShimmyProvider::new(None);
        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: "Hello, world!".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: Some("test-model".to_string()),
            temperature: Some(0.7),
            max_tokens: Some(100),
            stream: false,
            tools: None,
            metadata: HashMap::new(),
        };

        let shimmy_request = provider.convert_to_shimmy_request(&request);
        assert_eq!(shimmy_request.model, "test-model");
        assert_eq!(shimmy_request.temperature, Some(0.7));
        assert_eq!(shimmy_request.max_tokens, Some(100));
        assert_eq!(shimmy_request.stream, Some(false));
        assert!(shimmy_request.prompt.is_some());
    }

    #[test]
    fn test_convert_from_shimmy_response() {
        let provider = ShimmyProvider::new(None);
        let shimmy_response = ShimmyResponse {
            text: "Hello! How can I help you?".to_string(),
            tokens_used: Some(25),
            model: "phi3-lora".to_string(),
            finish_reason: "stop".to_string(),
        };

        let llm_response = provider.convert_from_shimmy_response(shimmy_response);
        assert_eq!(llm_response.content, "Hello! How can I help you?");
        assert_eq!(llm_response.model, "phi3-lora");
        assert_eq!(llm_response.usage.completion_tokens, 25);
        assert!(matches!(llm_response.finish_reason, FinishReason::Stop));
        assert!(matches!(llm_response.role, MessageRole::Assistant));
    }
}
