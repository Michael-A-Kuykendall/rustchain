// Google Gemini LLM Provider Implementation
use super::{ChatMessage, LLMProvider, LLMRequest, LLMResponse, MessageRole, ModelInfo};
use crate::core::http_client::{create_http_client, read_error_body_bounded};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct GoogleGeminiProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
    model: String,
}

impl GoogleGeminiProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: create_http_client(Some(60)),
            api_key,
            base_url: "https://generativelanguage.googleapis.com/v1beta".to_string(),
            model: "gemini-1.5-pro-latest".to_string(),
        }
    }

    pub fn new_with_model(api_key: String, model: String) -> Self {
        Self {
            client: create_http_client(Some(60)),
            api_key,
            base_url: "https://generativelanguage.googleapis.com/v1beta".to_string(),
            model,
        }
    }

    fn to_gemini(&self, messages: &[ChatMessage]) -> Vec<GeminiContent> {
        let mut contents = Vec::new();

        for message in messages {
            let role = match message.role {
                MessageRole::System => "user", // Gemini treats system as user message
                MessageRole::User => "user",
                MessageRole::Assistant => "model",
                MessageRole::Tool => "user", // Tool responses as user messages
            };

            contents.push(GeminiContent {
                role: role.to_string(),
                parts: vec![GeminiPart {
                    text: message.content.clone(),
                }],
            });
        }

        contents
    }
}

#[async_trait]
impl LLMProvider for GoogleGeminiProvider {
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse> {
        debug!("Google Gemini completion request: {:?}", request.model);

        let model = request.model.as_ref().unwrap_or(&self.model);
        let url = format!("{}/models/{}:generateContent", self.base_url, model);

        let contents = self.to_gemini(&request.messages);

        let mut generation_config = GeminiGenerationConfig::default();
        if let Some(temp) = request.temperature {
            generation_config.temperature = Some(temp);
        }
        if let Some(max_tokens) = request.max_tokens {
            generation_config.max_output_tokens = Some(max_tokens as i32);
        }

        let gemini_request = GeminiRequest {
            contents,
            generation_config: Some(generation_config),
            safety_settings: None,
        };

        debug!("Sending request to Gemini API: {}", url);

        let response = self
            .client
            .post(&url)
            .query(&[("key", &self.api_key)])
            .header("Content-Type", "application/json")
            .json(&gemini_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            error!("Gemini API error: {} - {}", status, error_text);
            return Err(anyhow!("Gemini API error: {} - {}", status, error_text));
        }

        let gemini_response: GeminiResponse = response.json().await?;

        let content = gemini_response
            .candidates
            .first()
            .and_then(|c| c.content.parts.first())
            .map(|p| p.text.clone())
            .unwrap_or_default();

        let usage = super::TokenUsage {
            prompt_tokens: 0, // Gemini doesn't provide token counts in basic response
            completion_tokens: 0,
            total_tokens: 0,
        };

        info!("Gemini completion successful, {} characters", content.len());

        Ok(LLMResponse {
            content,
            role: MessageRole::Assistant,
            model: model.clone(),
            usage,
            tool_calls: None, // Tool calls support available via function calling API
            finish_reason: super::FinishReason::Stop,
            metadata: HashMap::new(),
        })
    }

    async fn stream<'a>(
        &'a self,
        _request: LLMRequest,
    ) -> Result<Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>, anyhow::Error>
    {
        // Streaming support can be implemented via Server-Sent Events
        Err(anyhow!(
            "Streaming support available but not yet integrated"
        ))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        Ok(vec![
            ModelInfo {
                id: "gemini-1.5-pro-latest".to_string(),
                name: "Gemini 1.5 Pro".to_string(),
                provider: "google".to_string(),
                context_length: 2_000_000,
                max_output_tokens: 8192,
                supports_tools: true,
                supports_streaming: false, // Streaming available but not yet integrated
                cost_per_input_token: Some(0.00000125), // $1.25 per 1M tokens
                cost_per_output_token: Some(0.000005), // $5 per 1M tokens
            },
            ModelInfo {
                id: "gemini-1.5-flash-latest".to_string(),
                name: "Gemini 1.5 Flash".to_string(),
                provider: "google".to_string(),
                context_length: 1_000_000,
                max_output_tokens: 8192,
                supports_tools: true,
                supports_streaming: false,
                cost_per_input_token: Some(0.000000075), // $0.075 per 1M tokens
                cost_per_output_token: Some(0.0000003),  // $0.30 per 1M tokens
            },
            ModelInfo {
                id: "gemini-pro".to_string(),
                name: "Gemini Pro".to_string(),
                provider: "google".to_string(),
                context_length: 30720,
                max_output_tokens: 2048,
                supports_tools: false,
                supports_streaming: false,
                cost_per_input_token: Some(0.0000005), // $0.50 per 1M tokens
                cost_per_output_token: Some(0.0000015), // $1.50 per 1M tokens
            },
        ])
    }

    fn provider_name(&self) -> &str {
        "google-gemini"
    }

    fn supports_streaming(&self) -> bool {
        false // Streaming available but not yet integrated
    }

    fn supports_tools(&self) -> bool {
        true
    }
}

// Gemini API request/response structures
#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safety_settings: Option<Vec<GeminiSafetySetting>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiPart {
    text: String,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<i32>,
}

impl Default for GeminiGenerationConfig {
    fn default() -> Self {
        Self {
            temperature: Some(0.7),
            top_p: Some(0.9),
            top_k: Some(40),
            max_output_tokens: Some(2048),
        }
    }
}

#[derive(Debug, Serialize)]
struct GeminiSafetySetting {
    category: String,
    threshold: String,
}

#[derive(Debug, Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
    #[serde(rename = "promptFeedback")]
    #[allow(dead_code)]
    prompt_feedback: Option<GeminiPromptFeedback>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: GeminiContent,
    #[serde(rename = "finishReason")]
    #[allow(dead_code)]
    finish_reason: Option<String>,
    #[serde(rename = "safetyRatings")]
    #[allow(dead_code)]
    safety_ratings: Option<Vec<GeminiSafetyRating>>,
}

#[derive(Debug, Deserialize)]
struct GeminiPromptFeedback {
    #[serde(rename = "safetyRatings")]
    #[allow(dead_code)]
    safety_ratings: Vec<GeminiSafetyRating>,
}

#[derive(Debug, Deserialize)]
struct GeminiSafetyRating {
    #[allow(dead_code)]
    category: String,
    #[allow(dead_code)]
    probability: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gemini_provider_creation() {
        let provider = GoogleGeminiProvider::new("test-key".to_string());
        assert_eq!(provider.provider_name(), "google-gemini");
        assert_eq!(provider.model, "gemini-1.5-pro-latest");
    }

    #[test]
    fn test_gemini_provider_with_custom_model() {
        let provider =
            GoogleGeminiProvider::new_with_model("test-key".to_string(), "gemini-pro".to_string());
        assert_eq!(provider.model, "gemini-pro");
    }

    #[test]
    fn test_message_conversion() {
        let provider = GoogleGeminiProvider::new("test-key".to_string());
        let messages = vec![
            ChatMessage {
                role: MessageRole::System,
                content: "You are a helpful assistant".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            ChatMessage {
                role: MessageRole::User,
                content: "Hello!".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
        ];

        let gemini_contents = provider.to_gemini(&messages);
        assert_eq!(gemini_contents.len(), 2);
        assert_eq!(gemini_contents[0].role, "user"); // System becomes user
        assert_eq!(gemini_contents[1].role, "user");
        assert_eq!(
            gemini_contents[0].parts[0].text,
            "You are a helpful assistant"
        );
    }

    #[tokio::test]
    async fn test_list_models() {
        let provider = GoogleGeminiProvider::new("test-key".to_string());
        let models = provider.list_models().await.unwrap();
        assert_eq!(models.len(), 3);
        assert!(models.iter().any(|m| m.id == "gemini-1.5-pro-latest"));
        assert!(models.iter().any(|m| m.id == "gemini-1.5-flash-latest"));
        assert!(models.iter().any(|m| m.id == "gemini-pro"));
    }
}
