// Azure OpenAI LLM Provider Implementation
use super::{ChatMessage, LLMProvider, LLMRequest, LLMResponse, MessageRole, ModelInfo};
use crate::core::http_client::{create_http_client, read_error_body_bounded};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct AzureOpenAIProvider {
    client: reqwest::Client,
    api_key: String,
    endpoint: String,
    api_version: String,
    deployment_name: String,
}

impl AzureOpenAIProvider {
    pub fn new(api_key: String, endpoint: String, deployment_name: String) -> Self {
        Self {
            client: create_http_client(None),
            api_key,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_version: "2024-06-01".to_string(), // Latest stable API version
            deployment_name,
        }
    }

    pub fn with_api_version(mut self, api_version: String) -> Self {
        self.api_version = api_version;
        self
    }

    pub fn with_deployment(mut self, deployment_name: String) -> Self {
        self.deployment_name = deployment_name;
        self
    }

    fn get_azure_url(&self) -> String {
        format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.endpoint, self.deployment_name, self.api_version
        )
    }

    fn to_azure(&self, messages: &[ChatMessage]) -> Vec<AzureMessage> {
        messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    MessageRole::System => "system",
                    MessageRole::User => "user",
                    MessageRole::Assistant => "assistant",
                    MessageRole::Tool => "user", // Tool responses as user messages
                };

                AzureMessage {
                    role: role.to_string(),
                    content: Some(msg.content.clone()),
                    tool_calls: None, // Tool calls handled separately in requests
                }
            })
            .collect()
    }
}

#[async_trait]
impl LLMProvider for AzureOpenAIProvider {
    async fn complete(&self, request: LLMRequest) -> Result<LLMResponse> {
        debug!("Azure OpenAI completion request: {:?}", request.model);

        let url = self.get_azure_url();
        let messages = self.to_azure(&request.messages);

        let azure_request = AzureRequest {
            messages,
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            stream: false,
        };

        let payload = serde_json::to_string(&azure_request)?;

        debug!("Sending request to Azure OpenAI: {}", url);

        let response = self
            .client
            .post(&url)
            .header("api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            error!("Azure OpenAI API error: {} - {}", status, error_text);
            return Err(anyhow!(
                "Azure OpenAI API error: {} - {}",
                status,
                error_text
            ));
        }

        let azure_response: AzureResponse = response.json().await?;

        let choice = azure_response
            .choices
            .first()
            .ok_or_else(|| anyhow!("No choices in Azure OpenAI response"))?;

        let content = choice.message.content.clone().unwrap_or_default();

        let usage = super::TokenUsage {
            prompt_tokens: azure_response.usage.prompt_tokens,
            completion_tokens: azure_response.usage.completion_tokens,
            total_tokens: azure_response.usage.total_tokens,
        };

        let finish_reason = match choice.finish_reason.as_deref().unwrap_or("stop") {
            "stop" => super::FinishReason::Stop,
            "length" => super::FinishReason::Length,
            "tool_calls" => super::FinishReason::ToolCalls,
            "content_filter" => super::FinishReason::ContentFilter,
            _ => super::FinishReason::Error,
        };

        info!(
            "Azure OpenAI completion successful, {} input tokens, {} output tokens",
            azure_response.usage.prompt_tokens, azure_response.usage.completion_tokens
        );

        Ok(LLMResponse {
            content,
            role: MessageRole::Assistant,
            model: self.deployment_name.clone(),
            usage,
            tool_calls: choice.message.tool_calls.clone().map(|calls| {
                calls
                    .into_iter()
                    .map(|call| super::ToolCall {
                        id: call.id,
                        function: super::FunctionCall {
                            name: call.function.name,
                            arguments: call.function.arguments,
                        },
                    })
                    .collect()
            }),
            finish_reason,
            metadata: HashMap::new(),
        })
    }

    async fn stream<'a>(
        &'a self,
        _request: LLMRequest,
    ) -> Result<Pin<Box<dyn futures::Stream<Item = Result<LLMResponse>> + Send + 'a>>, anyhow::Error>
    {
        // Streaming support for Azure OpenAI - not implemented in this version
        // Azure OpenAI streaming requires Server-Sent Events (SSE) parsing
        // This is a lower priority feature that can be added in future versions
        Err(anyhow!(
            "Streaming support requires SSE implementation - planned for future release"
        ))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        // Azure OpenAI models are deployment-specific, so we return common deployment models
        Ok(vec![
            ModelInfo {
                id: "gpt-4".to_string(),
                name: "GPT-4".to_string(),
                provider: "azure-openai".to_string(),
                context_length: 8192,
                max_output_tokens: 4096,
                supports_tools: true,
                supports_streaming: false, // Streaming planned for future release
                cost_per_input_token: Some(0.00003), // $30 per 1M tokens
                cost_per_output_token: Some(0.00006), // $60 per 1M tokens
            },
            ModelInfo {
                id: "gpt-4-32k".to_string(),
                name: "GPT-4 32K".to_string(),
                provider: "azure-openai".to_string(),
                context_length: 32768,
                max_output_tokens: 4096,
                supports_tools: true,
                supports_streaming: false,
                cost_per_input_token: Some(0.00006), // $60 per 1M tokens
                cost_per_output_token: Some(0.00012), // $120 per 1M tokens
            },
            ModelInfo {
                id: "gpt-35-turbo".to_string(),
                name: "GPT-3.5 Turbo".to_string(),
                provider: "azure-openai".to_string(),
                context_length: 4096,
                max_output_tokens: 4096,
                supports_tools: true,
                supports_streaming: false,
                cost_per_input_token: Some(0.0000015), // $1.5 per 1M tokens
                cost_per_output_token: Some(0.000002), // $2 per 1M tokens
            },
            ModelInfo {
                id: "gpt-35-turbo-16k".to_string(),
                name: "GPT-3.5 Turbo 16K".to_string(),
                provider: "azure-openai".to_string(),
                context_length: 16384,
                max_output_tokens: 4096,
                supports_tools: true,
                supports_streaming: false,
                cost_per_input_token: Some(0.000003), // $3 per 1M tokens
                cost_per_output_token: Some(0.000004), // $4 per 1M tokens
            },
        ])
    }

    fn provider_name(&self) -> &str {
        "azure-openai"
    }

    fn supports_streaming(&self) -> bool {
        false // Streaming planned for future release - requires SSE implementation
    }

    fn supports_tools(&self) -> bool {
        true
    }
}

// Azure OpenAI API request/response structures
#[derive(Debug, Serialize)]
struct AzureRequest {
    messages: Vec<AzureMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct AzureMessage {
    role: String,
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<AzureToolCall>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AzureToolCall {
    id: String,
    function: AzureFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AzureFunction {
    name: String,
    arguments: String,
}

#[derive(Debug, Deserialize)]
struct AzureResponse {
    choices: Vec<AzureChoice>,
    usage: AzureUsage,
}

#[derive(Debug, Deserialize)]
struct AzureChoice {
    message: AzureMessage,
    #[serde(rename = "finish_reason")]
    finish_reason: Option<String>,
    #[allow(dead_code)]
    index: u32,
}

#[derive(Debug, Deserialize)]
struct AzureUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_provider_creation() {
        let provider = AzureOpenAIProvider::new(
            "test-api-key".to_string(),
            "https://test.openai.azure.com".to_string(),
            "gpt-4".to_string(),
        );
        assert_eq!(provider.provider_name(), "azure-openai");
        assert_eq!(provider.endpoint, "https://test.openai.azure.com");
        assert_eq!(provider.deployment_name, "gpt-4");
        assert_eq!(provider.api_version, "2024-06-01");
    }

    #[test]
    fn test_azure_provider_with_custom_api_version() {
        let provider = AzureOpenAIProvider::new(
            "test-api-key".to_string(),
            "https://test.openai.azure.com".to_string(),
            "gpt-35-turbo".to_string(),
        )
        .with_api_version("2023-12-01-preview".to_string());

        assert_eq!(provider.api_version, "2023-12-01-preview");
        assert_eq!(provider.deployment_name, "gpt-35-turbo");
    }

    #[test]
    fn test_azure_provider_with_custom_deployment() {
        let provider = AzureOpenAIProvider::new(
            "test-api-key".to_string(),
            "https://test.openai.azure.com".to_string(),
            "initial-deployment".to_string(),
        )
        .with_deployment("custom-deployment".to_string());

        assert_eq!(provider.deployment_name, "custom-deployment");
    }

    #[test]
    fn test_azure_url_generation() {
        let provider = AzureOpenAIProvider::new(
            "test-api-key".to_string(),
            "https://test.openai.azure.com".to_string(),
            "gpt-4".to_string(),
        );

        let url = provider.get_azure_url();
        assert_eq!(
            url,
            "https://test.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-06-01"
        );
    }

    #[test]
    fn test_azure_url_generation_with_trailing_slash() {
        let provider = AzureOpenAIProvider::new(
            "test-api-key".to_string(),
            "https://test.openai.azure.com/".to_string(), // With trailing slash
            "gpt-4".to_string(),
        );

        let url = provider.get_azure_url();
        assert_eq!(
            url,
            "https://test.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-06-01"
        );
    }

    #[test]
    fn test_message_conversion() {
        let provider = AzureOpenAIProvider::new(
            "test-api-key".to_string(),
            "https://test.openai.azure.com".to_string(),
            "gpt-4".to_string(),
        );

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
            ChatMessage {
                role: MessageRole::Assistant,
                content: "Hi there! How can I help you?".to_string(),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
        ];

        let azure_messages = provider.to_azure(&messages);
        assert_eq!(azure_messages.len(), 3);
        assert_eq!(azure_messages[0].role, "system");
        assert_eq!(azure_messages[1].role, "user");
        assert_eq!(azure_messages[2].role, "assistant");
        assert_eq!(
            azure_messages[0].content,
            Some("You are a helpful assistant".to_string())
        );
        assert_eq!(azure_messages[1].content, Some("Hello!".to_string()));
        assert_eq!(
            azure_messages[2].content,
            Some("Hi there! How can I help you?".to_string())
        );
    }

    #[tokio::test]
    async fn test_list_models() {
        let provider = AzureOpenAIProvider::new(
            "test-api-key".to_string(),
            "https://test.openai.azure.com".to_string(),
            "gpt-4".to_string(),
        );

        let models = provider.list_models().await.unwrap();
        assert_eq!(models.len(), 4);
        assert!(models.iter().any(|m| m.id == "gpt-4"));
        assert!(models.iter().any(|m| m.id == "gpt-4-32k"));
        assert!(models.iter().any(|m| m.id == "gpt-35-turbo"));
        assert!(models.iter().any(|m| m.id == "gpt-35-turbo-16k"));

        // Check that all models have azure-openai provider
        assert!(models.iter().all(|m| m.provider == "azure-openai"));
    }
}
