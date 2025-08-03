use crate::core::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait LLMBackend: Send + Sync {
    async fn generate(&self, prompt: &str) -> Result<String>;
    fn name(&self) -> &'static str;
}

pub struct OllamaBackend {
    base_url: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaBackend {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl LLMBackend for OllamaBackend {
    async fn generate(&self, prompt: &str) -> Result<String> {
        let payload = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });
        
        let response = self.client
            .post(&format!("{}/api/generate", self.base_url))
            .json(&payload)
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result["response"].as_str().unwrap_or("No response").to_string())
    }
    
    fn name(&self) -> &'static str {
        "ollama"
    }
}
