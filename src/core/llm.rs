use crate::core::error::RustChainError;
use async_trait::async_trait;
use futures::stream::Stream;
use std::pin::Pin;

#[async_trait]
pub trait LLMBackend: Send + Sync {
    async fn generate(&self, prompt: &str) -> Result<String, RustChainError> {
        let mut stream = self.stream(prompt).await?;
        let mut output = String::new();
        use futures::StreamExt;
        while let Some(chunk) = stream.next().await {
            output.push_str(&chunk?);
        }
        Ok(output)
    }

    async fn stream(&self, prompt: &str) -> Result<
        Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>,
        RustChainError>;

    fn name(&self) -> &'static str;

    async fn health_check(&self) -> Result<bool, RustChainError>;
}
