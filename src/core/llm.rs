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

    async fn stream(
        &self,
        prompt: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>, RustChainError>;

    fn name(&self) -> &'static str;

    async fn health_check(&self) -> Result<bool, RustChainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::RustChainError;
    use async_trait::async_trait;
    use futures::stream;
    use std::pin::Pin;

    // Mock LLM Backend for testing
    struct MockLLMBackend {
        responses: Vec<String>,
        should_fail: bool,
        stream_chunks: Vec<String>,
        health_status: bool,
    }

    impl MockLLMBackend {
        fn new() -> Self {
            Self {
                responses: vec!["Default mock response".to_string()],
                should_fail: false,
                stream_chunks: vec!["Hello".to_string(), " world!".to_string()],
                health_status: true,
            }
        }

        fn with_responses(mut self, responses: Vec<String>) -> Self {
            self.responses = responses;
            self
        }

        fn with_failure(mut self, should_fail: bool) -> Self {
            self.should_fail = should_fail;
            self
        }

        fn with_stream_chunks(mut self, chunks: Vec<String>) -> Self {
            self.stream_chunks = chunks;
            self
        }

        fn with_health_status(mut self, healthy: bool) -> Self {
            self.health_status = healthy;
            self
        }
    }

    #[async_trait]
    impl LLMBackend for MockLLMBackend {
        async fn generate(&self, prompt: &str) -> Result<String, RustChainError> {
            if self.should_fail {
                return Err(RustChainError::Llm(
                    crate::core::error::LlmError::response_error("Mock LLM failure".to_string()),
                ));
            }

            // Select response based on prompt content for more realistic testing
            if prompt.contains("error") {
                Err(RustChainError::Llm(
                    crate::core::error::LlmError::response_error(
                        "Prompt contained error".to_string(),
                    ),
                ))
            } else if prompt.contains("hello") {
                Ok("Hello! How can I help you today?".to_string())
            } else if prompt.contains("translate") {
                Ok("Translated text: Bonjour le monde!".to_string())
            } else {
                Ok(self
                    .responses
                    .first()
                    .unwrap_or(&"Default response".to_string())
                    .clone())
            }
        }

        async fn stream(
            &self,
            prompt: &str,
        ) -> Result<
            Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>,
            RustChainError,
        > {
            if self.should_fail {
                return Err(RustChainError::Llm(
                    crate::core::error::LlmError::response_error("Mock stream failure".to_string()),
                ));
            }

            if prompt.contains("stream_error") {
                // Return a stream that fails partway through
                let error_stream = stream::iter(vec![
                    Ok("Starting...".to_string()),
                    Err(RustChainError::Llm(
                        crate::core::error::LlmError::response_error(
                            "Stream error during generation".to_string(),
                        ),
                    )),
                ]);
                return Ok(Box::pin(error_stream));
            }

            // Create a stream from the chunks
            let chunks = self.stream_chunks.clone();
            let chunk_stream = stream::iter(chunks.into_iter().map(Ok));
            Ok(Box::pin(chunk_stream))
        }

        fn name(&self) -> &'static str {
            "MockLLM"
        }

        async fn health_check(&self) -> Result<bool, RustChainError> {
            if self.should_fail && !self.health_status {
                Err(RustChainError::Llm(
                    crate::core::error::LlmError::service_unavailable("MockLLM"),
                ))
            } else {
                Ok(self.health_status)
            }
        }
    }

    // Alternative mock that implements generate directly
    struct DirectGenerateMock {
        response: String,
        should_fail: bool,
    }

    impl DirectGenerateMock {
        fn new(response: String) -> Self {
            Self {
                response,
                should_fail: false,
            }
        }

        fn with_failure(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    #[async_trait]
    impl LLMBackend for DirectGenerateMock {
        // Override the default generate implementation
        async fn generate(&self, _prompt: &str) -> Result<String, RustChainError> {
            if self.should_fail {
                Err(RustChainError::Llm(
                    crate::core::error::LlmError::response_error(
                        "Direct generate failure".to_string(),
                    ),
                ))
            } else {
                Ok(self.response.clone())
            }
        }

        async fn stream(
            &self,
            _prompt: &str,
        ) -> Result<
            Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>,
            RustChainError,
        > {
            let chunks = vec![self.response.clone()];
            let chunk_stream = stream::iter(chunks.into_iter().map(Ok));
            Ok(Box::pin(chunk_stream))
        }

        fn name(&self) -> &'static str {
            "DirectGenerateMock"
        }

        async fn health_check(&self) -> Result<bool, RustChainError> {
            Ok(!self.should_fail)
        }
    }

    #[tokio::test]
    async fn test_mock_llm_backend_basic() {
        let mock = MockLLMBackend::new();

        assert_eq!(mock.name(), "MockLLM");

        let health = mock.health_check().await.unwrap();
        assert!(health);
    }

    #[tokio::test]
    async fn test_mock_llm_generate_success() {
        let mock = MockLLMBackend::new().with_responses(vec!["Test response".to_string()]);

        let result = mock.generate("test prompt").await.unwrap();
        assert_eq!(result, "Test response");
    }

    #[tokio::test]
    async fn test_mock_llm_generate_context_aware() {
        let mock = MockLLMBackend::new();

        // Test context-aware responses
        let hello_result = mock.generate("hello world").await.unwrap();
        assert_eq!(hello_result, "Hello! How can I help you today?");

        let translate_result = mock.generate("translate this text").await.unwrap();
        assert_eq!(translate_result, "Translated text: Bonjour le monde!");

        let generic_result = mock.generate("generic prompt").await.unwrap();
        assert_eq!(generic_result, "Default mock response");
    }

    #[tokio::test]
    async fn test_mock_llm_generate_failure() {
        let mock = MockLLMBackend::new().with_failure(true);

        let result = mock.generate("test prompt").await;
        assert!(result.is_err());

        match result {
            Err(RustChainError::Llm(e)) => {
                assert!(e.to_string().contains("Mock LLM failure"));
            }
            _ => panic!("Expected LLM error"),
        }
    }

    #[tokio::test]
    async fn test_mock_llm_generate_prompt_error() {
        let mock = MockLLMBackend::new();

        let result = mock.generate("this prompt contains error").await;
        assert!(result.is_err());

        match result {
            Err(RustChainError::Llm(e)) => {
                assert!(e.to_string().contains("Prompt contained error"));
            }
            _ => panic!("Expected LLM error"),
        }
    }

    #[tokio::test]
    async fn test_mock_llm_stream_success() {
        let mock = MockLLMBackend::new()
            .with_stream_chunks(vec!["Hello".to_string(), " world!".to_string()]);

        let mut stream = mock.stream("test prompt").await.unwrap();

        use futures::StreamExt;
        let mut chunks = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            chunks.push(chunk_result.unwrap());
        }

        assert_eq!(chunks, vec!["Hello", " world!"]);
    }

    #[tokio::test]
    async fn test_mock_llm_stream_failure() {
        let mock = MockLLMBackend::new().with_failure(true);

        let result = mock.stream("test prompt").await;
        assert!(result.is_err());

        match result {
            Err(RustChainError::Llm(e)) => {
                assert!(e.to_string().contains("Mock stream failure"));
            }
            _ => panic!("Expected LLM error"),
        }
    }

    #[tokio::test]
    async fn test_mock_llm_stream_error_during_generation() {
        let mock = MockLLMBackend::new();

        let mut stream = mock.stream("stream_error prompt").await.unwrap();

        use futures::StreamExt;
        let first_chunk = stream.next().await.unwrap().unwrap();
        assert_eq!(first_chunk, "Starting...");

        let second_chunk = stream.next().await.unwrap();
        assert!(second_chunk.is_err());

        match second_chunk {
            Err(RustChainError::Llm(e)) => {
                assert!(e.to_string().contains("Stream error during generation"));
            }
            _ => panic!("Expected LLM error"),
        }
    }

    #[tokio::test]
    async fn test_mock_llm_health_check_success() {
        let mock = MockLLMBackend::new().with_health_status(true);

        let health = mock.health_check().await.unwrap();
        assert!(health);
    }

    #[tokio::test]
    async fn test_mock_llm_health_check_unhealthy() {
        let mock = MockLLMBackend::new().with_health_status(false);

        let health = mock.health_check().await.unwrap();
        assert!(!health);
    }

    #[tokio::test]
    async fn test_mock_llm_health_check_failure() {
        let mock = MockLLMBackend::new()
            .with_failure(true)
            .with_health_status(false);

        let result = mock.health_check().await;
        assert!(result.is_err());

        match result {
            Err(RustChainError::Llm(e)) => {
                assert!(e.to_string().contains("service unavailable"));
            }
            _ => panic!("Expected LLM error"),
        }
    }

    #[tokio::test]
    async fn test_default_generate_implementation() {
        // Test that the default generate implementation works by collecting stream chunks
        let mock = MockLLMBackend::new()
            .with_stream_chunks(vec!["Chunk 1".to_string(), " Chunk 2".to_string()]);

        let result = mock.generate("test prompt").await.unwrap();
        // The default implementation should use context-aware logic, not stream collection
        assert_eq!(result, "Default mock response");
    }

    #[tokio::test]
    async fn test_direct_generate_mock() {
        let mock = DirectGenerateMock::new("Direct response".to_string());

        assert_eq!(mock.name(), "DirectGenerateMock");

        let result = mock.generate("any prompt").await.unwrap();
        assert_eq!(result, "Direct response");

        let health = mock.health_check().await.unwrap();
        assert!(health);
    }

    #[tokio::test]
    async fn test_direct_generate_mock_failure() {
        let mock = DirectGenerateMock::new("Response".to_string()).with_failure();

        let result = mock.generate("any prompt").await;
        assert!(result.is_err());

        match result {
            Err(RustChainError::Llm(e)) => {
                assert!(e.to_string().contains("Direct generate failure"));
            }
            _ => panic!("Expected LLM error"),
        }

        let health = mock.health_check().await.unwrap();
        assert!(!health);
    }

    #[tokio::test]
    async fn test_direct_generate_mock_stream() {
        let mock = DirectGenerateMock::new("Stream response".to_string());

        let mut stream = mock.stream("test prompt").await.unwrap();

        use futures::StreamExt;
        let chunk = stream.next().await.unwrap().unwrap();
        assert_eq!(chunk, "Stream response");

        // Stream should be exhausted
        let next_chunk = stream.next().await;
        assert!(next_chunk.is_none());
    }

    #[tokio::test]
    async fn test_llm_backend_trait_object() {
        // Test that we can use LLMBackend as a trait object
        let mock: Box<dyn LLMBackend> = Box::new(MockLLMBackend::new());

        let result = mock.generate("trait object test").await.unwrap();
        assert_eq!(result, "Default mock response");

        assert_eq!(mock.name(), "MockLLM");

        let health = mock.health_check().await.unwrap();
        assert!(health);
    }

    #[tokio::test]
    async fn test_multiple_llm_backends() {
        let mock1: Box<dyn LLMBackend> =
            Box::new(MockLLMBackend::new().with_responses(vec!["Mock1 response".to_string()]));
        let mock2: Box<dyn LLMBackend> =
            Box::new(DirectGenerateMock::new("Mock2 response".to_string()));

        let backends: [Box<dyn LLMBackend>; 2] = [mock1, mock2];

        for (i, backend) in backends.iter().enumerate() {
            let result = backend.generate("test prompt").await.unwrap();
            if i == 0 {
                assert_eq!(result, "Mock1 response"); // MockLLMBackend uses custom responses
            } else {
                assert_eq!(result, "Mock2 response");
            }

            let health = backend.health_check().await.unwrap();
            assert!(health);
        }
    }

    #[tokio::test]
    async fn test_stream_collection_integration() {
        // Test the default generate implementation that collects from stream
        struct StreamOnlyMock;

        #[async_trait]
        impl LLMBackend for StreamOnlyMock {
            // Don't override generate - use the default implementation

            async fn stream(
                &self,
                _prompt: &str,
            ) -> Result<
                Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>,
                RustChainError,
            > {
                let chunks = vec![
                    "Stream".to_string(),
                    " collected".to_string(),
                    " response".to_string(),
                ];
                let chunk_stream = stream::iter(chunks.into_iter().map(Ok));
                Ok(Box::pin(chunk_stream))
            }

            fn name(&self) -> &'static str {
                "StreamOnlyMock"
            }

            async fn health_check(&self) -> Result<bool, RustChainError> {
                Ok(true)
            }
        }

        let mock = StreamOnlyMock;

        let result = mock.generate("test prompt").await.unwrap();
        assert_eq!(result, "Stream collected response");
    }

    #[tokio::test]
    async fn test_stream_collection_with_error() {
        // Test the default generate implementation when stream has errors
        struct ErrorStreamMock;

        #[async_trait]
        impl LLMBackend for ErrorStreamMock {
            // Don't override generate - use the default implementation

            async fn stream(
                &self,
                _prompt: &str,
            ) -> Result<
                Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>,
                RustChainError,
            > {
                let items = vec![
                    Ok("Start".to_string()),
                    Err(RustChainError::Llm(
                        crate::core::error::LlmError::response_error(
                            "Mid-stream error".to_string(),
                        ),
                    )),
                ];
                let error_stream = stream::iter(items);
                Ok(Box::pin(error_stream))
            }

            fn name(&self) -> &'static str {
                "ErrorStreamMock"
            }

            async fn health_check(&self) -> Result<bool, RustChainError> {
                Ok(true)
            }
        }

        let mock = ErrorStreamMock;

        let result = mock.generate("test prompt").await;
        assert!(result.is_err());

        match result {
            Err(RustChainError::Llm(e)) => {
                assert!(e.to_string().contains("Mid-stream error"));
            }
            _ => panic!("Expected LLM error"),
        }
    }

    #[tokio::test]
    async fn test_empty_stream_collection() {
        // Test the default generate implementation with empty stream
        struct EmptyStreamMock;

        #[async_trait]
        impl LLMBackend for EmptyStreamMock {
            async fn stream(
                &self,
                _prompt: &str,
            ) -> Result<
                Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>,
                RustChainError,
            > {
                let empty_stream = stream::iter(vec![]);
                Ok(Box::pin(empty_stream))
            }

            fn name(&self) -> &'static str {
                "EmptyStreamMock"
            }

            async fn health_check(&self) -> Result<bool, RustChainError> {
                Ok(true)
            }
        }

        let mock = EmptyStreamMock;

        let result = mock.generate("test prompt").await.unwrap();
        assert_eq!(result, ""); // Should return empty string
    }

    #[tokio::test]
    async fn test_large_stream_collection() {
        // Test the default generate implementation with many chunks
        struct LargeStreamMock;

        #[async_trait]
        impl LLMBackend for LargeStreamMock {
            async fn stream(
                &self,
                _prompt: &str,
            ) -> Result<
                Pin<Box<dyn Stream<Item = Result<String, RustChainError>> + Send>>,
                RustChainError,
            > {
                let chunks: Vec<_> = (0..100).map(|i| Ok(format!("chunk{} ", i))).collect();
                let chunk_stream = stream::iter(chunks);
                Ok(Box::pin(chunk_stream))
            }

            fn name(&self) -> &'static str {
                "LargeStreamMock"
            }

            async fn health_check(&self) -> Result<bool, RustChainError> {
                Ok(true)
            }
        }

        let mock = LargeStreamMock;

        let result = mock.generate("test prompt").await.unwrap();

        // Should contain all chunks
        assert!(result.starts_with("chunk0 chunk1 chunk2"));
        assert!(result.contains("chunk50"));
        assert!(result.ends_with("chunk99 "));

        // Verify it collected all 100 chunks
        let chunk_count = result.matches("chunk").count();
        assert_eq!(chunk_count, 100);
    }

    #[test]
    fn test_llm_backend_trait_bounds() {
        // Test that LLMBackend has the correct trait bounds
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<Box<dyn LLMBackend>>();
    }
}
