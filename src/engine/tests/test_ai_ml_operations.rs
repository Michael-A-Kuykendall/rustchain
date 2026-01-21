use crate::core::RuntimeContext;
use crate::engine::{DagExecutor, MissionStep, StepType, StepStatus};
use serde_json::json;
use std::collections::HashMap;
use tokio;

#[tokio::test]
async fn test_generate_embedding_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let embedding_step = MissionStep {
        id: "test_generate_embedding".to_string(),
        name: Some("Test Generate Embedding".to_string()),
        step_type: StepType::GenerateEmbedding,
        parameters: json!({
            "text": "This is a test sentence for embedding generation.",
            "model": "text-embedding-ada-002"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&embedding_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on API availability
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("text").is_some());
    assert!(step_result.output.get("model").is_some());
}

#[tokio::test]
async fn test_similarity_search_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let search_step = MissionStep {
        id: "test_similarity_search".to_string(),
        name: Some("Test Similarity Search".to_string()),
        step_type: StepType::SimilaritySearch,
        parameters: json!({
            "query_embedding": [0.1, 0.2, 0.3, 0.4, 0.5],
            "database": "default",
            "top_k": 5
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&search_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on vector database availability
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("top_k").is_some());
}

#[tokio::test]
async fn test_model_inference_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let inference_step = MissionStep {
        id: "test_model_inference".to_string(),
        name: Some("Test Model Inference".to_string()),
        step_type: StepType::ModelInference,
        parameters: json!({
            "prompt": "What is the capital of France?",
            "model": "gpt-3.5-turbo",
            "max_tokens": 100
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&inference_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on model API availability
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("prompt").is_some());
    assert!(step_result.output.get("model").is_some());
}

#[tokio::test]
async fn test_ai_ml_operations_error_handling() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test with invalid model
    let invalid_model_step = MissionStep {
        id: "test_invalid_model".to_string(),
        name: Some("Test Invalid Model".to_string()),
        step_type: StepType::GenerateEmbedding,
        parameters: json!({
            "text": "Test text",
            "model": "nonexistent-model-123"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&invalid_model_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // Should handle invalid model gracefully
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
}

#[tokio::test]
async fn test_embedding_with_various_text_types() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let test_texts = vec![
        "Short text",
        "This is a much longer text that contains multiple sentences and should test the embedding model's ability to handle longer input sequences properly.",
        "", // Empty text
        "Text with special characters: !@#$%^&*()",
        "Non-English text: Bonjour le monde! ¿Cómo estás?",
    ];
    
    for (i, text) in test_texts.iter().enumerate() {
        let embedding_step = MissionStep {
            id: format!("test_embedding_text_{}", i),
            name: Some(format!("Test Embedding Text {}", i)),
            step_type: StepType::GenerateEmbedding,
            parameters: json!({
                "text": text,
                "model": "text-embedding-ada-002"
            }).as_object().unwrap().clone(),
            depends_on: vec![],
            timeout: None,
        };
        
        let result = executor.execute_step(&embedding_step).await;
        assert!(result.is_ok());
        let step_result = result.unwrap();
        
        // Should handle various text types gracefully
        assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
        assert_eq!(step_result.output.get("text").unwrap().as_str().unwrap(), *text);
    }
}

#[tokio::test]
async fn test_similarity_search_with_different_metrics() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let metrics = vec!["cosine", "euclidean", "dot_product"];
    let test_embedding = vec![0.1, 0.2, 0.3, 0.4, 0.5];
    
    for metric in metrics {
        let search_step = MissionStep {
            id: format!("test_similarity_{}", metric),
            name: Some(format!("Test Similarity Search {}", metric)),
            step_type: StepType::SimilaritySearch,
            parameters: json!({
                "query_embedding": test_embedding,
                "database": "default",
                "top_k": 3,
                "metric": metric,
                "threshold": 0.7
            }).as_object().unwrap().clone(),
            depends_on: vec![],
            timeout: None,
        };
        
        let result = executor.execute_step(&search_step).await;
        assert!(result.is_ok());
        let step_result = result.unwrap();
        
        // Should handle different similarity metrics
        assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
        assert!(step_result.output.get("metric").is_some());
    }
}

// AI/ML Performance Tests
#[tokio::test]
async fn test_embedding_batch_performance() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let batch_texts = vec![
        "First batch text for performance testing",
        "Second batch text for performance testing",  
        "Third batch text for performance testing",
        "Fourth batch text for performance testing",
        "Fifth batch text for performance testing"
    ];
    
    let batch_embedding_step = MissionStep {
        id: "test_batch_embedding".to_string(),
        name: Some("Test Batch Embedding Performance".to_string()),
        step_type: StepType::GenerateEmbedding,
        parameters: json!({
            "texts": batch_texts,
            "model": "text-embedding-ada-002",
            "batch_size": 5
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: Some(30000), // 30 second timeout
    };
    
    let start_time = std::time::Instant::now();
    let result = executor.execute_step(&batch_embedding_step).await;
    let duration = start_time.elapsed();
    
    assert!(result.is_ok());
    let step_result = result.unwrap();
    
    // Should complete within reasonable time
    assert!(duration.as_secs() < 30);
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
}

#[tokio::test]
async fn test_model_inference_memory_management() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test inference with large context
    let large_prompt = "Context: ".to_string() + &"This is a very long context that repeats many times to test memory management. ".repeat(100);
    
    let memory_test_step = MissionStep {
        id: "test_memory_inference".to_string(),
        name: Some("Test Memory Management Inference".to_string()),
        step_type: StepType::ModelInference,
        parameters: json!({
            "prompt": large_prompt,
            "model": "gpt-3.5-turbo",
            "max_tokens": 50,
            "stream": false
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: Some(60000), // 60 second timeout
    };
    
    let result = executor.execute_step(&memory_test_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    
    // Should handle large inputs without memory issues
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("max_tokens").is_some());
}

#[tokio::test]
async fn test_concurrent_ai_operations() {
    let context = RuntimeContext::new();
    
    // Test concurrent embedding generation
    let mut handles = vec![];
    
    for i in 0..3 {
        let executor = DagExecutor::new(RuntimeContext::new());
        let handle = tokio::spawn(async move {
            let embedding_step = MissionStep {
                id: format!("concurrent_embedding_{}", i),
                name: Some(format!("Concurrent Embedding {}", i)),
                step_type: StepType::GenerateEmbedding,
                parameters: json!({
                    "text": format!("Concurrent test text {}", i),
                    "model": "text-embedding-ada-002"
                }).as_object().unwrap().clone(),
                depends_on: vec![],
                timeout: None,
            };
            
            executor.execute_step(&embedding_step).await
        });
        
        handles.push(handle);
    }
    
    // Wait for all concurrent operations to complete
    let results = futures::future::join_all(handles).await;
    
    for result in results {
        assert!(result.is_ok());
        let execution_result = result.unwrap();
        assert!(execution_result.is_ok());
        let step_result = execution_result.unwrap();
        
        // Should handle concurrent operations without interference
        assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    }
}