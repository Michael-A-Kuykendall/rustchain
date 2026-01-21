use crate::core::RuntimeContext;
use crate::engine::{DagExecutor, MissionStep, StepType, StepStatus};
use serde_json::json;
use std::collections::HashMap;
use tempfile::TempDir;
use tokio;

#[tokio::test]
async fn test_file_operations_step_types() {
    // Create temporary directory for testing
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path().to_str().expect("Failed to convert temp path to string");
    
    // Test CopyFile step type
    let copy_step = MissionStep {
        id: "test_copy".to_string(),
        name: Some("Test Copy File".to_string()),
        step_type: StepType::CopyFile,
        parameters: json!({
            "source": "Cargo.toml",
            "destination": format!("{}/Cargo.toml.copy", temp_path)
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    let result = executor.execute_step(&copy_step).await;
    
    assert!(result.is_ok());
    let step_result = result.expect("CopyFile step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("source").is_some());
    assert!(step_result.output.get("destination").is_some());
}

#[tokio::test]
async fn test_data_processing_step_types() {
    // Test ParseJson step type
    let parse_json_step = MissionStep {
        id: "test_parse_json".to_string(),
        name: Some("Test Parse JSON".to_string()),
        step_type: StepType::ParseJson,
        parameters: json!({
            "content": r#"{"test": "value", "number": 42, "nested": {"key": "value"}}"#
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    let result = executor.execute_step(&parse_json_step).await;
    
    assert!(result.is_ok());
    let step_result = result.expect("ParseJson step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("parsed").is_some());
    assert_eq!(step_result.output.get("valid").expect("valid field should be present"), &json!(true));
    
    // Test ParseYaml step type
    let parse_yaml_step = MissionStep {
        id: "test_parse_yaml".to_string(),
        name: Some("Test Parse YAML".to_string()),
        step_type: StepType::ParseYaml,
        parameters: json!({
            "content": "test: value\nnumber: 42\nnested:\n  key: value"
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&parse_yaml_step).await;
    assert!(result.is_ok());
    let step_result = result.expect("ParseYaml step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("parsed").is_some());
    
    // Test CsvProcess step type
    let csv_step = MissionStep {
        id: "test_csv".to_string(),
        name: Some("Test CSV Processing".to_string()),
        step_type: StepType::CsvProcess,
        parameters: json!({
            "content": "name,age,city\nJohn,30,New York\nJane,25,San Francisco"
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&csv_step).await;
    assert!(result.is_ok());
    let step_result = result.expect("CsvProcess step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("headers").is_some());
    assert!(step_result.output.get("records").is_some());
    assert_eq!(step_result.output.get("row_count").expect("row_count field should be present"), &json!(2));
}

#[tokio::test]
async fn test_system_operations_step_types() {
    // Test MonitorResources step type
    let monitor_step = MissionStep {
        id: "test_monitor".to_string(),
        name: Some("Test Resource Monitoring".to_string()),
        step_type: StepType::MonitorResources,
        parameters: json!({}).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    let result = executor.execute_step(&monitor_step).await;
    
    assert!(result.is_ok());
    let step_result = result.expect("MonitorResources step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("cpu_usage_percent").is_some());
    assert!(step_result.output.get("memory").is_some());
}

#[tokio::test]
async fn test_git_operations_step_types() {
    // Test GitStatus step type
    let git_status_step = MissionStep {
        id: "test_git_status".to_string(),
        name: Some("Test Git Status".to_string()),
        step_type: StepType::GitStatus,
        parameters: json!({
            "path": "."
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    let result = executor.execute_step(&git_status_step).await;
    
    assert!(result.is_ok());
    let step_result = result.expect("GitStatus step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("status").is_some());
    assert!(step_result.output.get("clean").is_some());
}

#[tokio::test]
async fn test_compression_operations() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let temp_path = temp_dir.path().to_str().expect("Failed to convert temp path to string");
    
    // Create test files
    std::fs::write(format!("{}/test1.txt", temp_path), "Test content 1").expect("Failed to write test file 1");
    std::fs::write(format!("{}/test2.txt", temp_path), "Test content 2").expect("Failed to write test file 2");
    
    // Test Compress step type with tar format
    let compress_step = MissionStep {
        id: "test_compress".to_string(),
        name: Some("Test Compression".to_string()),
        step_type: StepType::Compress,
        parameters: json!({
            "source": temp_path,
            "destination": format!("{}/test.tar", temp_path),
            "format": "tar"
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    let result = executor.execute_step(&compress_step).await;
    
    assert!(result.is_ok());
    let step_result = result.expect("Compress step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("compressed").is_some());
    assert_eq!(step_result.output.get("format").expect("format field should be present"), &json!("tar"));
}

#[tokio::test]
async fn test_error_handling_for_new_step_types() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test CopyFile with invalid source
    let invalid_copy_step = MissionStep {
        id: "test_invalid_copy".to_string(),
        name: Some("Test Invalid Copy".to_string()),
        step_type: StepType::CopyFile,
        parameters: json!({
            "source": "/nonexistent/file.txt",
            "destination": "/tmp/test.txt"
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&invalid_copy_step).await;
    assert!(result.is_ok());
    let step_result = result.expect("Invalid copy step should still execute (and fail gracefully)");
    // Should fail gracefully
    assert_eq!(step_result.status, StepStatus::Failed);
    
    // Test ParseJson with invalid JSON
    let invalid_json_step = MissionStep {
        id: "test_invalid_json".to_string(),
        name: Some("Test Invalid JSON".to_string()),
        step_type: StepType::ParseJson,
        parameters: json!({
            "content": r#"{"invalid": json syntax"#
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&invalid_json_step).await;
    assert!(result.is_ok());
    let step_result = result.expect("Invalid JSON step should still execute (and fail gracefully)");
    assert_eq!(step_result.status, StepStatus::Failed);
}

#[tokio::test] 
async fn test_xml_parsing_step_type() {
    let parse_xml_step = MissionStep {
        id: "test_parse_xml".to_string(),
        name: Some("Test Parse XML".to_string()),
        step_type: StepType::ParseXml,
        parameters: json!({
            "content": r#"<root><item>value1</item><item>value2</item><nested><child>nested_value</child></nested></root>"#
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    let result = executor.execute_step(&parse_xml_step).await;
    
    assert!(result.is_ok());
    let step_result = result.expect("ParseXml step execution should succeed");
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("elements").is_some());
    assert!(step_result.output.get("element_count").is_some());
    assert_eq!(step_result.output.get("valid").expect("valid field should be present"), &json!(true));
}

#[tokio::test]
async fn test_ping_host_step_type() {
    let ping_step = MissionStep {
        id: "test_ping".to_string(),
        name: Some("Test Ping Host".to_string()),
        step_type: StepType::PingHost,
        parameters: json!({
            "host": "127.0.0.1",
            "count": 1
        }).as_object().expect("Failed to create parameters object").clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    let result = executor.execute_step(&ping_step).await;
    
    assert!(result.is_ok());
    let step_result = result.expect("PingHost step execution should succeed");
    // May fail on Windows due to different ping syntax, but should handle gracefully
    assert!(step_result.output.get("host").is_some());
    assert!(step_result.output.get("count").is_some());
}