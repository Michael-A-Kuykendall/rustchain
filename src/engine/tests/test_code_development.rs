use crate::core::RuntimeContext;
use crate::engine::{DagExecutor, MissionStep, StepType, StepStatus};
use serde_json::json;
use std::collections::HashMap;
use tempfile::TempDir;
use tokio;

#[tokio::test]
async fn test_compile_code_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test Rust compilation
    let compile_step = MissionStep {
        id: "test_compile_rust".to_string(),
        name: Some("Test Rust Compilation".to_string()),
        step_type: StepType::CompileCode,
        parameters: json!({
            "language": "rust",
            "path": "."
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&compile_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("language").is_some());
    assert!(step_result.output.get("path").is_some());
}

#[tokio::test]
async fn test_run_tests_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test running Rust tests
    let test_step = MissionStep {
        id: "test_run_tests".to_string(),
        name: Some("Test Run Tests".to_string()),
        step_type: StepType::RunTests,
        parameters: json!({
            "language": "rust",
            "path": "."
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&test_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("language").is_some());
}

#[tokio::test]
async fn test_format_code_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let format_step = MissionStep {
        id: "test_format_code".to_string(),
        name: Some("Test Format Code".to_string()),
        step_type: StepType::FormatCode,
        parameters: json!({
            "language": "rust",
            "path": "src/engine/mod.rs"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&format_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(step_result.output.get("language").is_some());
    assert!(step_result.output.get("formatted").is_some());
}

#[tokio::test]
async fn test_lint_code_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let lint_step = MissionStep {
        id: "test_lint_code".to_string(),
        name: Some("Test Lint Code".to_string()),
        step_type: StepType::LintCode,
        parameters: json!({
            "language": "rust",
            "path": "."
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&lint_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(step_result.output.get("language").is_some());
    assert!(step_result.output.get("issues").is_some());
}

#[tokio::test]
async fn test_build_project_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let build_step = MissionStep {
        id: "test_build_project".to_string(),
        name: Some("Test Build Project".to_string()),
        step_type: StepType::BuildProject,
        parameters: json!({
            "language": "rust",
            "path": ".",
            "target": "debug"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&build_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(step_result.output.get("language").is_some());
    assert!(step_result.output.get("target").is_some());
}

#[tokio::test]
async fn test_generate_code_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let generate_step = MissionStep {
        id: "test_generate_code".to_string(),
        name: Some("Test Generate Code".to_string()),
        step_type: StepType::GenerateCode,
        parameters: json!({
            "language": "rust",
            "template": "struct",
            "name": "TestStruct"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&generate_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(step_result.output.get("language").is_some());
    assert!(step_result.output.get("generated").is_some());
}

#[tokio::test]
async fn test_code_development_error_handling() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test with invalid language
    let invalid_compile_step = MissionStep {
        id: "test_invalid_compile".to_string(),
        name: Some("Test Invalid Compile".to_string()),
        step_type: StepType::CompileCode,
        parameters: json!({
            "language": "invalid_language",
            "path": "."
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&invalid_compile_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // Should handle gracefully
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
}

// Build System Integration Tests
#[tokio::test]
async fn test_cargo_build_with_features() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let cargo_build_step = MissionStep {
        id: "test_cargo_features".to_string(),
        name: Some("Test Cargo Build with Features".to_string()),
        step_type: StepType::BuildProject,
        parameters: json!({
            "language": "rust",
            "path": ".",
            "features": ["llm", "tools"],
            "target": "debug"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&cargo_build_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(step_result.output.get("language").unwrap().as_str().unwrap() == "rust");
    assert!(step_result.output.get("features").is_some());
}

#[tokio::test]
async fn test_make_build_integration() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let make_build_step = MissionStep {
        id: "test_make_build".to_string(),
        name: Some("Test Make Build".to_string()),
        step_type: StepType::BuildProject,
        parameters: json!({
            "language": "c",
            "path": ".",
            "build_system": "make",
            "target": "all"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&make_build_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(step_result.output.get("build_system").is_some());
}

#[tokio::test]
async fn test_npm_build_integration() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let npm_build_step = MissionStep {
        id: "test_npm_build".to_string(),
        name: Some("Test npm Build".to_string()),
        step_type: StepType::BuildProject,
        parameters: json!({
            "language": "javascript",
            "path": ".",
            "build_system": "npm",
            "script": "build"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&npm_build_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert!(step_result.output.get("build_system").is_some());
}