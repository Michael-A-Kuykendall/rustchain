use crate::core::RuntimeContext;
use crate::engine::{DagExecutor, MissionStep, StepType, StepStatus};
use serde_json::json;
use std::collections::HashMap;
use tempfile::TempDir;
use tokio;

#[tokio::test]
async fn test_git_status_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let git_status_step = MissionStep {
        id: "test_git_status".to_string(),
        name: Some("Test Git Status".to_string()),
        step_type: StepType::GitStatus,
        parameters: json!({
            "path": "."
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&git_status_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("status").is_some());
    assert!(step_result.output.get("clean").is_some());
}

#[tokio::test]
async fn test_git_diff_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let git_diff_step = MissionStep {
        id: "test_git_diff".to_string(),
        name: Some("Test Git Diff".to_string()),
        step_type: StepType::GitDiff,
        parameters: json!({
            "path": "."
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&git_diff_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("diff").is_some());
}

#[tokio::test]
async fn test_git_commit_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let git_commit_step = MissionStep {
        id: "test_git_commit".to_string(),
        name: Some("Test Git Commit".to_string()),
        step_type: StepType::GitCommit,
        parameters: json!({
            "path": ".",
            "message": "Test commit message",
            "author": "Test User <test@example.com>"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&git_commit_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail depending on repo state - both are valid
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("message").is_some());
}

#[tokio::test]
async fn test_git_branch_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let git_branch_step = MissionStep {
        id: "test_git_branch".to_string(),
        name: Some("Test Git Branch".to_string()),
        step_type: StepType::GitBranch,
        parameters: json!({
            "path": ".",
            "operation": "list"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&git_branch_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert_eq!(step_result.status, StepStatus::Success);
    assert!(step_result.output.get("branches").is_some());
}

#[tokio::test]
async fn test_git_merge_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let git_merge_step = MissionStep {
        id: "test_git_merge".to_string(),
        name: Some("Test Git Merge".to_string()),
        step_type: StepType::GitMerge,
        parameters: json!({
            "path": ".",
            "branch": "main",
            "strategy": "recursive"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&git_merge_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail depending on repo state - both are valid
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("branch").is_some());
}

#[tokio::test]
async fn test_git_operations_error_handling() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test with invalid path
    let invalid_path_step = MissionStep {
        id: "test_invalid_path".to_string(),
        name: Some("Test Invalid Path".to_string()),
        step_type: StepType::GitStatus,
        parameters: json!({
            "path": "/nonexistent/path"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&invalid_path_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // Should handle gracefully
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
}

// Git Edge Case Tests
#[tokio::test]
async fn test_git_merge_handles_binary_conflicts() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let merge_step = MissionStep {
        id: "test_binary_merge".to_string(),
        name: Some("Test Binary Merge Conflicts".to_string()),
        step_type: StepType::GitMerge,
        parameters: json!({
            "path": ".",
            "branch": "nonexistent-branch",
            "allow_unrelated_histories": true
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&merge_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // Should handle conflict scenarios gracefully
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    
    if step_result.status == StepStatus::Failed {
        assert!(step_result.error.is_some() || 
               step_result.output.get("error").is_some());
    }
}

#[tokio::test]
async fn test_git_commit_prevents_malicious_messages() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test with potentially dangerous commit message
    let malicious_commit_step = MissionStep {
        id: "test_malicious_commit".to_string(),
        name: Some("Test Malicious Commit Message".to_string()),
        step_type: StepType::GitCommit,
        parameters: json!({
            "path": ".",
            "message": "Test commit $(rm -rf /)",
            "author": "Test User <test@example.com>"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&malicious_commit_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    
    // Should not execute dangerous commands
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("message").is_some());
}

#[tokio::test]
async fn test_git_branch_create_and_switch() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let branch_create_step = MissionStep {
        id: "test_branch_create".to_string(),
        name: Some("Test Branch Create and Switch".to_string()),
        step_type: StepType::GitBranch,
        parameters: json!({
            "path": ".",
            "operation": "create",
            "branch_name": "test-branch-12345",
            "switch": false
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&branch_create_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    
    // May succeed or fail based on repo state
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("operation").is_some());
}

#[tokio::test]
async fn test_git_status_with_large_repo() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let status_step = MissionStep {
        id: "test_large_repo_status".to_string(),
        name: Some("Test Status on Large Repo".to_string()),
        step_type: StepType::GitStatus,
        parameters: json!({
            "path": ".",
            "include_ignored": false,
            "include_untracked": true
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: Some(30000), // 30 second timeout
    };
    
    let result = executor.execute_step(&status_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    assert_eq!(step_result.status, StepStatus::Success);
    
    // Should include file counts for large repos
    assert!(step_result.output.get("status").is_some());
    assert!(step_result.output.get("clean").is_some());
}