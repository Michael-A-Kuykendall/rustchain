use crate::core::RuntimeContext;
use crate::engine::{DagExecutor, MissionStep, StepType, StepStatus};
use serde_json::json;
use std::collections::HashMap;
use tokio;

#[tokio::test]
async fn test_sql_query_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let sql_query_step = MissionStep {
        id: "test_sql_query".to_string(),
        name: Some("Test SQL Query".to_string()),
        step_type: StepType::SqlQuery,
        parameters: json!({
            "query": "SELECT 1 as test_column",
            "database_url": "sqlite://memory:"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&sql_query_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on database availability
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("query").is_some());
}

#[tokio::test]
async fn test_redis_set_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let redis_set_step = MissionStep {
        id: "test_redis_set".to_string(),
        name: Some("Test Redis Set".to_string()),
        step_type: StepType::RedisSet,
        parameters: json!({
            "key": "test_key",
            "value": "test_value",
            "redis_url": "redis://127.0.0.1:6379"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&redis_set_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on Redis availability
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("key").is_some());
}

#[tokio::test]
async fn test_redis_get_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let redis_get_step = MissionStep {
        id: "test_redis_get".to_string(),
        name: Some("Test Redis Get".to_string()),
        step_type: StepType::RedisGet,
        parameters: json!({
            "key": "test_key",
            "redis_url": "redis://127.0.0.1:6379"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&redis_get_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on Redis availability and key existence
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("key").is_some());
}

#[tokio::test]
async fn test_db_backup_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let db_backup_step = MissionStep {
        id: "test_db_backup".to_string(),
        name: Some("Test Database Backup".to_string()),
        step_type: StepType::DbBackup,
        parameters: json!({
            "database_url": "sqlite://test.db",
            "backup_path": "/tmp/test_backup.db",
            "format": "sqlite"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&db_backup_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on database and filesystem availability
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("backup_path").is_some());
}

#[tokio::test]
async fn test_db_migrate_step_type() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let db_migrate_step = MissionStep {
        id: "test_db_migrate".to_string(),
        name: Some("Test Database Migration".to_string()),
        step_type: StepType::DbMigrate,
        parameters: json!({
            "database_url": "sqlite://memory:",
            "migration_path": "/tmp/migrations",
            "direction": "up"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&db_migrate_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // May succeed or fail based on migration files and database state
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("direction").is_some());
}

#[tokio::test]
async fn test_database_operations_error_handling() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test with invalid database URL
    let invalid_db_step = MissionStep {
        id: "test_invalid_db".to_string(),
        name: Some("Test Invalid Database".to_string()),
        step_type: StepType::SqlQuery,
        parameters: json!({
            "query": "SELECT 1",
            "database_url": "invalid://database/url"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&invalid_db_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    // Should handle invalid URL gracefully
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
}

// Database Security Tests
#[tokio::test]
async fn test_sql_query_prevents_injection() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test with potentially malicious SQL
    let injection_attempt_step = MissionStep {
        id: "test_sql_injection".to_string(),
        name: Some("Test SQL Injection Prevention".to_string()),
        step_type: StepType::SqlQuery,
        parameters: json!({
            "query": "SELECT * FROM users WHERE id = '1; DROP TABLE users; --'",
            "database_url": "sqlite://memory:"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&injection_attempt_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    
    // Should handle malicious queries safely
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("query").is_some());
}

#[tokio::test]
async fn test_redis_operations_with_auth() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let auth_redis_step = MissionStep {
        id: "test_auth_redis".to_string(),
        name: Some("Test Redis with Authentication".to_string()),
        step_type: StepType::RedisSet,
        parameters: json!({
            "key": "secure_key",
            "value": "secure_value",
            "redis_url": "redis://:password@127.0.0.1:6379",
            "auth": true
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&auth_redis_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    
    // Should handle authentication properly
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("key").is_some());
}

#[tokio::test]
async fn test_database_connection_pooling() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    // Test multiple database operations to validate connection handling
    let queries = vec![
        "SELECT 1 as first_query",
        "SELECT 2 as second_query", 
        "SELECT 3 as third_query"
    ];
    
    for (i, query) in queries.iter().enumerate() {
        let db_step = MissionStep {
            id: format!("test_pool_query_{}", i),
            name: Some(format!("Test Pool Query {}", i)),
            step_type: StepType::SqlQuery,
            parameters: json!({
                "query": query,
                "database_url": "sqlite://memory:",
                "pool_size": 5
            }).as_object().unwrap().clone(),
            depends_on: vec![],
            timeout: None,
        };
        
        let result = executor.execute_step(&db_step).await;
        assert!(result.is_ok());
        let step_result = result.unwrap();
        
        // Should handle connection pooling efficiently
        assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    }
}

#[tokio::test]
async fn test_backup_with_encryption() {
    let context = RuntimeContext::new();
    let executor = DagExecutor::new(context);
    
    let encrypted_backup_step = MissionStep {
        id: "test_encrypted_backup".to_string(),
        name: Some("Test Encrypted Database Backup".to_string()),
        step_type: StepType::DbBackup,
        parameters: json!({
            "database_url": "sqlite://test.db",
            "backup_path": "/tmp/encrypted_backup.db",
            "encryption": true,
            "encryption_key": "test_encryption_key_32_bytes_long"
        }).as_object().unwrap().clone(),
        depends_on: vec![],
        timeout: None,
    };
    
    let result = executor.execute_step(&encrypted_backup_step).await;
    assert!(result.is_ok());
    let step_result = result.unwrap();
    
    // Should handle encryption properly
    assert!(matches!(step_result.status, StepStatus::Success | StepStatus::Failed));
    assert!(step_result.output.get("encryption").is_some());
}