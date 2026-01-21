/// Basic validation of core step types in RustChain
/// Tests the fundamental step types to understand implementation status
use rustchain::engine::{DagExecutor, ExecutionContext, MissionStep, StepType};
use serde_json::json;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_noop_step_type() {
    println!("🔧 Testing Noop step type...");

    let step = MissionStep {
        id: "noop_test".to_string(),
        name: "Test Noop".to_string(),
        step_type: StepType::Noop,
        depends_on: Some(vec![]),
        timeout_seconds: Some(30),
        continue_on_error: Some(false),
        parameters: json!({}),
    };

    let mut context = ExecutionContext::new();

    let result = DagExecutor::execute_step(&step, &mut context).await;

    match result {
        Ok(_) => println!("  ✅ Noop step executed successfully"),
        Err(e) => println!("  ❌ Noop step failed: {}", e),
    }
}

#[tokio::test]
async fn test_create_file_step_type() {
    println!("🔧 Testing CreateFile step type...");

    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let test_file = temp_dir.path().join("test.txt");

    let step = MissionStep {
        id: "create_file_test".to_string(),
        name: "Test Create File".to_string(),
        step_type: StepType::CreateFile,
        depends_on: Some(vec![]),
        timeout_seconds: Some(30),
        continue_on_error: Some(false),
        parameters: json!({
            "path": test_file.to_string_lossy(),
            "content": "Hello RustChain!"
        }),
    };

    let mut context = ExecutionContext::new();

    let result = DagExecutor::execute_step(&step, &mut context).await;

    match result {
        Ok(_) => {
            if test_file.exists() {
                let content = fs::read_to_string(&test_file).expect("Failed to read test file");
                assert_eq!(content, "Hello RustChain!");
                println!("  ✅ CreateFile step executed successfully");
            } else {
                println!("  ⚠️  CreateFile step completed but file not found");
            }
        }
        Err(e) => println!("  ⚠️  CreateFile step failed: {}", e),
    }
}

#[tokio::test]
async fn test_command_step_type() {
    println!("🔧 Testing Command step type...");

    let step = MissionStep {
        id: "command_test".to_string(),
        name: "Test Command".to_string(),
        step_type: StepType::Command,
        depends_on: Some(vec![]),
        timeout_seconds: Some(30),
        continue_on_error: Some(false),
        parameters: json!({
            "command": "echo",
            "args": ["Hello World"]
        }),
    };

    let mut context = ExecutionContext::new();

    let result = DagExecutor::execute_step(&step, &mut context).await;

    match result {
        Ok(_) => println!("  ✅ Command step executed successfully"),
        Err(e) => println!("  ⚠️  Command step failed: {}", e),
    }
}

#[tokio::test]
async fn test_http_step_type() {
    println!("🔧 Testing Http step type...");

    let step = MissionStep {
        id: "http_test".to_string(),
        name: "Test HTTP".to_string(),
        step_type: StepType::Http,
        depends_on: Some(vec![]),
        timeout_seconds: Some(30),
        continue_on_error: Some(true), // Allow failure for external dependencies
        parameters: json!({
            "url": "https://httpbin.org/get",
            "method": "GET"
        }),
    };

    let mut context = ExecutionContext::new();

    let result = DagExecutor::execute_step(&step, &mut context).await;

    match result {
        Ok(_) => println!("  ✅ HTTP step executed successfully"),
        Err(e) => println!("  ⚠️  HTTP step failed (may be feature-gated): {}", e),
    }
}

#[tokio::test]
async fn test_feature_gated_step_types() {
    println!("🔧 Testing potentially feature-gated step types...");

    let feature_gated_types = vec![
        (StepType::SqlQuery, "SQL Query"),
        (StepType::RedisGet, "Redis Get"),
        (StepType::FtpUpload, "FTP Upload"),
        (StepType::SshExecute, "SSH Execute"),
        (StepType::GenerateEmbedding, "Generate Embedding"),
    ];

    let mut context = ExecutionContext::new();

    for (step_type, type_name) in feature_gated_types {
        let step = MissionStep {
            id: format!("{}_test", type_name.replace(" ", "_").to_lowercase()),
            name: format!("Test {}", type_name),
            step_type: step_type.clone(),
            depends_on: Some(vec![]),
            timeout_seconds: Some(30),
            continue_on_error: Some(true),
            parameters: json!({}),
        };

        let result = DagExecutor::execute_step(&step, &mut context).await;

        match result {
            Ok(_) => println!("  ✅ {} step executed successfully", type_name),
            Err(e) => {
                if e.to_string().contains("feature") || e.to_string().contains("not implemented") {
                    println!(
                        "  🚧 {} step is feature-gated or not implemented",
                        type_name
                    );
                } else {
                    println!("  ⚠️  {} step failed: {}", type_name, e);
                }
            }
        }
    }
}

#[tokio::test]
async fn test_step_type_inventory() {
    println!("📊 Step Type Implementation Inventory");
    println!("=====================================");

    // Test all step types to understand current implementation status
    let all_step_types = vec![
        // Core Operations
        (StepType::Noop, "Noop"),
        (StepType::Command, "Command"),
        (StepType::Http, "HTTP"),
        // File Operations
        (StepType::CreateFile, "Create File"),
        (StepType::ReadFile, "Read File"),
        (StepType::EditFile, "Edit File"),
        (StepType::DeleteFile, "Delete File"),
        (StepType::CopyFile, "Copy File"),
        // Data Processing
        (StepType::ParseJson, "Parse JSON"),
        (StepType::ParseYaml, "Parse YAML"),
        // System Operations
        (StepType::ProcessStart, "Process Start"),
        // Database Operations
        (StepType::SqlQuery, "SQL Query"),
        (StepType::RedisGet, "Redis Get"),
        // Network Operations
        (StepType::FtpUpload, "FTP Upload"),
        (StepType::SshExecute, "SSH Execute"),
        // AI/ML Operations
        (StepType::GenerateEmbedding, "Generate Embedding"),
    ];

    let mut context = ExecutionContext::new();

    let mut implemented_count = 0;
    let mut feature_gated_count = 0;
    let mut failed_count = 0;

    for (step_type, type_name) in all_step_types {
        let step = MissionStep {
            id: format!("{}_inventory", type_name.replace(" ", "_").to_lowercase()),
            name: format!("Inventory {}", type_name),
            step_type: step_type.clone(),
            depends_on: Some(vec![]),
            timeout_seconds: Some(30),
            continue_on_error: Some(true),
            parameters: json!({}),
        };

        let result = DagExecutor::execute_step(&step, &mut context).await;

        match result {
            Ok(_) => {
                implemented_count += 1;
                println!("  ✅ {} - IMPLEMENTED", type_name);
            }
            Err(e) => {
                let error_msg = e.to_string().to_lowercase();
                if error_msg.contains("feature")
                    || error_msg.contains("not implemented")
                    || error_msg.contains("unsupported")
                {
                    feature_gated_count += 1;
                    println!("  🚧 {} - FEATURE GATED/NOT IMPLEMENTED", type_name);
                } else {
                    failed_count += 1;
                    println!("  ❌ {} - FAILED: {}", type_name, e);
                }
            }
        }
    }

    println!("\n📈 IMPLEMENTATION SUMMARY");
    println!("=========================");
    println!("✅ Fully Implemented: {} step types", implemented_count);
    println!(
        "🚧 Feature Gated/Not Implemented: {} step types",
        feature_gated_count
    );
    println!("❌ Failed: {} step types", failed_count);
    println!(
        "📊 Total Tested: {} step types",
        implemented_count + feature_gated_count + failed_count
    );
}
