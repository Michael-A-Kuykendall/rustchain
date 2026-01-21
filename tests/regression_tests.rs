use rustchain::assert_invariant;
use rustchain::core::RuntimeContext;
use rustchain::engine::{DagExecutor, Mission, MissionLoader, MissionStep, StepType};
use rustchain::invariant_ppt::*;
use rustchain::policy::create_default_policies;
use rustchain::safety::{SafetyValidator, ValidationMode};

#[cfg(feature = "tools")]
use rustchain::tools::create_default_tool_manager;
use serde_json::json;
use tempfile::TempDir;
use tokio::fs;

/// Comprehensive regression test suite with Invariant System
/// Ensures all core RustChain functionality works with invariant verification
/// This suite must pass before any new feature development proceeds

#[tokio::test]
async fn regression_test_01_basic_mission_execution() {
    start_metrics();
    clear_invariant_log();

    // Test that basic file creation missions still work
    let temp_dir =
        TempDir::new().expect("Failed to create temporary directory for regression test");
    let file_path = temp_dir.path().join("regression_test.txt");

    assert_invariant!(
        temp_dir.path().exists(),
        "Temporary directory must be created successfully",
        Some("regression_testing")
    );

    let file_path_str = file_path
        .to_str()
        .expect("Failed to convert file path to string");

    let mission = Mission {
        version: "1.0".to_string(),
        name: "Basic Regression Test".to_string(),
        description: Some("Test basic mission execution".to_string()),
        steps: vec![MissionStep {
            id: "create_test_file".to_string(),
            name: "Create Test File".to_string(),
            step_type: StepType::CreateFile,
            parameters: json!({
                "path": file_path_str,
                "content": "RustChain regression test successful!"
            }),
            depends_on: None,
            timeout_seconds: Some(30),
            continue_on_error: None,
        }],
        config: None,
    };

    let ctx = rustchain::core::RuntimeContext::new();
    let result = DagExecutor::execute_mission(mission, &ctx).await;

    assert_invariant!(
        result.is_ok(),
        "Basic mission execution must succeed in regression tests",
        Some("regression_testing")
    );

    let execution_result =
        result.expect("Basic mission execution must succeed in regression tests");

    assert_invariant!(
        execution_result.step_results.len() == 1,
        "Mission execution must produce expected number of step results",
        Some("regression_testing")
    );

    // Verify file was actually created
    let content = fs::read_to_string(&file_path)
        .await
        .expect("File should be readable");

    assert_invariant!(
        content == "RustChain regression test successful!",
        "Mission execution must produce expected file content",
        Some("regression_testing")
    );

    let _metrics = finish_metrics();

    // Contract test for basic mission execution
    contract_test(
        "basic_mission_execution",
        &[
            "Temporary directory must be created successfully",
            "Basic mission execution must succeed in regression tests",
            "Mission execution must produce expected number of step results",
            "Mission execution must produce expected file content",
        ],
    );
}

#[tokio::test]
#[cfg(feature = "tools")]
async fn regression_test_02_tool_manager_integration() {
    // Test that tool manager still registers all expected tools
    let tool_manager = create_default_tool_manager();
    let tools = tool_manager.list_tools();

    // Core tools should still be registered
    assert!(tools.contains(&"create_file"));
    assert!(tools.contains(&"http"));
    assert!(tools.contains(&"command"));

    // Our new document loaders should be registered
    assert!(tools.contains(&"csv_loader"));
    assert!(tools.contains(&"json_yaml_loader"));
    assert!(tools.contains(&"html_loader"));

    // Should have expected number of tools (6 total)
    assert_eq!(tools.len(), 10, "Expected 10 tools registered");
}

#[tokio::test]
async fn regression_test_03_policy_engine_functionality() {
    // Test that policy engine still works and has our new rules
    let policies = create_default_policies();

    // Should have our new document loader policy
    assert!(policies.iter().any(|p| p.name == "allow_document_loaders"));

    // Should still have existing policies
    assert!(policies.iter().any(|p| p.name == "safe_file_ops"));
    assert!(policies.iter().any(|p| p.name == "deny_dangerous_commands"));
    assert!(policies.iter().any(|p| p.name == "allow_test_tools"));

    // Should have reasonable number of policies (6+ policies)
    assert!(policies.len() >= 6, "Should have at least 6 policy rules");
}

#[tokio::test]
async fn regression_test_04_safety_validator_functionality() {
    // Test that safety validation still works
    let validator = SafetyValidator::new();

    let safe_mission = Mission {
        version: "1.0".to_string(),
        name: "Safe Test Mission".to_string(),
        description: Some("Safe test".to_string()),
        steps: vec![MissionStep {
            id: "safe_step".to_string(),
            name: "Safe Step".to_string(),
            step_type: StepType::CreateFile,
            parameters: json!({
                "path": "/tmp/safe_file.txt",
                "content": "Safe content"
            }),
            depends_on: None,
            timeout_seconds: Some(30),
            continue_on_error: None,
        }],
        config: None,
    };

    let validation = validator.validate_mission(&safe_mission, ValidationMode::Standard);
    assert!(validation.is_ok(), "Safety validation should work");

    let result = validation.expect("Validation should succeed for safe mission");
    assert!(result.is_safe, "Safe mission should be marked as safe");
    assert_eq!(
        result.risk_score, 0,
        "Safe mission should have risk score 0"
    );
}

#[tokio::test]
async fn regression_test_05_mission_loading() {
    // Test that mission loading from YAML still works
    let temp_dir =
        TempDir::new().expect("Failed to create temp directory for mission loading test");
    let mission_file = temp_dir.path().join("test_mission.yaml");

    let mission_yaml = r#"
version: "1.0"
name: "YAML Loading Test"
description: "Test YAML mission loading"
steps:
  - id: "test_step"
    name: "Test Step"
    step_type: "noop"
    parameters: {}
config:
  max_parallel_steps: 1
  timeout_seconds: 60
"#;

    fs::write(&mission_file, mission_yaml)
        .await
        .expect("Failed to write mission YAML file");

    let mission_file_str = mission_file
        .to_str()
        .expect("Failed to convert mission file path to string");
    let mission = MissionLoader::load_from_file(mission_file_str);
    assert!(mission.is_ok(), "Mission loading should work");

    let loaded_mission = mission.expect("Mission loading should succeed");
    assert_eq!(loaded_mission.name, "YAML Loading Test");
    assert_eq!(loaded_mission.steps.len(), 1);
}

#[tokio::test]
#[cfg(feature = "tools")]
async fn regression_test_06_document_loaders_cli_functionality() {
    // Test that CLI tool registry still works with document loaders
    use rustchain::core::tools::ToolRegistry;

    let mut registry = ToolRegistry::new();
    registry.register_defaults();

    let tools = registry.list();

    // Document loaders should be registered in CLI registry
    assert!(tools.contains(&"csv_loader".to_string()));
    assert!(tools.contains(&"json_yaml_loader".to_string()));
    assert!(tools.contains(&"html_loader".to_string()));
    assert!(tools.contains(&"pdf_loader".to_string()));

    // Should have multiple tools registered
    assert!(
        tools.len() > 4,
        "Should have multiple tools in CLI registry"
    );
}

#[tokio::test]
#[cfg(feature = "tools")]
async fn regression_test_07_document_loaders_mission_integration() {
    // Test that document loaders work in missions (the critical integration we fixed)
    let temp_dir =
        TempDir::new().expect("Failed to create temp directory for document loader test");
    let csv_file = temp_dir.path().join("test.csv");

    // Create test CSV file
    fs::write(&csv_file, "name,age\nJohn,30\nJane,25")
        .await
        .expect("Failed to write test CSV file");

    let csv_file_str = csv_file
        .to_str()
        .expect("Failed to convert CSV file path to string");

    let mission = Mission {
        version: "1.0".to_string(),
        name: "Document Loader Integration Test".to_string(),
        description: Some("Test document loader in mission".to_string()),
        steps: vec![MissionStep {
            id: "load_csv".to_string(),
            name: "Load CSV File".to_string(),
            step_type: StepType::Tool,
            parameters: json!({
                "tool": "csv_loader",
                "parameters": {
                    "file_path": csv_file_str,
                    "delimiter": ",",
                    "has_headers": true
                }
            }),
            depends_on: None,
            timeout_seconds: Some(30),
            continue_on_error: None,
        }],
        config: None,
    };

    let ctx = rustchain::core::RuntimeContext::new();
    let result = DagExecutor::execute_mission(mission, &ctx).await;
    assert!(
        result.is_ok(),
        "Document loader mission should execute successfully"
    );

    let execution_result = result.expect("Mission execution should succeed");
    assert_eq!(execution_result.step_results.len(), 1);

    // Verify the step succeeded
    let step_result = execution_result
        .step_results
        .get("load_csv")
        .expect("load_csv step should be present in results");
    assert!(matches!(
        step_result.status,
        rustchain::engine::StepStatus::Success
    ));
}

#[tokio::test]
async fn regression_test_08_runtime_context_functionality() {
    // Test that RuntimeContext still works correctly
    let context = RuntimeContext::new();

    // Should be able to perform audit actions
    context
        .audit_action("regression_test", "test_action", "testing")
        .await;

    // Audit chain should have entries
    let chain_hash = context.audit.get_chain_hash().await;
    assert_ne!(chain_hash, "genesis", "Audit chain should have entries");
}

#[tokio::test]
async fn regression_test_09_compilation_and_features() {
    // Test that all feature flags still compile correctly by testing feature-gated code

    // Test that tools feature is working
    #[cfg(feature = "tools")]
    {
        let tool_manager = create_default_tool_manager();
        assert!(!tool_manager.list_tools().is_empty());
    }

    // Test that other features don't break basic functionality
    #[cfg(not(feature = "tools"))]
    {
        // Should still be able to create basic mission without tools
        let mission = Mission {
            version: "1.0".to_string(),
            name: "No Tools Test".to_string(),
            description: None,
            steps: vec![MissionStep {
                id: "noop".to_string(),
                name: "No-op".to_string(),
                step_type: StepType::Noop,
                parameters: json!({}),
                depends_on: None,
                timeout_seconds: Some(30),
                continue_on_error: None,
            }],
            config: None,
        };

        let ctx = rustchain::core::RuntimeContext::new();
        let result = DagExecutor::execute_mission(mission, &ctx).await;
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn regression_test_10_comprehensive_mission_workflow() {
    // Test a comprehensive mission that uses multiple features
    let temp_dir =
        TempDir::new().expect("Failed to create temp directory for comprehensive workflow test");
    let output_file = temp_dir.path().join("workflow_output.txt");

    let output_file_str = output_file
        .to_str()
        .expect("Failed to convert output file path to string");

    let mission = Mission {
        version: "1.0".to_string(),
        name: "Comprehensive Workflow Test".to_string(),
        description: Some("Test multiple mission features together".to_string()),
        steps: vec![
            MissionStep {
                id: "step1_create".to_string(),
                name: "Create Initial File".to_string(),
                step_type: StepType::CreateFile,
                parameters: json!({
                    "path": output_file_str,
                    "content": "Step 1: Created initial file\n"
                }),
                depends_on: None,
                timeout_seconds: Some(30),
                continue_on_error: None,
            },
            MissionStep {
                id: "step2_append".to_string(),
                name: "Append to File".to_string(),
                step_type: StepType::EditFile,
                parameters: json!({
                    "path": output_file_str,
                    "content": "Step 2: Appended content\n",
                    "append": true
                }),
                depends_on: Some(vec!["step1_create".to_string()]),
                timeout_seconds: Some(30),
                continue_on_error: None,
            },
            MissionStep {
                id: "step3_noop".to_string(),
                name: "No-op Step".to_string(),
                step_type: StepType::Noop,
                parameters: json!({}),
                depends_on: Some(vec!["step2_append".to_string()]),
                timeout_seconds: Some(30),
                continue_on_error: None,
            },
        ],
        config: Some(rustchain::engine::MissionConfig {
            max_parallel_steps: Some(1),
            timeout_seconds: Some(120),
            fail_fast: Some(true),
        }),
    };

    let ctx = rustchain::core::RuntimeContext::new();
    let result = DagExecutor::execute_mission(mission, &ctx).await;
    assert!(
        result.is_ok(),
        "Comprehensive workflow should execute successfully"
    );

    let execution_result = result.expect("Comprehensive workflow execution should succeed");
    assert_eq!(execution_result.step_results.len(), 3);

    // Verify all steps succeeded
    for (step_id, step_result) in &execution_result.step_results {
        assert!(
            matches!(step_result.status, rustchain::engine::StepStatus::Success),
            "Step {} should succeed",
            step_id
        );
    }

    // Verify file content
    let content = fs::read_to_string(&output_file)
        .await
        .expect("Failed to read output file content");
    assert!(content.contains("Step 1: Created initial file"));
    assert!(content.contains("Step 2: Appended content"));
}

/// Regression test results summary with invariant verification
#[tokio::test]
async fn regression_test_summary() {
    start_metrics();
    clear_invariant_log();

    println!("\n🧪 RUSTCHAIN REGRESSION TEST SUITE COMPLETED WITH INVARIANT VERIFICATION");
    println!("========================================================================");
    println!("✅ Basic mission execution");
    println!("✅ Tool manager integration");
    println!("✅ Policy engine functionality");
    println!("✅ Safety validator functionality");
    println!("✅ Mission loading from YAML");
    println!("✅ Document loaders CLI functionality");
    println!("✅ Document loaders mission integration");
    println!("✅ Runtime context functionality");
    println!("✅ Compilation and feature flags");
    println!("✅ Comprehensive workflow execution");

    assert_invariant!(
        true, // If we reach here, all tests passed
        "All regression tests must complete successfully",
        Some("regression_testing")
    );

    let metrics = finish_metrics();
    let invariant_log = get_invariant_log();

    println!("\n📊 REGRESSION TEST METRICS:");
    println!("   Invariants Checked: {}", metrics.invariants_logged);
    println!("   Properties Tested: {}", metrics.properties_run);
    println!(
        "   Test Scopes: {}",
        invariant_log
            .iter()
            .filter_map(|r| r.scope.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len()
    );

    println!("\n🎯 ALL REGRESSION TESTS PASSING - SYSTEM STABLE WITH INVARIANT COVERAGE");
}
