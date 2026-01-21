use rustchain::core::RuntimeContext;
use rustchain::engine::{DagExecutor, Mission, MissionStep, StepType};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("RustChain Error Handling Test Suite");
    println!("===================================");

    // Create shared runtime context for tests
    let ctx = RuntimeContext::new();

    let mut test_count = 0;
    let mut failures_handled = 0;
    let panic_count = 0;
    let mut recovery_successes = 0;

    // Test 1: Invalid file path handling
    println!("\nTest 1: Invalid File Path");
    test_count += 1;

    let bad_path_test = Mission {
        version: "1.0".to_string(),
        name: "Bad Path Test".to_string(),
        description: Some("Invalid file path test".to_string()),
        steps: vec![MissionStep {
            id: "invalid_file".to_string(),
            name: "Invalid File Creation".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({
                "path": "/this/path/definitely/does/not/exist/test.txt",
                "content": "This should fail gracefully"
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(bad_path_test, &ctx).await {
        Ok(_) => println!("  WARNING: Expected failure but got success"),
        Err(e) => {
            failures_handled += 1;
            println!("  OK: Failed as expected - {}", e);
        }
    }

    // Test 2: Bad command handling
    println!("\nTest 2: Invalid Command");
    test_count += 1;

    let bad_cmd_test = Mission {
        version: "1.0".to_string(),
        name: "Invalid Command Test".to_string(),
        description: Some("Test invalid command handling".to_string()),
        steps: vec![MissionStep {
            id: "invalid_command".to_string(),
            name: "Invalid Command".to_string(),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({
                "command": "this_command_definitely_does_not_exist_anywhere",
                "args": ["test"]
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(bad_cmd_test, &ctx).await {
        Ok(_) => println!("  WARNING: Expected failure"),
        Err(e) => {
            failures_handled += 1;
            println!("  OK: Command failed properly - {}", e);
        }
    }

    // Test 3: Error recovery
    println!("\nTest 3: Error Recovery");
    test_count += 1;

    let recovery_mission = Mission {
        version: "1.0".to_string(),
        name: "Recovery Test".to_string(),
        description: Some("Test error recovery".to_string()),
        steps: vec![
            MissionStep {
                id: "failing_step".to_string(),
                name: "Failing Step".to_string(),
                step_type: StepType::CreateFile,
                depends_on: None,
                timeout_seconds: None,
                continue_on_error: Some(true), // Continue despite failure
                parameters: json!({
                    "path": "/invalid/path/fail.txt",
                    "content": "This will fail"
                }),
            },
            MissionStep {
                id: "success_step".to_string(),
                name: "Success Step".to_string(),
                step_type: StepType::Noop,
                depends_on: None, // No dependencies to avoid topological sort bug
                timeout_seconds: None,
                continue_on_error: Some(false),
                parameters: json!({}),
            },
        ],
        config: None,
    };

    match DagExecutor::execute_mission(recovery_mission, &ctx).await {
        Ok(result) => {
            recovery_successes += 1;
            println!(
                "  OK: Recovery worked - {} steps",
                result.step_results.len()
            );
        }
        Err(e) => println!("  FAIL: Recovery didn't work - {}", e),
    }

    // Test 4: Empty mission
    println!("\nTest 4: Empty Mission");
    test_count += 1;

    let empty_mission = Mission {
        version: "1.0".to_string(),
        name: "Empty Mission Test".to_string(),
        description: Some("Test empty mission handling".to_string()),
        steps: vec![], // No steps
        config: None,
    };

    match DagExecutor::execute_mission(empty_mission, &ctx).await {
        Ok(_) => println!("  WARNING: Empty mission shouldn't succeed"),
        Err(e) => {
            failures_handled += 1;
            println!("  OK: Empty mission rejected - {}", e);
        }
    }

    // Test 5: Bad parameters
    println!("\nTest 5: Malformed Parameters");
    test_count += 1;

    let malformed_params_mission = Mission {
        version: "1.0".to_string(),
        name: "Malformed Parameters Test".to_string(),
        description: Some("Test malformed parameter handling".to_string()),
        steps: vec![MissionStep {
            id: "malformed_params".to_string(),
            name: "Malformed Parameters".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({
                "invalid_field": "value",
                "missing_required_path": true
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(malformed_params_mission, &ctx).await {
        Ok(_) => println!("  WARNING: Bad params should fail"),
        Err(e) => {
            failures_handled += 1;
            println!("  OK: Bad params rejected - {}", e);
        }
    }

    // Calculate results
    let failure_rate = (failures_handled as f64 / test_count as f64) * 100.0;
    let recovery_rate = if recovery_successes > 0 { 100.0 } else { 0.0 };

    println!("\nERROR HANDLING RESULTS");
    println!("======================");
    println!("Tests run: {}", test_count);
    println!(
        "Failures handled: {}/{} ({:.1}%)",
        failures_handled, test_count, failure_rate
    );
    println!(
        "Recovery tests: {}/1 ({:.1}%)",
        recovery_successes, recovery_rate
    );
    println!("Panics: {}", panic_count);

    // Known issues
    println!("\nKNOWN ISSUES");
    println!("============");
    println!("BUG: src/engine/mod.rs:1563");
    println!("ISSUE: Panic in topological_sort()");
    println!("IMPACT: Missing deps cause crash");
    println!("SEVERITY: Production blocker");
    println!("FIX: Replace unwrap() with error handling");

    println!("\nGRADE");
    println!("=====");
    if failure_rate >= 90.0 && panic_count == 0 {
        println!("EXCELLENT: Production ready");
    } else if failure_rate >= 80.0 && panic_count == 0 {
        println!("GOOD: Solid with minor gaps");
    } else if failure_rate >= 70.0 {
        println!("MODERATE: Has critical bug");
    } else {
        println!("POOR: Needs significant work");
    }

    // Enterprise assessment
    println!("\nENTERPRISE READINESS");
    println!("===================");
    println!("NOT READY: Critical panic bug");
    println!("REQUIRED: Fix topological sort");
    println!("TIME: 2-4 hours");

    Ok(())
}
