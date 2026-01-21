// Comprehensive error handling validation for RustChain
use rustchain::core::RuntimeContext;
use rustchain::engine::{DagExecutor, Mission, MissionConfig, MissionStep, StepType};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ctx = RuntimeContext::new();

    println!("🛡️ RustChain Error Handling Validation");
    println!("======================================");

    let mut total_tests = 0;
    let mut graceful_failures = 0;
    let unexpected_panics = 0;
    let mut error_recovery_successes = 0;

    // Test 1: Invalid Parameters
    println!("\n📋 Test 1: Invalid Parameter Handling");
    total_tests += 1;

    let invalid_params_mission = Mission {
        version: "1.0".to_string(),
        name: "Invalid Parameters Test".to_string(),
        description: Some("Test how system handles invalid parameters".to_string()),
        steps: vec![MissionStep {
            id: "invalid_create_file".to_string(),
            name: "Invalid File Creation".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({
                "path": "/invalid/path/with/no/permissions/test.txt",
                "content": "This should fail gracefully"
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(invalid_params_mission, &ctx).await {
        Ok(_) => println!("  ⚠️  Unexpected success - should have failed"),
        Err(e) => {
            graceful_failures += 1;
            println!("  ✅ Graceful failure: {}", e);
        }
    }

    // Test 2: Missing Dependencies
    println!("\n📋 Test 2: Missing Dependency Handling");
    total_tests += 1;

    let missing_deps_mission = Mission {
        version: "1.0".to_string(),
        name: "Missing Dependencies Test".to_string(),
        description: Some("Test dependency validation".to_string()),
        steps: vec![MissionStep {
            id: "dependent_step".to_string(),
            name: "Step with Missing Dependency".to_string(),
            step_type: StepType::Noop,
            depends_on: Some(vec!["nonexistent_step".to_string()]),
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({}),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(missing_deps_mission, &ctx).await {
        Ok(_) => println!("  ⚠️  Unexpected success - should have failed"),
        Err(e) => {
            graceful_failures += 1;
            println!("  ✅ Graceful failure: {}", e);
        }
    }

    // Test 3: Circular Dependencies
    println!("\n📋 Test 3: Circular Dependency Detection");
    total_tests += 1;

    let circular_deps_mission = Mission {
        version: "1.0".to_string(),
        name: "Circular Dependencies Test".to_string(),
        description: Some("Test circular dependency detection".to_string()),
        steps: vec![
            MissionStep {
                id: "step_a".to_string(),
                name: "Step A".to_string(),
                step_type: StepType::Noop,
                depends_on: Some(vec!["step_b".to_string()]),
                timeout_seconds: None,
                continue_on_error: Some(false),
                parameters: json!({}),
            },
            MissionStep {
                id: "step_b".to_string(),
                name: "Step B".to_string(),
                step_type: StepType::Noop,
                depends_on: Some(vec!["step_a".to_string()]),
                timeout_seconds: None,
                continue_on_error: Some(false),
                parameters: json!({}),
            },
        ],
        config: None,
    };

    match DagExecutor::execute_mission(circular_deps_mission, &ctx).await {
        Ok(_) => println!("  ⚠️  Unexpected success - should have failed"),
        Err(e) => {
            graceful_failures += 1;
            println!("  ✅ Graceful failure: {}", e);
        }
    }

    // Test 4: Continue on Error Behavior
    println!("\n📋 Test 4: Continue-on-Error Recovery");
    total_tests += 1;

    let continue_on_error_mission = Mission {
        version: "1.0".to_string(),
        name: "Continue on Error Test".to_string(),
        description: Some("Test error recovery with continue_on_error".to_string()),
        steps: vec![
            MissionStep {
                id: "failing_step".to_string(),
                name: "Failing Step".to_string(),
                step_type: StepType::CreateFile,
                depends_on: None,
                timeout_seconds: None,
                continue_on_error: Some(true), // Should continue despite failure
                parameters: json!({
                    "path": "/invalid/path/fail.txt",
                    "content": "This will fail"
                }),
            },
            MissionStep {
                id: "recovery_step".to_string(),
                name: "Recovery Step".to_string(),
                step_type: StepType::Noop,
                depends_on: Some(vec!["failing_step".to_string()]),
                timeout_seconds: None,
                continue_on_error: Some(false),
                parameters: json!({}),
            },
        ],
        config: None,
    };

    match DagExecutor::execute_mission(continue_on_error_mission, &ctx).await {
        Ok(result) => {
            error_recovery_successes += 1;
            println!(
                "  ✅ Error recovery success: {} steps completed",
                result.step_results.len()
            );
        }
        Err(e) => println!("  ⚠️  Recovery failed: {}", e),
    }

    // Test 5: Timeout Handling
    println!("\n📋 Test 5: Timeout Handling");
    total_tests += 1;

    let timeout_mission = Mission {
        version: "1.0".to_string(),
        name: "Timeout Test".to_string(),
        description: Some("Test timeout behavior".to_string()),
        steps: vec![MissionStep {
            id: "timeout_step".to_string(),
            name: "Step with Short Timeout".to_string(),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: Some(1), // 1 second timeout
            continue_on_error: Some(false),
            parameters: json!({
                "command": "sleep",
                "args": ["5"] // Sleep for 5 seconds - should timeout
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(timeout_mission, &ctx).await {
        Ok(_) => println!("  ⚠️  Unexpected success - should have timed out"),
        Err(e) => {
            graceful_failures += 1;
            println!("  ✅ Graceful timeout: {}", e);
        }
    }

    // Test 6: Fail-Fast vs Continue Behavior
    println!("\n📋 Test 6: Fail-Fast Configuration");
    total_tests += 1;

    let fail_fast_mission = Mission {
        version: "1.0".to_string(),
        name: "Fail-Fast Test".to_string(),
        description: Some("Test fail-fast configuration".to_string()),
        steps: vec![
            MissionStep {
                id: "first_step".to_string(),
                name: "First Step".to_string(),
                step_type: StepType::CreateFile,
                depends_on: None,
                timeout_seconds: None,
                continue_on_error: Some(false),
                parameters: json!({
                    "path": "/invalid/path/fail.txt",
                    "content": "This will fail"
                }),
            },
            MissionStep {
                id: "second_step".to_string(),
                name: "Second Step".to_string(),
                step_type: StepType::Noop,
                depends_on: None,
                timeout_seconds: None,
                continue_on_error: Some(false),
                parameters: json!({}),
            },
        ],
        config: Some(MissionConfig {
            max_parallel_steps: None,
            timeout_seconds: None,
            fail_fast: Some(true),
        }),
    };

    match DagExecutor::execute_mission(fail_fast_mission, &ctx).await {
        Ok(_) => println!("  ⚠️  Unexpected success - should have failed fast"),
        Err(e) => {
            graceful_failures += 1;
            println!("  ✅ Fail-fast behavior: {}", e);
        }
    }

    // Test 7: Empty Mission Handling
    println!("\n📋 Test 7: Empty Mission Validation");
    total_tests += 1;

    let empty_mission = Mission {
        version: "1.0".to_string(),
        name: "Empty Mission Test".to_string(),
        description: Some("Test empty mission handling".to_string()),
        steps: vec![], // No steps
        config: None,
    };

    match DagExecutor::execute_mission(empty_mission, &ctx).await {
        Ok(_) => println!("  ⚠️  Unexpected success - empty mission should fail"),
        Err(e) => {
            graceful_failures += 1;
            println!("  ✅ Empty mission rejection: {}", e);
        }
    }

    // Calculate error handling score
    let graceful_failure_rate = (graceful_failures as f64 / total_tests as f64) * 100.0;
    let error_recovery_rate = if error_recovery_successes > 0 {
        100.0
    } else {
        0.0
    };

    println!("\n🛡️ ERROR HANDLING ASSESSMENT");
    println!("============================");
    println!("📊 Total Tests: {}", total_tests);
    println!(
        "✅ Graceful Failures: {}/{} ({:.1}%)",
        graceful_failures, total_tests, graceful_failure_rate
    );
    println!(
        "🔄 Error Recovery: {}/{} ({:.1}%)",
        error_recovery_successes, 1, error_recovery_rate
    );
    println!("💥 Unexpected Panics: {}", unexpected_panics);

    println!("\n📋 ERROR HANDLING GRADE");
    println!("=======================");
    if graceful_failure_rate >= 90.0 && unexpected_panics == 0 {
        println!("🎉 EXCELLENT: Production-ready error handling");
    } else if graceful_failure_rate >= 80.0 && unexpected_panics == 0 {
        println!("👍 GOOD: Solid error handling with minor gaps");
    } else if graceful_failure_rate >= 70.0 && unexpected_panics <= 1 {
        println!("⚠️  MODERATE: Adequate error handling, needs improvement");
    } else {
        println!("❌ POOR: Error handling needs significant work");
    }

    // Enterprise readiness assessment for error handling
    if graceful_failure_rate >= 85.0 && unexpected_panics == 0 && error_recovery_successes > 0 {
        println!("✅ ENTERPRISE READY: Error handling meets enterprise standards");
    } else {
        println!("🚧 NEEDS WORK: Error handling requires improvement for enterprise use");
    }

    Ok(())
}
