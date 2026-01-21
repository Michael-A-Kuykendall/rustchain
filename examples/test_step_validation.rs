// Simple test program to validate step type functionality
use rustchain::core::RuntimeContext;
use rustchain::engine::{DagExecutor, Mission, MissionStep, StepType};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🔧 RustChain Step Type Validation");
    println!("===================================");

    // Create runtime context
    let ctx = RuntimeContext::new();

    // Test 1: Basic Noop Step
    println!("\n📋 Test 1: Basic Noop Mission");
    let noop_mission = Mission {
        version: "1.0".to_string(),
        name: "Noop Test Mission".to_string(),
        description: Some("Test basic Noop step execution".to_string()),
        steps: vec![MissionStep {
            id: "noop_1".to_string(),
            name: "Test Noop Step".to_string(),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({}),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(noop_mission, &ctx).await {
        Ok(result) => println!(
            "  ✅ Noop mission succeeded: {} steps",
            result.step_results.len()
        ),
        Err(e) => println!("  ❌ Noop mission failed: {}", e),
    }

    // Test 2: Step Type Availability Survey (reduced set)
    println!("\n📋 Test 2: Core Step Type Survey");
    let test_step_types = vec![
        (StepType::Noop, "Noop"),
        (StepType::Command, "Command"),
        (StepType::CreateFile, "CreateFile"),
        (StepType::Http, "HTTP"),
    ];

    let mut implemented_count = 0;
    let mut not_implemented_count = 0;

    for (step_type, type_name) in test_step_types {
        let test_mission = Mission {
            version: "1.0".to_string(),
            name: format!("Test {} Mission", type_name),
            description: Some(format!("Test {} step type", type_name)),
            steps: vec![MissionStep {
                id: format!("test_{}", type_name.replace(" ", "_").to_lowercase()),
                name: format!("Test {}", type_name),
                step_type: step_type.clone(),
                depends_on: None,
                timeout_seconds: Some(5), // 5 second timeout for tests
                continue_on_error: Some(true),
                parameters: json!({}),
            }],
            config: None,
        };

        match DagExecutor::execute_mission(test_mission, &ctx).await {
            Ok(_) => {
                implemented_count += 1;
                println!("  ✅ {} - IMPLEMENTED", type_name);
            }
            Err(e) => {
                not_implemented_count += 1;
                println!("  🚧 {} - NOT IMPLEMENTED: {}", type_name, e);
            }
        }
    }

    println!("\n📊 CORE STEP TYPE SUMMARY");
    println!("=========================");
    println!("✅ Implemented: {} step types", implemented_count);
    println!("🚧 Not Implemented: {} step types", not_implemented_count);

    Ok(())
}
