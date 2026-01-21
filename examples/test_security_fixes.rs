// Test the security fixes to ensure they prevent dangerous operations
use rustchain::core::RuntimeContext;
use rustchain::engine::{DagExecutor, Mission, MissionStep, StepType};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🛡️ Testing Security Fixes");
    println!("========================");

    // Create runtime context
    let ctx = RuntimeContext::new();

    let mut tests_passed = 0;
    let mut total_tests = 0;

    // Test 1: Path traversal prevention
    println!("\n📋 Test 1: Path Traversal Prevention");
    total_tests += 1;

    let path_traversal_mission = Mission {
        version: "1.0".to_string(),
        name: "Path Traversal Test".to_string(),
        description: Some("Test path traversal prevention".to_string()),
        steps: vec![MissionStep {
            id: "path_traversal_test".to_string(),
            name: "Path Traversal Test".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: Some(5),
            continue_on_error: Some(false),
            parameters: json!({
                "path": "../../../etc/passwd",
                "content": "This should be blocked"
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(path_traversal_mission, &ctx).await {
        Ok(_) => {
            println!("  ❌ SECURITY FAILURE: Path traversal allowed");
        }
        Err(e) => {
            if e.to_string().contains("Path traversal detected") {
                tests_passed += 1;
                println!("  ✅ SECURITY SUCCESS: Path traversal blocked");
            } else {
                println!("  ⚠️  Blocked for different reason: {}", e);
            }
        }
    }

    // Test 2: Windows reserved filename prevention
    println!("\n📋 Test 2: Windows Reserved Filename Prevention");
    total_tests += 1;

    let reserved_name_mission = Mission {
        version: "1.0".to_string(),
        name: "Reserved Name Test".to_string(),
        description: Some("Test Windows reserved name prevention".to_string()),
        steps: vec![MissionStep {
            id: "reserved_name_test".to_string(),
            name: "Reserved Name Test".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: Some(5),
            continue_on_error: Some(false),
            parameters: json!({
                "path": "CON",
                "content": "This should be blocked"
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(reserved_name_mission, &ctx).await {
        Ok(_) => {
            println!("  ❌ SECURITY FAILURE: Reserved filename allowed");
        }
        Err(e) => {
            if e.to_string().contains("Windows reserved filename") {
                tests_passed += 1;
                println!("  ✅ SECURITY SUCCESS: Reserved filename blocked");
            } else {
                println!("  ⚠️  Blocked for different reason: {}", e);
            }
        }
    }

    // Test 3: Command injection prevention
    println!("\n📋 Test 3: Command Injection Prevention");
    total_tests += 1;

    let command_injection_mission = Mission {
        version: "1.0".to_string(),
        name: "Command Injection Test".to_string(),
        description: Some("Test command injection prevention".to_string()),
        steps: vec![MissionStep {
            id: "command_injection_test".to_string(),
            name: "Command Injection Test".to_string(),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: Some(5),
            continue_on_error: Some(false),
            parameters: json!({
                "command": "echo test && rm -rf /",
                "args": []
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(command_injection_mission, &ctx).await {
        Ok(_) => {
            println!("  ❌ SECURITY FAILURE: Command injection allowed");
        }
        Err(e) => {
            if e.to_string().contains("Dangerous command pattern detected") {
                tests_passed += 1;
                println!("  ✅ SECURITY SUCCESS: Command injection blocked");
            } else {
                println!("  ⚠️  Blocked for different reason: {}", e);
            }
        }
    }

    // Test 4: Dangerous command prevention
    println!("\n📋 Test 4: Dangerous Command Prevention");
    total_tests += 1;

    let dangerous_command_mission = Mission {
        version: "1.0".to_string(),
        name: "Dangerous Command Test".to_string(),
        description: Some("Test dangerous command prevention".to_string()),
        steps: vec![MissionStep {
            id: "dangerous_command_test".to_string(),
            name: "Dangerous Command Test".to_string(),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: Some(5),
            continue_on_error: Some(false),
            parameters: json!({
                "command": "rm",
                "args": ["-rf", "/"]
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(dangerous_command_mission, &ctx).await {
        Ok(_) => {
            println!("  ❌ SECURITY FAILURE: Dangerous command allowed");
        }
        Err(e) => {
            if e.to_string().contains("Dangerous command blocked") {
                tests_passed += 1;
                println!("  ✅ SECURITY SUCCESS: Dangerous command blocked");
            } else {
                println!("  ⚠️  Blocked for different reason: {}", e);
            }
        }
    }

    // Test 5: Safe operations still work
    println!("\n📋 Test 5: Safe Operations Still Work");
    total_tests += 1;

    let temp_file = std::env::temp_dir().join("security_test_safe.txt");
    let safe_operation_mission = Mission {
        version: "1.0".to_string(),
        name: "Safe Operation Test".to_string(),
        description: Some("Test that safe operations still work".to_string()),
        steps: vec![MissionStep {
            id: "safe_file_test".to_string(),
            name: "Safe File Test".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: Some(5),
            continue_on_error: Some(false),
            parameters: json!({
                "path": temp_file.to_string_lossy(),
                "content": "This is a safe operation"
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(safe_operation_mission, &ctx).await {
        Ok(_) => {
            tests_passed += 1;
            println!("  ✅ FUNCTIONALITY SUCCESS: Safe operations work");
            // Cleanup
            let _ = std::fs::remove_file(&temp_file);
        }
        Err(e) => {
            println!("  ❌ FUNCTIONALITY FAILURE: Safe operation blocked: {}", e);
        }
    }

    // Test 6: Safe commands still work
    println!("\n📋 Test 6: Safe Commands Still Work");
    total_tests += 1;

    let safe_command_mission = Mission {
        version: "1.0".to_string(),
        name: "Safe Command Test".to_string(),
        description: Some("Test that safe commands still work".to_string()),
        steps: vec![MissionStep {
            id: "safe_command_test".to_string(),
            name: "Safe Command Test".to_string(),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: Some(5),
            continue_on_error: Some(false),
            parameters: json!({
                "command": if cfg!(target_os = "windows") { "cmd" } else { "echo" },
                "args": if cfg!(target_os = "windows") {
                    vec!["/c", "echo", "Safe command test"]
                } else {
                    vec!["Safe command test"]
                }
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(safe_command_mission, &ctx).await {
        Ok(_) => {
            tests_passed += 1;
            println!("  ✅ FUNCTIONALITY SUCCESS: Safe commands work");
        }
        Err(e) => {
            println!("  ❌ FUNCTIONALITY FAILURE: Safe command blocked: {}", e);
        }
    }

    // Security test results
    println!("\n🛡️ SECURITY TEST RESULTS");
    println!("========================");
    println!("📊 Tests Passed: {}/{}", tests_passed, total_tests);

    let security_score = (tests_passed as f64 / total_tests as f64) * 100.0;
    println!("📊 Security Score: {:.1}%", security_score);

    if security_score >= 95.0 {
        println!("🎉 EXCELLENT: Security fixes working perfectly");
    } else if security_score >= 80.0 {
        println!("👍 GOOD: Security fixes mostly working");
    } else if security_score >= 60.0 {
        println!("⚠️  MODERATE: Some security fixes working");
    } else {
        println!("❌ POOR: Security fixes need more work");
    }

    println!("\n🎯 PRODUCTION READINESS");
    println!("=======================");
    if security_score >= 90.0 && tests_passed >= 4 {
        println!("✅ PRODUCTION READY: Security fixes successfully implemented");
        println!("🚀 RECOMMENDATION: Deploy with confidence");
    } else {
        println!("🚧 NEEDS WORK: Security fixes need attention");
        println!("📋 RECOMMENDATION: Fix remaining issues before deployment");
    }

    Ok(())
}
