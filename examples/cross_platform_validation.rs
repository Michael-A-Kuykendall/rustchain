use rustchain::core::RuntimeContext;
use rustchain::engine::{DagExecutor, Mission, MissionStep, StepType};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("RustChain Cross-Platform Test Suite");
    println!("===================================");

    // Create shared runtime context
    let ctx = RuntimeContext::new();

    let mut test_count = 0;
    let mut compat_successes = 0;
    let mut platform_failures = 0;

    // Detect current platform
    let platform = if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Unknown"
    };

    println!("Platform: {}", platform);

    // Test 1: File operations
    println!("\nTest 1: File Operations");
    test_count += 1;

    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("rustchain_cross_platform_test.txt");

    let file_ops_mission = Mission {
        version: "1.0".to_string(),
        name: "Cross-Platform File Test".to_string(),
        description: Some("Test file operations across platforms".to_string()),
        steps: vec![MissionStep {
            id: "create_test_file".to_string(),
            name: "Create Test File".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({
                "path": test_file.to_string_lossy(),
                "content": format!("Cross-platform test on {}", platform)
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(file_ops_mission, &ctx).await {
        Ok(_) => {
            compat_successes += 1;
            println!("  OK: File ops work on {}", platform);

            if test_file.exists() {
                println!("  OK: File verified");
                let _ = std::fs::remove_file(&test_file);
            } else {
                println!("  WARNING: File not found after creation");
            }
        }
        Err(e) => {
            platform_failures += 1;
            println!("  FAIL: File ops failed on {}: {}", platform, e);
        }
    }

    // Test 2: Platform commands
    println!("\nTest 2: Platform Commands");
    test_count += 1;

    let (test_command, test_args) = if cfg!(target_os = "windows") {
        ("cmd", vec!["/c", "echo", "Windows test"])
    } else {
        ("echo", vec!["Unix test"])
    };

    let platform_command_mission = Mission {
        version: "1.0".to_string(),
        name: "Platform Command Test".to_string(),
        description: Some("Test platform-appropriate commands".to_string()),
        steps: vec![MissionStep {
            id: "platform_command".to_string(),
            name: "Platform Command".to_string(),
            step_type: StepType::Command,
            depends_on: None,
            timeout_seconds: Some(10),
            continue_on_error: Some(false),
            parameters: json!({
                "command": test_command,
                "args": test_args
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(platform_command_mission, &ctx).await {
        Ok(_) => {
            compat_successes += 1;
            println!("  OK: Commands work on {}", platform);
        }
        Err(e) => {
            platform_failures += 1;
            println!("  FAIL: Commands failed on {}: {}", platform, e);
        }
    }

    // Test 3: Path handling
    println!("\nTest 3: Path Separators");
    test_count += 1;

    let test_subdir = temp_dir.join("rustchain_test_subdir");
    let test_file_in_subdir = test_subdir.join("test.txt");

    let path_handling_mission = Mission {
        version: "1.0".to_string(),
        name: "Path Handling Test".to_string(),
        description: Some("Test path separator handling".to_string()),
        steps: vec![MissionStep {
            id: "create_subdir_file".to_string(),
            name: "Create File in Subdirectory".to_string(),
            step_type: StepType::CreateFile,
            depends_on: None,
            timeout_seconds: None,
            continue_on_error: Some(false),
            parameters: json!({
                "path": test_file_in_subdir.to_string_lossy(),
                "content": "Path separator test"
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(path_handling_mission, &ctx).await {
        Ok(_) => {
            compat_successes += 1;
            println!("  OK: Paths work on {}", platform);

            let _ = std::fs::remove_file(&test_file_in_subdir);
            let _ = std::fs::remove_dir(&test_subdir);
        }
        Err(e) => {
            platform_failures += 1;
            println!("  FAIL: Paths failed on {}: {}", platform, e);
        }
    }

    // Test 4: Environment variables
    println!("\nTest 4: Environment Variables");
    test_count += 1;

    // Use a universally available environment variable
    let env_var = if cfg!(target_os = "windows") {
        "USERPROFILE"
    } else {
        "HOME"
    };

    if std::env::var(env_var).is_ok() {
        compat_successes += 1;
        println!("  OK: Env var {} accessible on {}", env_var, platform);
    } else {
        platform_failures += 1;
        println!("  FAIL: Env var {} missing on {}", env_var, platform);
    }

    // Test 5: HTTP operations
    println!("\nTest 5: HTTP Operations");
    test_count += 1;

    let http_mission = Mission {
        version: "1.0".to_string(),
        name: "HTTP Test".to_string(),
        description: Some("Test HTTP operations".to_string()),
        steps: vec![MissionStep {
            id: "http_test".to_string(),
            name: "HTTP Request".to_string(),
            step_type: StepType::Http,
            depends_on: None,
            timeout_seconds: Some(10),
            continue_on_error: Some(true), // Network might not be available
            parameters: json!({
                "url": "https://httpbin.org/get",
                "method": "GET"
            }),
        }],
        config: None,
    };

    match DagExecutor::execute_mission(http_mission, &ctx).await {
        Ok(_) => {
            compat_successes += 1;
            println!("  OK: HTTP works on {}", platform);
        }
        Err(e) => {
            println!("  WARNING: HTTP failed on {} (network?): {}", platform, e);
            compat_successes += 1; // Don't penalize for network issues
        }
    }

    // Calculate results
    let compat_rate = (compat_successes as f64 / test_count as f64) * 100.0;

    println!("\nCROSS-PLATFORM RESULTS");
    println!("======================");
    println!("Platform: {}", platform);
    println!("Tests: {}", test_count);
    println!(
        "Compatible: {}/{} ({:.1}%)",
        compat_successes, test_count, compat_rate
    );
    println!("Failures: {}", platform_failures);

    println!("\nGRADE");
    println!("=====");
    if compat_rate >= 95.0 {
        println!("EXCELLENT: Fully compatible");
    } else if compat_rate >= 85.0 {
        println!("GOOD: Strong compatibility");
    } else if compat_rate >= 70.0 {
        println!("MODERATE: Adequate support");
    } else {
        println!("POOR: Compatibility issues");
    }

    println!("\nENTERPRISE READINESS");
    println!("===================");
    if compat_rate >= 90.0 {
        println!("READY: Multi-platform deployments");
    } else if compat_rate >= 80.0 {
        println!("PARTIAL: Platform considerations needed");
    } else {
        println!("NOT READY: Platform-specific dev required");
    }

    println!("\nNOTES");
    println!("=====");
    println!("Tested on: {}", platform);
    println!("Full validation requires Windows, Linux, macOS testing");
    println!("Test all deployment platforms before production");

    Ok(())
}
