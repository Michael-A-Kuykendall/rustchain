#!/usr/bin/env cargo script

//! RustChain Performance Benchmark
//! 
//! Tests RustChain performance against documented baselines
//! 
//! Usage: cargo run --bin simple_benchmark

use std::time::Instant;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 RustChain Performance Benchmark");
    println!("=====================================\n");
    
    println!("⚠️  WARNING: This benchmark only measures RustChain performance.");
    println!("   Comparisons to other frameworks require separate testing.\n");

    // Test 1: Mission Parsing Speed
    println!("📊 Test 1: Mission Parsing Speed");
    let parsing_times = benchmark_mission_parsing(5)?;
    if parsing_times.is_empty() {
        println!("   ❌ No successful parsing tests completed");
    } else {
        let avg_parsing = parsing_times.iter().sum::<u128>() / parsing_times.len() as u128;
        println!("   RustChain Average: {}ms", avg_parsing);
        println!("   Note: Comparison requires testing other frameworks separately\n");
    }

    // Test 2: File Operations Speed  
    println!("📁 Test 2: File Operations Speed");
    let file_times = benchmark_file_operations(5)?;
    if file_times.is_empty() {
        println!("   ❌ No successful file operation tests completed");
    } else {
        let avg_file = file_times.iter().sum::<u128>() / file_times.len() as u128;
        println!("   RustChain Average: {}ms", avg_file);
        println!("   Note: Comparison requires testing other frameworks separately\n");
    }

    // Test 3: Memory Usage (Static Analysis)
    println!("🧠 Test 3: Memory Usage Analysis");
    println!("   RustChain Binary Size: Limited to what's measured");
    println!("   Note: Memory comparisons require actual testing of alternatives\n");

    // Test 4: Startup Time
    println!("⚡ Test 4: Startup Time");
    let startup_times = benchmark_startup_time(5)?;
    if startup_times.is_empty() {
        println!("   ❌ No successful startup tests completed");
    } else {
        let avg_startup = startup_times.iter().sum::<u128>() / startup_times.len() as u128;
        println!("   RustChain Average: {}ms", avg_startup);
        println!("   Note: Comparison requires testing other frameworks separately\n");
    }

    // Honest Summary Report
    println!("📈 PERFORMANCE SUMMARY");
    println!("======================");
    println!("📊 RustChain Performance Measured (Internal Testing Only)");
    println!("⚠️  Performance claims relative to other frameworks require");
    println!("   independent benchmarking of those frameworks");
    println!();
    println!("🔍 For legitimate comparisons, please:");
    println!("   1. Test equivalent workflows in target frameworks");
    println!("   2. Use identical hardware and conditions");
    println!("   3. Document methodology and limitations");
    println!("   4. Provide reproducible benchmark suites");

    Ok(())
}

fn benchmark_mission_parsing(iterations: usize) -> Result<Vec<u128>, Box<dyn std::error::Error>> {
    let mut times = Vec::new();
    
    for _ in 0..iterations {
        let start = Instant::now();
        
        // Run mission validation (parsing + validation)
        let output = Command::new("cargo")
            .args(&["run", "--bin", "rustchain", "--", "mission", "validate", "examples/01_hello_world_mission.yaml"])
            .output()?;
            
        let duration = start.elapsed();
        
        if output.status.success() {
            times.push(duration.as_millis());
        }
    }
    
    Ok(times)
}

fn benchmark_file_operations(iterations: usize) -> Result<Vec<u128>, Box<dyn std::error::Error>> {
    let mut times = Vec::new();
    
    for i in 0..iterations {
        let start = Instant::now();
        
        // Run simple file operation mission
        let output = Command::new("cargo")
            .args(&["run", "--bin", "rustchain", "--", "run", "examples/01_hello_world_mission.yaml"])
            .output()?;
            
        let duration = start.elapsed();
        
        if output.status.success() {
            times.push(duration.as_millis());
        }
        
        // Cleanup test file
        let _ = std::fs::remove_file("hello_rustchain.txt");
    }
    
    Ok(times)
}

fn benchmark_startup_time(iterations: usize) -> Result<Vec<u128>, Box<dyn std::error::Error>> {
    let mut times = Vec::new();
    
    for _ in 0..iterations {
        let start = Instant::now();
        
        // Test CLI startup time
        let output = Command::new("cargo")
            .args(&["run", "--bin", "rustchain", "--", "--version"])
            .output()?;
            
        let duration = start.elapsed();
        
        if output.status.success() {
            times.push(duration.as_millis());
        }
    }
    
    Ok(times)
}