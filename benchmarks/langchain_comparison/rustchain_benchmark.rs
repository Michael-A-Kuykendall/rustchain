//! RustChain Benchmark Suite
//! ==========================
//! Equivalent workloads to LangChain for fair comparison.
//!
//! Run: cargo run --release --bin rustchain-benchmark

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::time::Instant;

/// System information for reproducibility
#[derive(Serialize)]
struct SystemInfo {
    timestamp: String,
    platform: String,
    rust_version: String,
    cpu_count: usize,
    target: String,
}

impl SystemInfo {
    fn capture() -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            rust_version: "1.70+".to_string(),
            cpu_count: num_cpus::get(),
            target: std::env::consts::ARCH.to_string(),
        }
    }
}

/// Benchmark result statistics
#[derive(Serialize)]
struct BenchmarkResult {
    operation: String,
    iterations: usize,
    total_ms: f64,
    mean_ms: f64,
    median_ms: f64,
    stdev_ms: f64,
    min_ms: f64,
    max_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tasks: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ops_per_iteration: Option<usize>,
}

impl BenchmarkResult {
    fn from_times(operation: &str, times: &[f64]) -> Self {
        let mut sorted = times.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let n = sorted.len();
        let sum: f64 = sorted.iter().sum();
        let mean = sum / n as f64;
        let median = if n % 2 == 0 {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        } else {
            sorted[n / 2]
        };

        let variance: f64 = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        let stdev = variance.sqrt();

        Self {
            operation: operation.to_string(),
            iterations: n,
            total_ms: sum,
            mean_ms: mean,
            median_ms: median,
            stdev_ms: stdev,
            min_ms: sorted[0],
            max_ms: sorted[n - 1],
            p95_ms: sorted[(n as f64 * 0.95) as usize],
            p99_ms: sorted[(n as f64 * 0.99) as usize],
            parallel_tasks: None,
            ops_per_iteration: None,
        }
    }
}

/// Sample workflow definition (matches Python benchmark)
const WORKFLOW_YAML: &str = r#"
name: benchmark_workflow
version: "1.0"
description: Multi-step data processing workflow

steps:
  - id: step_1
    name: Initialize
    action: set_variable
    params:
      key: data
      value: "input_data"
    
  - id: step_2
    name: Process
    action: transform
    depends_on: [step_1]
    params:
      operation: uppercase
      
  - id: step_3
    name: Validate
    action: check
    depends_on: [step_2]
    params:
      condition: "length > 0"
      
  - id: step_4
    name: Output
    action: return
    depends_on: [step_3]
    params:
      format: json
"#;

/// Workflow structure for parsing
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Workflow {
    name: String,
    version: String,
    description: String,
    steps: Vec<Step>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Step {
    id: String,
    name: String,
    action: String,
    #[serde(default)]
    depends_on: Vec<String>,
    params: HashMap<String, serde_yaml::Value>,
}

/// Benchmark 1: Workflow Parsing
fn benchmark_workflow_parsing(iterations: usize) -> BenchmarkResult {
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();

        // Parse YAML
        let workflow: Workflow = serde_yaml::from_str(WORKFLOW_YAML).unwrap();

        // Validate structure
        assert!(!workflow.name.is_empty());
        assert!(!workflow.steps.is_empty());
        for step in &workflow.steps {
            assert!(!step.id.is_empty());
            assert!(!step.action.is_empty());
        }

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    BenchmarkResult::from_times("workflow_parsing", &times)
}

/// Benchmark 2: Chain Execution
fn benchmark_chain_execution(iterations: usize) -> BenchmarkResult {
    let mut times = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let input = format!("benchmark_input_data_{}", i).repeat(10);
        let mut state: HashMap<String, serde_json::Value> = HashMap::new();
        state.insert("input".to_string(), json!(input));

        let start = Instant::now();

        // Step 1: Uppercase
        let step_1: String = state["input"].as_str().unwrap().to_uppercase();
        state.insert("step_1".to_string(), json!(step_1));

        // Step 2: Reverse
        let step_2: String = state["step_1"].as_str().unwrap().chars().rev().collect();
        state.insert("step_2".to_string(), json!(step_2));

        // Step 3: Length
        let step_3 = state["step_2"].as_str().unwrap().len();
        state.insert("step_3".to_string(), json!(step_3));

        // Step 4: Output
        let output = format!("Processed: {} chars", step_3);
        state.insert("output".to_string(), json!(output));

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    BenchmarkResult::from_times("chain_execution", &times)
}

/// Benchmark 3: Parallel Execution
fn benchmark_parallel_execution(iterations: usize) -> BenchmarkResult {
    use rayon::prelude::*;

    const NUM_PARALLEL_TASKS: usize = 20;
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();

        // Fan-out: Execute tasks in parallel (true parallelism with Rayon)
        let results: Vec<(usize, i64)> = (0..NUM_PARALLEL_TASKS)
            .into_par_iter()
            .map(|task_id| {
                // CPU-bound work
                let result: i64 = (0..10000i64).map(|i| i * task_id as i64).sum();
                (task_id, result)
            })
            .collect();

        // Fan-in: Aggregate results
        let _total: i64 = results.iter().map(|(_, r)| r).sum();

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    let mut result = BenchmarkResult::from_times("parallel_execution", &times);
    result.parallel_tasks = Some(NUM_PARALLEL_TASKS);
    result
}

/// Benchmark 4: Memory Operations
fn benchmark_memory_operations(iterations: usize) -> BenchmarkResult {
    const NUM_OPERATIONS: usize = 100;
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let mut store: HashMap<String, serde_json::Value> = HashMap::new();

        let start = Instant::now();

        // Write operations
        for i in 0..NUM_OPERATIONS {
            store.insert(
                format!("key_{}", i),
                json!({
                    "value": "data_".repeat(100),
                    "metadata": {"index": i}
                }),
            );
        }

        // Read operations
        for i in 0..NUM_OPERATIONS {
            let _ = store.get(&format!("key_{}", i));
        }

        // Update operations
        for i in 0..NUM_OPERATIONS {
            if let Some(entry) = store.get_mut(&format!("key_{}", i)) {
                if let Some(obj) = entry.as_object_mut() {
                    if let Some(meta) = obj.get_mut("metadata") {
                        if let Some(meta_obj) = meta.as_object_mut() {
                            meta_obj.insert("updated".to_string(), json!(true));
                        }
                    }
                }
            }
        }

        // Delete operations
        for i in (0..NUM_OPERATIONS).step_by(2) {
            store.remove(&format!("key_{}", i));
        }

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    let mut result = BenchmarkResult::from_times("memory_operations", &times);
    result.ops_per_iteration = Some(NUM_OPERATIONS * 4);
    result
}

/// Benchmark 5: LLM Chain (optional - requires OPENAI_API_KEY)
#[cfg(feature = "llm")]
async fn benchmark_llm_chain(iterations: usize) -> serde_json::Value {
    use rustchain::llm::{ChatMessage, LLMManager, LLMRequest, MessageRole};
    use std::env;

    let no_llm = std::env::args().any(|arg| arg == "--no-llm");
    if no_llm {
        return json!({
            "operation": "llm_chain",
            "skipped": true,
            "reason": "--no-llm flag set"
        });
    }

    let api_key = env::var("OPENAI_API_KEY");
    if api_key.is_err() {
        return json!({
            "operation": "llm_chain",
            "skipped": true,
            "reason": "OPENAI_API_KEY not set"
        });
    }

    let topics = ["Python", "Rust", "benchmarking", "performance", "testing"];
    let mut times = Vec::with_capacity(iterations);

    let manager = LLMManager::new();

    for i in 0..iterations {
        let topic = topics[i % topics.len()];
        let prompt = format!("Answer in exactly 3 words: What is {}?", topic);

        let request = LLMRequest {
            messages: vec![ChatMessage {
                role: MessageRole::User,
                content: prompt,
                name: None,
                tool_calls: None,
                tool_call_id: None,
            }],
            model: Some("gpt-3.5-turbo".to_string()),
            temperature: Some(0.0),
            max_tokens: Some(20),
            stream: false,
            tools: None,
            metadata: std::collections::HashMap::new(),
        };

        let start = Instant::now();
        let _ = manager.complete(request, Some("openai")).await;
        let elapsed = start.elapsed();

        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    let result = BenchmarkResult::from_times("llm_chain", &times);
    serde_json::to_value(result).unwrap()
}

#[cfg(not(feature = "llm"))]
async fn benchmark_llm_chain(_iterations: usize) -> serde_json::Value {
    json!({
        "operation": "llm_chain",
        "skipped": true,
        "reason": "LLM feature not enabled"
    })
}

#[derive(Serialize)]
struct BenchmarkResults {
    framework: String,
    system: SystemInfo,
    benchmarks: Vec<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    println!("{}", "=".repeat(60));
    println!("RustChain Benchmark Suite");
    println!("{}", "=".repeat(60));
    println!();

    let mut results = BenchmarkResults {
        framework: "rustchain".to_string(),
        system: SystemInfo::capture(),
        benchmarks: Vec::new(),
    };

    // Benchmark 1: Workflow Parsing
    println!("Running: Workflow Parsing (1000 iterations)...");
    let result = benchmark_workflow_parsing(1000);
    println!(
        "  Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());
    println!();

    // Benchmark 2: Chain Execution
    println!("Running: Chain Execution (100 iterations)...");
    let result = benchmark_chain_execution(100);
    println!(
        "  Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());
    println!();

    // Benchmark 3: Parallel Execution
    println!("Running: Parallel Execution (50 iterations, 20 parallel tasks)...");
    let result = benchmark_parallel_execution(50);
    println!(
        "  Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());
    println!();

    // Benchmark 4: Memory Operations
    println!("Running: Memory Operations (1000 iterations)...");
    let result = benchmark_memory_operations(1000);
    println!(
        "  Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());
    println!();

    // Benchmark 5: LLM Chain (optional)
    println!("Running: LLM Chain (5 iterations)...");
    let result = benchmark_llm_chain(5).await;
    if let Some(_skipped) = result.get("skipped") {
        println!("  Skipped: {}", result.get("reason").unwrap());
    } else if let Some(error) = result.get("error") {
        println!("  Error: {}", error);
    } else {
        println!(
            "  Mean: {:.3}ms, Median: {:.3}ms",
            result.get("mean_ms").unwrap().as_f64().unwrap(),
            result.get("median_ms").unwrap().as_f64().unwrap()
        );
    }
    results.benchmarks.push(result);
    println!();

    println!("{}", "=".repeat(60));
    println!("Benchmark Complete");
    println!("{}", "=".repeat(60));

    // Save results to JSON
    let output_file = "rustchain_results.json";
    fs::write(output_file, serde_json::to_string_pretty(&results).unwrap()).unwrap();
    println!("\nResults saved to: {}", output_file);
}
