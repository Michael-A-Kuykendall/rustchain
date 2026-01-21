//! RustChain Benchmark Suite v2
//! =============================
//! Real LLM benchmarks using local Ollama or Shimmy backends.
//!
//! Run: cargo run --release --bin rustchain-benchmark-v2 -- --backend ollama --model phi3
//!      cargo run --release --bin rustchain-benchmark-v2 -- --backend shimmy --model phi3

use rayon::prelude::*;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    turns_per_conversation: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_calls: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avg_response_chars: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_response_chars: Option<usize>,
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

        let variance: f64 =
            sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1).max(1) as f64;
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
            turns_per_conversation: None,
            parallel_calls: None,
            avg_response_chars: None,
            max_response_chars: None,
        }
    }
}

/// LLM Client for Ollama/Shimmy (OpenAI-compatible API)
#[derive(Debug, Serialize, Default, Clone)]
struct LLMUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_tokens: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
struct ChatResponse {
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_chars: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<LLMUsage>,
}

struct LLMClient {
    client: Client,
    base_url: String,
    model: String,
    temperature: f64,
    max_tokens: u32,
}

impl LLMClient {
    fn new(
        backend: &str,
        model: &str,
        base_url_override: Option<String>,
        temperature: f64,
        max_tokens: u32,
    ) -> Self {
        let base_url = base_url_override.unwrap_or_else(|| match backend {
            "ollama" => "http://localhost:11434/v1".to_string(),
            "shimmy" => "http://localhost:11435/v1".to_string(),
            // Default to ollama for unknown backends
            _ => "http://localhost:11434/v1".to_string(),
        });

        Self {
            client: Client::new(),
            base_url,
            model: model.to_string(),
            temperature,
            max_tokens,
        }
    }

    fn chat(&self, messages: &[serde_json::Value]) -> Result<ChatResponse, String> {
        let url = format!("{}/chat/completions", self.base_url);

        let body = json!({
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        });

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response
                .text()
                .unwrap_or_else(|_| "<failed to read body>".to_string());
            return Err(format!(
                "HTTP {} from {}: {}",
                status.as_u16(),
                url,
                body_text
            ));
        }

        let json: serde_json::Value = response
            .json()
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "No content in response".to_string())?;

        let usage = json
            .get("usage")
            .and_then(|u| u.as_object())
            .map(|u| LLMUsage {
                prompt_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()),
                completion_tokens: u.get("completion_tokens").and_then(|v| v.as_u64()),
                total_tokens: u.get("total_tokens").and_then(|v| v.as_u64()),
            });

        Ok(ChatResponse {
            response_chars: Some(content.chars().count()),
            content,
            usage,
        })
    }
}

#[derive(Serialize)]
struct BenchmarkConfig {
    temperature: f64,
    max_tokens: u32,
}

// =============================================================================
// Sample workflow for parsing
// =============================================================================

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

// =============================================================================
// CATEGORY 1: Framework Overhead (No LLM)
// =============================================================================

fn benchmark_workflow_parsing(iterations: usize) -> BenchmarkResult {
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        let workflow: Workflow = serde_yaml::from_str(WORKFLOW_YAML).unwrap();
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

fn benchmark_large_dag(iterations: usize) -> BenchmarkResult {
    let mut times = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let input = format!("dag_input_{}", i);

        let start = Instant::now();

        // Layer 1: 10 parallel steps using Rayon
        let layer1_results: Vec<(String, String)> = (0..10)
            .into_par_iter()
            .map(|j| (format!("l1_s{}", j), format!("processed_l1_s{}", j)))
            .collect();

        // Aggregate
        let mut state: HashMap<String, String> = HashMap::new();
        state.insert("input".to_string(), input);
        for (key, value) in layer1_results {
            state.insert(key, value);
        }
        state.insert("aggregated".to_string(), state.len().to_string());

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    BenchmarkResult::from_times("large_dag", &times)
}

fn benchmark_tool_dispatch(iterations: usize) -> BenchmarkResult {
    type ToolFn = Box<dyn Fn(&str) -> String + Sync>;
    let mut times = Vec::with_capacity(iterations);

    // Simulate 10 different tools as closures
    let tools: Vec<ToolFn> = (0..10)
        .map(|i| Box::new(move |input: &str| format!("tool_{}_output: {}", i, input)) as ToolFn)
        .collect();

    for i in 0..iterations {
        let input = format!("dispatch_{}", i);
        let tool_id = i % 10;

        let start = Instant::now();
        let _result = tools[tool_id](&input);
        let elapsed = start.elapsed();

        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    BenchmarkResult::from_times("tool_dispatch", &times)
}

fn benchmark_parallel_execution(iterations: usize) -> BenchmarkResult {
    const NUM_PARALLEL_TASKS: usize = 20;
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();

        let results: Vec<(usize, i64)> = (0..NUM_PARALLEL_TASKS)
            .into_par_iter()
            .map(|task_id| {
                let result: i64 = (0..10000i64).map(|i| i * task_id as i64).sum();
                (task_id, result)
            })
            .collect();

        let _total: i64 = results.iter().map(|(_, r)| r).sum();

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    let mut result = BenchmarkResult::from_times("parallel_execution", &times);
    result.parallel_tasks = Some(NUM_PARALLEL_TASKS);
    result
}

fn benchmark_memory_operations(iterations: usize) -> BenchmarkResult {
    const NUM_OPERATIONS: usize = 100;
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let mut store: HashMap<String, serde_json::Value> = HashMap::new();

        let start = Instant::now();

        for i in 0..NUM_OPERATIONS {
            store.insert(
                format!("key_{}", i),
                json!({"value": "data_".repeat(100), "metadata": {"index": i}}),
            );
        }
        for i in 0..NUM_OPERATIONS {
            let _ = store.get(&format!("key_{}", i));
        }
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

// =============================================================================
// CATEGORY 2: Real LLM Calls
// =============================================================================

fn benchmark_single_prompt(llm: &LLMClient, iterations: usize) -> BenchmarkResult {
    let topics = [
        "Python",
        "Rust",
        "machine learning",
        "databases",
        "networking",
        "compilers",
        "operating systems",
        "cryptography",
        "algorithms",
        "data structures",
    ];

    let mut times = Vec::with_capacity(iterations);
    let mut response_chars: Vec<usize> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let topic = topics[i % topics.len()];
        let messages = vec![json!({
            "role": "user",
            "content": format!("Answer in exactly 5 words: What is {}?", topic)
        })];

        let start = Instant::now();
        let response = llm.chat(&messages).unwrap();
        let elapsed = start.elapsed();

        if let Some(chars) = response.response_chars {
            response_chars.push(chars);
        }

        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    let mut result = BenchmarkResult::from_times("single_prompt", &times);
    if !response_chars.is_empty() {
        let sum: usize = response_chars.iter().sum();
        result.avg_response_chars = Some(sum as f64 / response_chars.len() as f64);
        result.max_response_chars = Some(*response_chars.iter().max().unwrap());
    }
    result
}

fn benchmark_multi_turn_chat(llm: &LLMClient, iterations: usize) -> BenchmarkResult {
    let conversation_turns = [
        "What is Rust?",
        "Why is it fast?",
        "What about memory safety?",
        "How does it compare to C++?",
        "Should I learn it?",
    ];

    let mut times = Vec::with_capacity(iterations);
    let mut response_chars: Vec<usize> = Vec::with_capacity(iterations * conversation_turns.len());

    for _ in 0..iterations {
        let mut messages = vec![json!({
            "role": "system",
            "content": "You are a helpful assistant. Keep responses under 20 words."
        })];

        let start = Instant::now();

        for turn in &conversation_turns {
            messages.push(json!({"role": "user", "content": *turn}));

            let response = llm.chat(&messages).unwrap();
            if let Some(chars) = response.response_chars {
                response_chars.push(chars);
            }
            messages.push(json!({"role": "assistant", "content": response.content}));
        }

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    let mut result = BenchmarkResult::from_times("multi_turn_chat", &times);
    result.turns_per_conversation = Some(conversation_turns.len());
    if !response_chars.is_empty() {
        let sum: usize = response_chars.iter().sum();
        result.avg_response_chars = Some(sum as f64 / response_chars.len() as f64);
        result.max_response_chars = Some(*response_chars.iter().max().unwrap());
    }
    result
}

fn benchmark_parallel_inference(llm: &LLMClient, iterations: usize) -> BenchmarkResult {
    const NUM_PARALLEL: usize = 3;

    let topics_sets = [
        ["Python", "Java", "Rust"],
        ["cats", "dogs", "birds"],
        ["cars", "planes", "boats"],
        ["pizza", "sushi", "tacos"],
        ["mountains", "oceans", "deserts"],
    ];

    let mut times = Vec::with_capacity(iterations);
    let mut response_chars: Vec<usize> = Vec::with_capacity(iterations * NUM_PARALLEL);

    for i in 0..iterations {
        let topics = &topics_sets[i % topics_sets.len()];

        let start = Instant::now();

        // Note: Parallel HTTP requests - not limited by GIL like Python
        let results: Vec<_> = topics
            .par_iter()
            .map(|topic| {
                let messages = vec![json!({
                    "role": "user",
                    "content": format!("In one sentence, describe {}.", topic)
                })];
                llm.chat(&messages)
            })
            .collect();

        for r in results {
            let r = r.unwrap();
            if let Some(chars) = r.response_chars {
                response_chars.push(chars);
            }
        }

        let elapsed = start.elapsed();
        times.push(elapsed.as_secs_f64() * 1000.0);
    }

    let mut result = BenchmarkResult::from_times("parallel_inference", &times);
    result.parallel_calls = Some(NUM_PARALLEL);
    if !response_chars.is_empty() {
        let sum: usize = response_chars.iter().sum();
        result.avg_response_chars = Some(sum as f64 / response_chars.len() as f64);
        result.max_response_chars = Some(*response_chars.iter().max().unwrap());
    }
    result
}

// =============================================================================
// Main
// =============================================================================

#[derive(Serialize)]
struct BenchmarkResults {
    framework: String,
    backend: String,
    model: String,
    config: BenchmarkConfig,
    system: SystemInfo,
    benchmarks: Vec<serde_json::Value>,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut backend = "ollama".to_string();
    let mut model = "phi3".to_string();
    let mut skip_llm = false;
    let mut temperature: f64 = 0.0;
    let mut max_tokens: u32 = 100;
    let mut base_url: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--backend" => {
                backend = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--model" => {
                model = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--base-url" => {
                base_url = args.get(i + 1).cloned();
                i += 2;
            }
            "--skip-llm" => {
                skip_llm = true;
                i += 1;
            }
            "--temperature" => {
                temperature = args
                    .get(i + 1)
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0);
                i += 2;
            }
            "--max-tokens" => {
                max_tokens = args
                    .get(i + 1)
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(100);
                i += 2;
            }
            _ => i += 1,
        }
    }

    println!("{}", "=".repeat(60));
    println!("RustChain Benchmark Suite v2");
    println!("Backend: {} | Model: {}", backend, model);
    println!(
        "Config: temperature={} | max_tokens={}",
        temperature, max_tokens
    );
    if let Some(url) = &base_url {
        println!("Base URL: {}", url);
    }
    println!("{}", "=".repeat(60));
    println!();

    let mut results = BenchmarkResults {
        framework: "rustchain".to_string(),
        backend: backend.clone(),
        model: model.clone(),
        config: BenchmarkConfig {
            temperature,
            max_tokens,
        },
        system: SystemInfo::capture(),
        benchmarks: Vec::new(),
    };

    // Category 1: Framework Overhead
    println!("{}", "=".repeat(40));
    println!("CATEGORY 1: Framework Overhead (No LLM)");
    println!("{}", "=".repeat(40));

    println!("\n[1/6] Workflow Parsing (1000 iterations)...");
    let result = benchmark_workflow_parsing(1000);
    println!(
        "       Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());

    println!("\n[2/6] Chain Execution (100 iterations)...");
    let result = benchmark_chain_execution(100);
    println!(
        "       Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());

    println!("\n[3/6] Large DAG (100 iterations)...");
    let result = benchmark_large_dag(100);
    println!(
        "       Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());

    println!("\n[4/6] Tool Dispatch (500 iterations)...");
    let result = benchmark_tool_dispatch(500);
    println!(
        "       Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());

    println!("\n[5/6] Parallel Execution (50 iterations, 20 tasks)...");
    let result = benchmark_parallel_execution(50);
    println!(
        "       Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());

    println!("\n[6/6] Memory Operations (1000 iterations)...");
    let result = benchmark_memory_operations(1000);
    println!(
        "       Mean: {:.3}ms, Median: {:.3}ms",
        result.mean_ms, result.median_ms
    );
    results
        .benchmarks
        .push(serde_json::to_value(&result).unwrap());

    // Category 2: Real LLM Calls
    if !skip_llm {
        println!("\n{}", "=".repeat(40));
        println!("CATEGORY 2: Real LLM Calls");
        println!("{}", "=".repeat(40));

        let llm = LLMClient::new(&backend, &model, base_url.clone(), temperature, max_tokens);

        println!("\n[7/9] Single Prompt (10 iterations)...");
        let result = benchmark_single_prompt(&llm, 10);
        println!(
            "       Mean: {:.1}ms, Median: {:.1}ms",
            result.mean_ms, result.median_ms
        );
        results
            .benchmarks
            .push(serde_json::to_value(&result).unwrap());

        println!("\n[8/9] Multi-Turn Chat (5 iterations, 5 turns each)...");
        let result = benchmark_multi_turn_chat(&llm, 5);
        println!(
            "       Mean: {:.1}ms, Median: {:.1}ms",
            result.mean_ms, result.median_ms
        );
        results
            .benchmarks
            .push(serde_json::to_value(&result).unwrap());

        println!("\n[9/9] Parallel Inference (5 iterations, 3 parallel)...");
        let result = benchmark_parallel_inference(&llm, 5);
        println!(
            "       Mean: {:.1}ms, Median: {:.1}ms",
            result.mean_ms, result.median_ms
        );
        results
            .benchmarks
            .push(serde_json::to_value(&result).unwrap());
    } else {
        println!("\n[Skipping LLM benchmarks - --skip-llm flag set]");
    }

    println!("\n{}", "=".repeat(60));
    println!("Benchmark Complete");
    println!("{}", "=".repeat(60));

    // Save results
    let output_file = format!("rustchain_results_{}.json", backend);
    fs::write(
        &output_file,
        serde_json::to_string_pretty(&results).unwrap(),
    )
    .unwrap();
    println!("\nResults saved to: {}", output_file);
}
