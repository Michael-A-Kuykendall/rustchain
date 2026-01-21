# RustChain vs LangChain Benchmark Report

**Generated:** 2025-12-17T11:54:55.596539

## Test Environment

| Metric | Value |
|--------|-------|
| Platform | Windows-11-10.0.26200-SP0 |
| CPU Cores | 24 |
| Python Version | 3.13.7 |
| Rust Version | 1.70+ |
| Backend | ollama |
| Model | phi3 |
| LLM temperature | LC=0.0 / RC=N/A |
| LLM max_tokens | LC=100 / RC=N/A |

## Performance Comparison

| Benchmark | LangChain (mean) | RustChain (mean) | Speedup |
|-----------|------------------:|----------------:|:--------|
| Workflow Parsing | 1.239 ms | 0.038 ms | **32.8x faster** |
| Chain Execution | 0.437 ms | 0.001 ms | **398.9x faster** |
| Large Dag | 2.251 ms | 0.099 ms | **22.7x faster** |
| Tool Dispatch | 0.085 ms | 0.000 ms | **1160.8x faster** |
| Parallel Execution | 9.965 ms | 0.035 ms | **283.2x faster** |
| Memory Operations | 0.075 ms | 0.092 ms | **1.2x slower** |
| Single Prompt | 346.167 ms | 154.818 ms | **2.2x faster** |
| Multi Turn Chat | 18792.119 ms | 3620.791 ms | **5.2x faster** |
| Parallel Inference | 1442.192 ms | 1589.397 ms | **1.1x slower** |

## Summary

**Average speedup (mean, excluding missing results):** 211.9x

## Detailed Results

### Workflow Parsing

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 1.239ms | 0.038ms |
| Median | 1.235ms | 0.039ms |
| Min | 1.201ms | 0.023ms |
| Max | 1.751ms | 0.347ms |
| P95 | 1.264ms | 0.048ms |
| P99 | 1.288ms | 0.080ms |
| Stdev | 0.025ms | 0.019ms |
| Avg Response Chars | N/A | N/A |
| Max Response Chars | N/A | N/A |

### Chain Execution

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 0.437ms | 0.001ms |
| Median | 0.429ms | 0.001ms |
| Min | 0.422ms | 0.001ms |
| Max | 0.845ms | 0.007ms |
| P95 | 0.456ms | 0.001ms |
| P99 | 0.845ms | 0.007ms |
| Stdev | 0.045ms | 0.001ms |
| Avg Response Chars | N/A | N/A |
| Max Response Chars | N/A | N/A |

### Large Dag

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 2.251ms | 0.099ms |
| Median | 2.160ms | 0.085ms |
| Min | 2.086ms | 0.020ms |
| Max | 3.190ms | 0.774ms |
| P95 | 2.688ms | 0.171ms |
| P99 | 3.190ms | 0.774ms |
| Stdev | 0.183ms | 0.085ms |
| Avg Response Chars | N/A | N/A |
| Max Response Chars | N/A | N/A |

### Tool Dispatch

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 0.085ms | 0.000ms |
| Median | 0.083ms | 0.000ms |
| Min | 0.081ms | 0.000ms |
| Max | 0.142ms | 0.001ms |
| P95 | 0.090ms | 0.000ms |
| P99 | 0.113ms | 0.000ms |
| Stdev | 0.005ms | 0.000ms |
| Avg Response Chars | N/A | N/A |
| Max Response Chars | N/A | N/A |

### Parallel Execution

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 9.965ms | 0.035ms |
| Median | 10.004ms | 0.021ms |
| Min | 9.576ms | 0.010ms |
| Max | 10.433ms | 0.160ms |
| P95 | 10.280ms | 0.148ms |
| P99 | 10.433ms | 0.160ms |
| Stdev | 0.204ms | 0.037ms |
| Avg Response Chars | N/A | N/A |
| Max Response Chars | N/A | N/A |

### Memory Operations

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 0.075ms | 0.092ms |
| Median | 0.074ms | 0.069ms |
| Min | 0.072ms | 0.059ms |
| Max | 0.130ms | 0.786ms |
| P95 | 0.078ms | 0.158ms |
| P99 | 0.093ms | 0.238ms |
| Stdev | 0.004ms | 0.047ms |
| Avg Response Chars | N/A | N/A |
| Max Response Chars | N/A | N/A |

### Single Prompt

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 346.167ms | 154.818ms |
| Median | 102.407ms | 118.397ms |
| Min | 71.400ms | 90.193ms |
| Max | 2513.580ms | 446.412ms |
| P95 | 2513.580ms | 446.412ms |
| P99 | 2513.580ms | 446.412ms |
| Stdev | 761.865ms | 105.326ms |
| Avg Response Chars | 48.4 | N/A |
| Max Response Chars | 83 | N/A |

### Multi Turn Chat

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 18792.119ms | 3620.791ms |
| Median | 22463.524ms | 3627.715ms |
| Min | 3428.700ms | 3542.640ms |
| Max | 22916.074ms | 3701.772ms |
| P95 | 22916.074ms | 3701.772ms |
| P99 | 22916.074ms | 3701.772ms |
| Stdev | 8591.956ms | 57.176ms |
| Avg Response Chars | 1728.64 | N/A |
| Max Response Chars | 4046 | N/A |

### Parallel Inference

| Metric | LangChain | RustChain |
|--------|-----------|-----------|
| Mean | 1442.192ms | 1589.397ms |
| Median | 1344.913ms | 1442.248ms |
| Min | 821.053ms | 870.922ms |
| Max | 2595.828ms | 3007.723ms |
| P95 | 2595.828ms | 3007.723ms |
| P99 | 2595.828ms | 3007.723ms |
| Stdev | 700.900ms | 843.902ms |
| Avg Response Chars | 173 | N/A |
| Max Response Chars | 268 | N/A |

## Methodology

This benchmark compares equivalent operations between LangChain (Python) and RustChain (Rust).

The suite contains two categories:

- **Framework overhead** (no LLM): parsing, orchestration, parallel fan-out/fan-in, and state operations
- **Real LLM calls**: single prompt, multi-turn chat, and parallel inference via an OpenAI-compatible local endpoint

All results shown are wall-clock latencies measured in milliseconds.

## Integrity / Anti-Performance-Theater Checks

This report is generated directly from raw JSON artifacts. Recommended checks:

- Confirm **same backend + model** across both JSONs
- Confirm **same temperature + max_tokens** in the `config` section
- Check `avg_response_chars`/`max_response_chars` for LLM benchmarks; large skews usually indicate unequal output length
- Ensure both runs complete without errors (no missing operations, no HTTP errors)

## Reproduce These Results

```bash
# Prereq: start Ollama locally (default: http://localhost:11434)
# and ensure the model is present (e.g., `ollama pull phi3`).

cd benchmarks/langchain_comparison

# RustChain
cargo build --release --bin rustchain-benchmark-v2 --features llm
./target/release/rustchain-benchmark-v2 --backend ollama --model phi3 --temperature 0 --max-tokens 100

# LangChain (in your venv)
python langchain_benchmark_v2.py --backend ollama --model phi3 --temperature 0 --max-tokens 100 --max-retries 0

# Generate report
python generate_report.py --langchain langchain_results_ollama.json --rustchain rustchain_results_ollama.json --output benchmark_report.md
```
