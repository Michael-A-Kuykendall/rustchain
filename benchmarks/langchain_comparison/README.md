# RustChain vs LangChain: Head-to-Head Benchmark

This directory contains a **reproducible, fair comparison** between RustChain and LangChain.

## What We Test

Both frameworks perform the **exact same operations**:

1. **Workflow Parsing**: Parse YAML workflow definitions into execution plans
2. **Multi-Step Chains**: Execute a sequence of dependent operations
3. **Parallel Execution**: Fan-out/fan-in patterns with concurrent steps
4. **LLM Calls** (optional): Same prompts to same model via same API

## Running the Benchmark

### Prerequisites

```bash
# Python side (LangChain)
pip install langchain langchain-openai pyyaml

# Rust side (RustChain) - already built if you're in this repo
cargo build --release
```

### Run the Comparison

```bash
# Full benchmark (requires OPENAI_API_KEY for LLM tests)
./run_benchmark.sh

# Framework-only benchmark (no API key needed)
./run_benchmark.sh --no-llm
```

## Benchmark Results Format

The benchmark outputs:
- System information (CPU, RAM, OS)
- Individual operation timings
- Statistical summary (mean, median, p95, p99)
- Side-by-side comparison table

## Why These Tests?

| Test | What It Measures | Why It Matters |
|------|------------------|----------------|
| Workflow Parsing | Framework startup overhead | Every execution pays this cost |
| Multi-Step Chains | Sequential orchestration | Common pattern in agent workflows |
| Parallel Execution | Concurrency handling | Rust has no GIL, Python does |
| LLM Calls | End-to-end real-world | Total time users actually experience |

## Reproducibility

All tests are deterministic (except LLM responses). Anyone can:
1. Clone this repo
2. Run the benchmark
3. Verify the results on their own hardware

The benchmark captures system info so results can be compared across machines.
