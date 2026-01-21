#!/usr/bin/env python3
"""
LangChain Benchmark Suite
=========================
Equivalent workloads to RustChain for fair comparison.

Run: python langchain_benchmark.py [--no-llm]
"""

import sys
import time
import json
import yaml
import statistics
import platform
import os
from datetime import datetime
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Check for --no-llm flag
NO_LLM = "--no-llm" in sys.argv

# LangChain imports
try:
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.runnables import RunnablePassthrough, RunnableParallel
    if not NO_LLM:
        from langchain_openai import ChatOpenAI
    LANGCHAIN_AVAILABLE = True
except ImportError as e:
    print(f"LangChain not installed: {e}")
    print("Install with: pip install langchain langchain-openai langchain-core")
    LANGCHAIN_AVAILABLE = False


def get_system_info() -> Dict[str, Any]:
    """Capture system information for reproducibility."""
    return {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def benchmark_workflow_parsing(iterations: int = 1000) -> Dict[str, float]:
    """
    Benchmark: Parse YAML workflow definitions
    
    This measures the framework's ability to load and validate workflow definitions.
    """
    # Sample workflow that both frameworks can parse
    workflow_yaml = """
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
"""
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        # Parse YAML (what LangChain does when loading configs)
        parsed = yaml.safe_load(workflow_yaml)
        # Validate structure (basic schema check)
        assert "name" in parsed
        assert "steps" in parsed
        for step in parsed["steps"]:
            assert "id" in step
            assert "action" in step
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    
    return {
        "operation": "workflow_parsing",
        "iterations": iterations,
        "total_ms": sum(times),
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "p95_ms": sorted(times)[int(len(times) * 0.95)],
        "p99_ms": sorted(times)[int(len(times) * 0.99)],
    }


def benchmark_chain_execution(iterations: int = 100) -> Dict[str, float]:
    """
    Benchmark: Execute multi-step processing chains using LangChain LCEL
    
    This measures LangChain's orchestration overhead with Runnables.
    """
    if not LANGCHAIN_AVAILABLE:
        return {"error": "LangChain not available"}
    
    from langchain_core.runnables import RunnableLambda, RunnablePassthrough
    
    # Create LangChain Runnables for each step
    step_1 = RunnableLambda(lambda x: {**x, "step_1": x.get("input", "").upper()})
    step_2 = RunnableLambda(lambda x: {**x, "step_2": x["step_1"][::-1]})
    step_3 = RunnableLambda(lambda x: {**x, "step_3": len(x["step_2"])})
    step_4 = RunnableLambda(lambda x: {**x, "output": f"Processed: {x['step_3']} chars"})
    
    # Chain them using LCEL pipe operator
    chain = step_1 | step_2 | step_3 | step_4
    
    times = []
    for i in range(iterations):
        input_data = {"input": f"benchmark_input_data_{i}" * 10}
        
        start = time.perf_counter()
        result = chain.invoke(input_data)
        end = time.perf_counter()
        
        times.append((end - start) * 1000)
    
    return {
        "operation": "chain_execution",
        "iterations": iterations,
        "total_ms": sum(times),
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "p95_ms": sorted(times)[int(len(times) * 0.95)],
        "p99_ms": sorted(times)[int(len(times) * 0.99)],
    }


def benchmark_parallel_execution(iterations: int = 50) -> Dict[str, float]:
    """
    Benchmark: Execute parallel tasks (fan-out/fan-in)
    
    This measures concurrency handling. Python's GIL limits true parallelism.
    """
    NUM_PARALLEL_TASKS = 20
    
    def cpu_bound_task(task_id: int) -> Dict:
        """Simulate CPU-bound work"""
        result = 0
        for i in range(10000):
            result += i * task_id
        return {"task_id": task_id, "result": result}
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        
        # Fan-out: Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=NUM_PARALLEL_TASKS) as executor:
            futures = [executor.submit(cpu_bound_task, i) for i in range(NUM_PARALLEL_TASKS)]
            results = [f.result() for f in as_completed(futures)]
        
        # Fan-in: Aggregate results
        total = sum(r["result"] for r in results)
        
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return {
        "operation": "parallel_execution",
        "parallel_tasks": NUM_PARALLEL_TASKS,
        "iterations": iterations,
        "total_ms": sum(times),
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "p95_ms": sorted(times)[int(len(times) * 0.95)],
        "p99_ms": sorted(times)[int(len(times) * 0.99)],
    }


def benchmark_memory_operations(iterations: int = 1000) -> Dict[str, float]:
    """
    Benchmark: In-memory state management
    
    This measures read/write performance for agent state.
    """
    NUM_OPERATIONS = 100
    
    times = []
    for _ in range(iterations):
        store = {}
        
        start = time.perf_counter()
        
        # Write operations
        for i in range(NUM_OPERATIONS):
            store[f"key_{i}"] = {"value": f"data_{i}" * 100, "metadata": {"index": i}}
        
        # Read operations
        for i in range(NUM_OPERATIONS):
            _ = store.get(f"key_{i}")
        
        # Update operations
        for i in range(NUM_OPERATIONS):
            if f"key_{i}" in store:
                store[f"key_{i}"]["metadata"]["updated"] = True
        
        # Delete operations
        for i in range(0, NUM_OPERATIONS, 2):
            store.pop(f"key_{i}", None)
        
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return {
        "operation": "memory_operations",
        "ops_per_iteration": NUM_OPERATIONS * 4,
        "iterations": iterations,
        "total_ms": sum(times),
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "p95_ms": sorted(times)[int(len(times) * 0.95)],
        "p99_ms": sorted(times)[int(len(times) * 0.99)],
    }


def benchmark_llm_chain(iterations: int = 5) -> Dict[str, float]:
    """
    Benchmark: Real LLM calls with LangChain
    
    This measures end-to-end latency including actual API calls.
    Requires OPENAI_API_KEY environment variable.
    """
    if NO_LLM:
        return {"operation": "llm_chain", "skipped": True, "reason": "--no-llm flag set"}
    
    if not LANGCHAIN_AVAILABLE:
        return {"operation": "llm_chain", "error": "LangChain not available"}
    
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return {"operation": "llm_chain", "skipped": True, "reason": "OPENAI_API_KEY not set"}
    
    try:
        # Create a simple chain
        model = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
        prompt = ChatPromptTemplate.from_template(
            "Answer in exactly 3 words: What is {topic}?"
        )
        chain = prompt | model | StrOutputParser()
        
        topics = ["Python", "Rust", "benchmarking", "performance", "testing"]
        times = []
        
        for i in range(iterations):
            topic = topics[i % len(topics)]
            
            start = time.perf_counter()
            result = chain.invoke({"topic": topic})
            end = time.perf_counter()
            
            times.append((end - start) * 1000)
        
        return {
            "operation": "llm_chain",
            "model": "gpt-3.5-turbo",
            "iterations": iterations,
            "total_ms": sum(times),
            "mean_ms": statistics.mean(times),
            "median_ms": statistics.median(times),
            "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
            "min_ms": min(times),
            "max_ms": max(times),
        }
        
    except Exception as e:
        return {"operation": "llm_chain", "error": str(e)}


def run_all_benchmarks() -> Dict[str, Any]:
    """Run all benchmarks and return results."""
    print("=" * 60)
    print("LangChain Benchmark Suite")
    print("=" * 60)
    print()
    
    results = {
        "framework": "langchain",
        "system": get_system_info(),
        "benchmarks": []
    }
    
    # Benchmark 1: Workflow Parsing
    print("Running: Workflow Parsing (1000 iterations)...")
    result = benchmark_workflow_parsing(1000)
    results["benchmarks"].append(result)
    print(f"  Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    print()
    
    # Benchmark 2: Chain Execution
    print("Running: Chain Execution (100 iterations)...")
    result = benchmark_chain_execution(100)
    results["benchmarks"].append(result)
    if "error" not in result:
        print(f"  Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    else:
        print(f"  Error: {result['error']}")
    print()
    
    # Benchmark 3: Parallel Execution
    print("Running: Parallel Execution (50 iterations, 20 parallel tasks)...")
    result = benchmark_parallel_execution(50)
    results["benchmarks"].append(result)
    print(f"  Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    print()
    
    # Benchmark 4: Memory Operations
    print("Running: Memory Operations (1000 iterations)...")
    result = benchmark_memory_operations(1000)
    results["benchmarks"].append(result)
    print(f"  Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    print()
    
    # Benchmark 5: LLM Chain (optional)
    print("Running: LLM Chain (5 iterations)...")
    result = benchmark_llm_chain(5)
    results["benchmarks"].append(result)
    if "skipped" in result:
        print(f"  Skipped: {result['reason']}")
    elif "error" in result:
        print(f"  Error: {result['error']}")
    else:
        print(f"  Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    print()
    
    print("=" * 60)
    print("Benchmark Complete")
    print("=" * 60)
    
    return results


if __name__ == "__main__":
    results = run_all_benchmarks()
    
    # Save results to JSON
    output_file = "langchain_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
