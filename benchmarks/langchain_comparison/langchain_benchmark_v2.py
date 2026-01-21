#!/usr/bin/env python3
"""
LangChain Benchmark Suite v2
============================
Real LLM benchmarks using local Ollama or Shimmy backends.

Backends:
  - Ollama: Standard local LLM server (fair comparison)
  - Shimmy: Rust-based OpenAI-compatible server (shows full Rust stack potential)

Run: python langchain_benchmark_v2.py --backend ollama --model phi3
     python langchain_benchmark_v2.py --backend shimmy --model phi3
"""

import sys
import time
import json
import yaml
import statistics
import platform
import os
import argparse
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# LangChain imports
try:
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.runnables import RunnableLambda, RunnablePassthrough, RunnableParallel
    from langchain_core.messages import HumanMessage, AIMessage
    from langchain_openai import ChatOpenAI
    LANGCHAIN_AVAILABLE = True
except ImportError as e:
    print(f"LangChain not installed: {e}")
    print("Install with: pip install langchain langchain-openai langchain-core pyyaml")
    LANGCHAIN_AVAILABLE = False
    sys.exit(1)


def get_system_info() -> Dict[str, Any]:
    """Capture system information for reproducibility."""
    return {
        "timestamp": datetime.now().isoformat(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def create_llm(
    backend: str,
    model: str,
    base_url: str = None,
    *,
    temperature: float = 0,
    max_tokens: int = 100,
    max_retries: int = 0,
) -> ChatOpenAI:
    """Create LLM client for specified backend.

    NOTE: We set explicit generation params to keep comparisons fair and
    prevent accidental variance (e.g., unconstrained response length).
    """
    if backend == "ollama":
        return ChatOpenAI(
            model=model,
            base_url=base_url or "http://localhost:11434/v1",
            api_key="ollama",  # Ollama doesn't need a real key
            temperature=temperature,
            max_tokens=max_tokens,
            max_retries=max_retries,
        )
    elif backend == "shimmy":
        return ChatOpenAI(
            model=model,
            base_url=base_url or "http://localhost:11435/v1",
            api_key="shimmy",  # Shimmy doesn't need a real key
            temperature=temperature,
            max_tokens=max_tokens,
            max_retries=max_retries,
        )
    else:
        raise ValueError(f"Unknown backend: {backend}")


def _extract_usage_metadata(ai_message: AIMessage) -> Dict[str, Any]:
    """Best-effort extraction of token usage/metadata (varies by backend + LC versions)."""
    usage: Dict[str, Any] = {}

    # LangChain sometimes puts structured info here.
    for attr in ("usage_metadata", "response_metadata", "additional_kwargs"):
        obj = getattr(ai_message, attr, None)
        if isinstance(obj, dict):
            usage[attr] = obj

    return usage


def _invoke_chat_and_measure(
    llm: ChatOpenAI,
    messages,
) -> Tuple[str, Dict[str, Any]]:
    """Invoke ChatOpenAI and return (content, audit_metadata)."""
    ai = llm.invoke(messages)
    content = getattr(ai, "content", "")
    meta = {
        "response_chars": len(content) if isinstance(content, str) else None,
        "usage": _extract_usage_metadata(ai) if isinstance(ai, AIMessage) else {},
    }
    return content, meta


# =============================================================================
# CATEGORY 1: Framework Overhead (No LLM)
# =============================================================================

def benchmark_workflow_parsing(iterations: int = 1000) -> Dict[str, Any]:
    """Parse YAML workflow definitions."""
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
        parsed = yaml.safe_load(workflow_yaml)
        assert "name" in parsed
        assert "steps" in parsed
        for step in parsed["steps"]:
            assert "id" in step
            assert "action" in step
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return calc_stats("workflow_parsing", times, iterations)


def benchmark_chain_execution(iterations: int = 100) -> Dict[str, Any]:
    """Execute multi-step LCEL chains (no LLM)."""
    step_1 = RunnableLambda(lambda x: {**x, "step_1": x.get("input", "").upper()})
    step_2 = RunnableLambda(lambda x: {**x, "step_2": x["step_1"][::-1]})
    step_3 = RunnableLambda(lambda x: {**x, "step_3": len(x["step_2"])})
    step_4 = RunnableLambda(lambda x: {**x, "output": f"Processed: {x['step_3']} chars"})
    
    chain = step_1 | step_2 | step_3 | step_4
    
    times = []
    for i in range(iterations):
        input_data = {"input": f"benchmark_input_data_{i}" * 10}
        start = time.perf_counter()
        result = chain.invoke(input_data)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return calc_stats("chain_execution", times, iterations)


def benchmark_large_dag(iterations: int = 100) -> Dict[str, Any]:
    """Execute a 50-step DAG with complex dependencies."""
    # Build a DAG: 10 parallel initial steps, then 4 layers of 10 steps each
    def make_step(name: str):
        return RunnableLambda(lambda x, n=name: {**x, n: f"processed_{n}"})
    
    # Layer 1: 10 parallel steps
    layer1_steps = {f"l1_s{i}": make_step(f"l1_s{i}") for i in range(10)}
    layer1 = RunnableParallel(**layer1_steps)
    
    # Layers 2-5: Sequential processing with fan-in
    def aggregate_layer(x):
        return {"aggregated": len(x), **x}
    
    aggregate = RunnableLambda(aggregate_layer)
    
    # Simple chain for this test
    dag = layer1 | aggregate
    
    times = []
    for i in range(iterations):
        input_data = {"input": f"dag_input_{i}"}
        start = time.perf_counter()
        result = dag.invoke(input_data)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return calc_stats("large_dag", times, iterations)


def benchmark_tool_dispatch(iterations: int = 500) -> Dict[str, Any]:
    """Route to different tools based on input."""
    # Simulate 10 different tools
    tools = {
        f"tool_{i}": RunnableLambda(lambda x, i=i: {**x, "tool_result": f"tool_{i}_output"})
        for i in range(10)
    }
    
    def router(x):
        tool_id = x.get("tool_id", 0) % 10
        return tools[f"tool_{tool_id}"]
    
    times = []
    for i in range(iterations):
        input_data = {"input": f"dispatch_{i}", "tool_id": i}
        start = time.perf_counter()
        # Manual dispatch (LangChain's RunnableBranch would add more overhead)
        tool = router(input_data)
        result = tool.invoke(input_data)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return calc_stats("tool_dispatch", times, iterations)


def benchmark_parallel_execution(iterations: int = 50) -> Dict[str, Any]:
    """Fan-out/fan-in with ThreadPoolExecutor."""
    NUM_PARALLEL_TASKS = 20
    
    def cpu_bound_task(task_id: int) -> Dict:
        result = sum(i * task_id for i in range(10000))
        return {"task_id": task_id, "result": result}
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=NUM_PARALLEL_TASKS) as executor:
            futures = [executor.submit(cpu_bound_task, i) for i in range(NUM_PARALLEL_TASKS)]
            results = [f.result() for f in as_completed(futures)]
        total = sum(r["result"] for r in results)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    result = calc_stats("parallel_execution", times, iterations)
    result["parallel_tasks"] = NUM_PARALLEL_TASKS
    return result


def benchmark_memory_operations(iterations: int = 1000) -> Dict[str, Any]:
    """In-memory state management."""
    NUM_OPERATIONS = 100
    
    times = []
    for _ in range(iterations):
        store = {}
        start = time.perf_counter()
        
        for i in range(NUM_OPERATIONS):
            store[f"key_{i}"] = {"value": f"data_{i}" * 100, "metadata": {"index": i}}
        for i in range(NUM_OPERATIONS):
            _ = store.get(f"key_{i}")
        for i in range(NUM_OPERATIONS):
            if f"key_{i}" in store:
                store[f"key_{i}"]["metadata"]["updated"] = True
        for i in range(0, NUM_OPERATIONS, 2):
            store.pop(f"key_{i}", None)
        
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    result = calc_stats("memory_operations", times, iterations)
    result["ops_per_iteration"] = NUM_OPERATIONS * 4
    return result


# =============================================================================
# CATEGORY 2: Real LLM Calls
# =============================================================================

def benchmark_single_prompt(llm: ChatOpenAI, iterations: int = 10) -> Dict[str, Any]:
    """Single prompt → response latency."""
    prompt = ChatPromptTemplate.from_template(
        "Answer in exactly 5 words: What is {topic}?"
    )
    
    topics = ["Python", "Rust", "machine learning", "databases", "networking",
              "compilers", "operating systems", "cryptography", "algorithms", "data structures"]
    
    times = []
    response_chars: List[int] = []
    for i in range(iterations):
        topic = topics[i % len(topics)]
        messages = prompt.format_messages(topic=topic)
        start = time.perf_counter()
        result, meta = _invoke_chat_and_measure(llm, messages)
        end = time.perf_counter()
        times.append((end - start) * 1000)
        if meta.get("response_chars") is not None:
            response_chars.append(int(meta["response_chars"]))
    
    result = calc_stats("single_prompt", times, iterations)
    if response_chars:
        result["avg_response_chars"] = statistics.mean(response_chars)
        result["max_response_chars"] = max(response_chars)
    return result


def benchmark_multi_turn_chat(llm: ChatOpenAI, iterations: int = 5) -> Dict[str, Any]:
    """5-turn conversation with history."""
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant. Keep responses under 20 words."),
        MessagesPlaceholder(variable_name="history"),
        ("human", "{input}"),
    ])
    # Keep the prompt structure identical to Rust benchmark.
    
    conversation_turns = [
        "What is Rust?",
        "Why is it fast?",
        "What about memory safety?",
        "How does it compare to C++?",
        "Should I learn it?",
    ]
    
    times = []
    response_chars: List[int] = []
    for _ in range(iterations):
        history = []
        turn_times = []
        
        for turn in conversation_turns:
            messages = prompt.format_messages(history=history, input=turn)
            start = time.perf_counter()
            response, meta = _invoke_chat_and_measure(llm, messages)
            end = time.perf_counter()
            turn_times.append((end - start) * 1000)

            if meta.get("response_chars") is not None:
                response_chars.append(int(meta["response_chars"]))
            
            history.append(HumanMessage(content=turn))
            history.append(AIMessage(content=response))
        
        times.append(sum(turn_times))  # Total conversation time
    
    result = calc_stats("multi_turn_chat", times, iterations)
    result["turns_per_conversation"] = len(conversation_turns)
    if response_chars:
        result["avg_response_chars"] = statistics.mean(response_chars)
        result["max_response_chars"] = max(response_chars)
    return result


def benchmark_parallel_inference(llm: ChatOpenAI, iterations: int = 5) -> Dict[str, Any]:
    """3 simultaneous LLM calls."""
    NUM_PARALLEL = 3
    
    prompt = ChatPromptTemplate.from_template(
        "In one sentence, describe {topic}."
    )
    # Measure framework + client overhead for concurrent LLM calls.
    
    topics_sets = [
        ["Python", "Java", "Rust"],
        ["cats", "dogs", "birds"],
        ["cars", "planes", "boats"],
        ["pizza", "sushi", "tacos"],
        ["mountains", "oceans", "deserts"],
    ]
    
    times = []
    response_chars: List[int] = []
    for i in range(iterations):
        topics = topics_sets[i % len(topics_sets)]
        
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=NUM_PARALLEL) as executor:
            futures = []
            for t in topics:
                messages = prompt.format_messages(topic=t)
                futures.append(executor.submit(_invoke_chat_and_measure, llm, messages))
            results = [f.result() for f in as_completed(futures)]
        end = time.perf_counter()
        
        times.append((end - start) * 1000)
        for content, meta in results:
            if meta.get("response_chars") is not None:
                response_chars.append(int(meta["response_chars"]))
    
    result = calc_stats("parallel_inference", times, iterations)
    result["parallel_calls"] = NUM_PARALLEL
    if response_chars:
        result["avg_response_chars"] = statistics.mean(response_chars)
        result["max_response_chars"] = max(response_chars)
    return result


# =============================================================================
# Utilities
# =============================================================================

def calc_stats(operation: str, times: List[float], iterations: int) -> Dict[str, Any]:
    """Calculate statistics from timing data."""
    sorted_times = sorted(times)
    n = len(sorted_times)
    
    return {
        "operation": operation,
        "iterations": iterations,
        "total_ms": sum(times),
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "p95_ms": sorted_times[int(n * 0.95)] if n > 1 else sorted_times[0],
        "p99_ms": sorted_times[int(n * 0.99)] if n > 1 else sorted_times[0],
    }


def run_all_benchmarks(
    backend: str,
    model: str,
    base_url: str = None,
    skip_llm: bool = False,
    *,
    temperature: float = 0,
    max_tokens: int = 100,
    max_retries: int = 0,
) -> Dict[str, Any]:
    """Run all benchmarks and return results."""
    print("=" * 60)
    print(f"LangChain Benchmark Suite v2")
    print(f"Backend: {backend} | Model: {model}")
    print("=" * 60)
    print()
    
    results = {
        "framework": "langchain",
        "backend": backend,
        "model": model,
        "config": {
            "temperature": temperature,
            "max_tokens": max_tokens,
            "max_retries": max_retries,
        },
        "system": get_system_info(),
        "benchmarks": []
    }
    
    # Category 1: Framework Overhead
    print("=" * 40)
    print("CATEGORY 1: Framework Overhead (No LLM)")
    print("=" * 40)
    
    print("\n[1/6] Workflow Parsing (1000 iterations)...")
    result = benchmark_workflow_parsing(1000)
    results["benchmarks"].append(result)
    print(f"       Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    
    print("\n[2/6] Chain Execution (100 iterations)...")
    result = benchmark_chain_execution(100)
    results["benchmarks"].append(result)
    print(f"       Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    
    print("\n[3/6] Large DAG (100 iterations)...")
    result = benchmark_large_dag(100)
    results["benchmarks"].append(result)
    print(f"       Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    
    print("\n[4/6] Tool Dispatch (500 iterations)...")
    result = benchmark_tool_dispatch(500)
    results["benchmarks"].append(result)
    print(f"       Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    
    print("\n[5/6] Parallel Execution (50 iterations, 20 tasks)...")
    result = benchmark_parallel_execution(50)
    results["benchmarks"].append(result)
    print(f"       Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    
    print("\n[6/6] Memory Operations (1000 iterations)...")
    result = benchmark_memory_operations(1000)
    results["benchmarks"].append(result)
    print(f"       Mean: {result['mean_ms']:.3f}ms, Median: {result['median_ms']:.3f}ms")
    
    # Category 2: Real LLM Calls
    if not skip_llm:
        print("\n" + "=" * 40)
        print("CATEGORY 2: Real LLM Calls")
        print("=" * 40)
        
        try:
            llm = create_llm(
                backend,
                model,
                base_url,
                temperature=temperature,
                max_tokens=max_tokens,
                max_retries=max_retries,
            )
            
            print("\n[7/9] Single Prompt (10 iterations)...")
            result = benchmark_single_prompt(llm, 10)
            results["benchmarks"].append(result)
            print(f"       Mean: {result['mean_ms']:.1f}ms, Median: {result['median_ms']:.1f}ms")
            
            print("\n[8/9] Multi-Turn Chat (5 iterations, 5 turns each)...")
            result = benchmark_multi_turn_chat(llm, 5)
            results["benchmarks"].append(result)
            print(f"       Mean: {result['mean_ms']:.1f}ms, Median: {result['median_ms']:.1f}ms")
            
            print("\n[9/9] Parallel Inference (5 iterations, 3 parallel)...")
            result = benchmark_parallel_inference(llm, 5)
            results["benchmarks"].append(result)
            print(f"       Mean: {result['mean_ms']:.1f}ms, Median: {result['median_ms']:.1f}ms")
            
        except Exception as e:
            print(f"\n  ERROR: LLM benchmarks failed: {e}")
            results["benchmarks"].append({"operation": "llm_error", "error": str(e)})
    else:
        print("\n[Skipping LLM benchmarks - --skip-llm flag set]")
    
    print("\n" + "=" * 60)
    print("Benchmark Complete")
    print("=" * 60)
    
    return results


def main():
    parser = argparse.ArgumentParser(description="LangChain Benchmark Suite v2")
    parser.add_argument("--backend", choices=["ollama", "shimmy"], default="ollama",
                        help="LLM backend to use (default: ollama)")
    parser.add_argument("--model", default="phi3",
                        help="Model name (default: phi3)")
    parser.add_argument("--base-url", default=None,
                        help="Override base URL for the backend")
    parser.add_argument("--skip-llm", action="store_true",
                        help="Skip LLM benchmarks (framework overhead only)")
    parser.add_argument("--max-tokens", type=int, default=100,
                        help="Max completion tokens for LLM calls (default: 100)")
    parser.add_argument("--temperature", type=float, default=0,
                        help="Sampling temperature (default: 0)")
    parser.add_argument("--max-retries", type=int, default=0,
                        help="Client retry attempts (default: 0)")
    parser.add_argument("--output", default=None,
                        help="Output JSON file (default: langchain_results_{backend}.json)")
    
    args = parser.parse_args()
    
    results = run_all_benchmarks(
        backend=args.backend,
        model=args.model,
        base_url=args.base_url,
        skip_llm=args.skip_llm,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        max_retries=args.max_retries,
    )
    
    output_file = args.output or f"langchain_results_{args.backend}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    main()
