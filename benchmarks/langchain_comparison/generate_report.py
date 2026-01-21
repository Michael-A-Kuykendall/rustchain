#!/usr/bin/env python3
"""Benchmark Report Generator (v2).

Generates a professional, reproducible comparison report from benchmark JSON
artifacts produced by:
    - rustchain_benchmark_v2.rs
    - langchain_benchmark_v2.py
"""

import json
import sys
import argparse
from datetime import datetime
from typing import Dict, Any, List

def load_results(filename: str) -> Dict[str, Any]:
    """Load benchmark results from JSON file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: {filename} not found. Run benchmarks first.")
        sys.exit(1)

def calculate_speedup(langchain_ms: float, rustchain_ms: float) -> str:
    """Calculate speedup factor."""
    if rustchain_ms == 0:
        return "∞"
    speedup = langchain_ms / rustchain_ms
    if speedup >= 1:
        return f"{speedup:.1f}x faster"
    else:
        return f"{1/speedup:.1f}x slower"

def generate_report(langchain: Dict, rustchain: Dict) -> str:
    """Generate markdown comparison report."""
    
    report = []
    report.append("# RustChain vs LangChain Benchmark Report")
    report.append("")
    report.append(f"**Generated:** {datetime.now().isoformat()}")
    report.append("")
    
    # System Info
    report.append("## Test Environment")
    report.append("")
    report.append("| Metric | Value |")
    report.append("|--------|-------|")
    
    lc_sys = langchain.get("system", {})
    rc_sys = rustchain.get("system", {})
    
    report.append(f"| Platform | {lc_sys.get('platform', 'Unknown')} |")
    report.append(f"| CPU Cores | {lc_sys.get('cpu_count', 'Unknown')} |")
    report.append(f"| Python Version | {lc_sys.get('python_version', 'N/A')} |")
    report.append(f"| Rust Version | {rc_sys.get('rust_version', 'N/A')} |")

    lc_cfg = langchain.get("config", {})
    rc_cfg = rustchain.get("config", {})
    report.append(f"| Backend | {langchain.get('backend', 'Unknown')} |")
    report.append(f"| Model | {langchain.get('model', 'Unknown')} |")
    report.append(f"| LLM temperature | LC={lc_cfg.get('temperature', 'N/A')} / RC={rc_cfg.get('temperature', 'N/A')} |")
    report.append(f"| LLM max_tokens | LC={lc_cfg.get('max_tokens', 'N/A')} / RC={rc_cfg.get('max_tokens', 'N/A')} |")
    report.append("")
    
    # Results Comparison
    report.append("## Performance Comparison")
    report.append("")
    report.append("| Benchmark | LangChain (mean) | RustChain (mean) | Speedup |")
    report.append("|-----------|------------------:|----------------:|:--------|")
    
    # Build lookup maps
    lc_benchmarks = {b["operation"]: b for b in langchain.get("benchmarks", []) if "operation" in b}
    rc_benchmarks = {b["operation"]: b for b in rustchain.get("benchmarks", []) if "operation" in b}
    
    operations = [
        "workflow_parsing",
        "chain_execution",
        "large_dag",
        "tool_dispatch",
        "parallel_execution",
        "memory_operations",
        "single_prompt",
        "multi_turn_chat",
        "parallel_inference",
    ]
    
    speedups = []
    
    for op in operations:
        lc = lc_benchmarks.get(op, {})
        rc = rc_benchmarks.get(op, {})
        
        # Handle skipped benchmarks
        if lc.get("skipped") or rc.get("skipped"):
            report.append(f"| {op.replace('_', ' ').title()} | Skipped | Skipped | N/A |")
            continue
        
        if "error" in lc or "error" in rc:
            report.append(f"| {op.replace('_', ' ').title()} | Error | Error | N/A |")
            continue
        
        lc_mean = lc.get("mean_ms", 0)
        rc_mean = rc.get("mean_ms", 0)
        
        if lc_mean > 0 and rc_mean > 0:
            speedup = calculate_speedup(lc_mean, rc_mean)
            speedup_factor = lc_mean / rc_mean
            speedups.append(speedup_factor)
        else:
            speedup = "N/A"
        
        report.append(f"| {op.replace('_', ' ').title()} | {lc_mean:.3f} ms | {rc_mean:.3f} ms | **{speedup}** |")
    
    report.append("")
    
    # Summary
    if speedups:
        avg_speedup = sum(speedups) / len(speedups)
        report.append("## Summary")
        report.append("")
        report.append(f"**Average speedup (mean, excluding missing results):** {avg_speedup:.1f}x")
        report.append("")
    
    # Detailed Results
    report.append("## Detailed Results")
    report.append("")
    
    for op in operations:
        lc = lc_benchmarks.get(op, {})
        rc = rc_benchmarks.get(op, {})
        
        if lc.get("skipped") or rc.get("skipped"):
            continue
        
        report.append(f"### {op.replace('_', ' ').title()}")
        report.append("")
        report.append("| Metric | LangChain | RustChain |")
        report.append("|--------|-----------|-----------|")
        
        for metric in ["mean_ms", "median_ms", "min_ms", "max_ms", "p95_ms", "p99_ms", "stdev_ms"]:
            lc_val = lc.get(metric, "N/A")
            rc_val = rc.get(metric, "N/A")
            
            if isinstance(lc_val, (int, float)):
                lc_val = f"{lc_val:.3f}ms"
            if isinstance(rc_val, (int, float)):
                rc_val = f"{rc_val:.3f}ms"
            
            metric_name = metric.replace("_ms", "").replace("_", " ").title()
            report.append(f"| {metric_name} | {lc_val} | {rc_val} |")

        # Optional audit fields for LLM response size
        for metric in ["avg_response_chars", "max_response_chars"]:
            lc_val = lc.get(metric, "N/A")
            rc_val = rc.get(metric, "N/A")
            metric_name = metric.replace("_", " ").title()
            report.append(f"| {metric_name} | {lc_val} | {rc_val} |")
        
        report.append("")
    
    # Methodology
    report.append("## Methodology")
    report.append("")
    report.append("This benchmark compares equivalent operations between LangChain (Python) and RustChain (Rust).")
    report.append("")
    report.append("The suite contains two categories:")
    report.append("")
    report.append("- **Framework overhead** (no LLM): parsing, orchestration, parallel fan-out/fan-in, and state operations")
    report.append("- **Real LLM calls**: single prompt, multi-turn chat, and parallel inference via an OpenAI-compatible local endpoint")
    report.append("")
    report.append("All results shown are wall-clock latencies measured in milliseconds.")
    report.append("")
    report.append("## Integrity / Anti-Performance-Theater Checks")
    report.append("")
    report.append("This report is generated directly from raw JSON artifacts. Recommended checks:")
    report.append("")
    report.append("- Confirm **same backend + model** across both JSONs")
    report.append("- Confirm **same temperature + max_tokens** in the `config` section")
    report.append("- Check `avg_response_chars`/`max_response_chars` for LLM benchmarks; large skews usually indicate unequal output length")
    report.append("- Ensure both runs complete without errors (no missing operations, no HTTP errors)")
    report.append("")
    
    # Reproducibility
    report.append("## Reproduce These Results")
    report.append("")
    report.append("```bash")
    report.append("# Prereq: start Ollama locally (default: http://localhost:11434)")
    report.append("# and ensure the model is present (e.g., `ollama pull phi3`).")
    report.append("")
    report.append("cd benchmarks/langchain_comparison")
    report.append("")
    report.append("# RustChain")
    report.append("cargo build --release --bin rustchain-benchmark-v2 --features llm")
    report.append("./target/release/rustchain-benchmark-v2 --backend ollama --model phi3 --temperature 0 --max-tokens 100")
    report.append("")
    report.append("# LangChain (in your venv)")
    report.append("python langchain_benchmark_v2.py --backend ollama --model phi3 --temperature 0 --max-tokens 100 --max-retries 0")
    report.append("")
    report.append("# Generate report")
    report.append("python generate_report.py --langchain langchain_results_ollama.json --rustchain rustchain_results_ollama.json --output benchmark_report.md")
    report.append("```")
    report.append("")
    
    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description="Generate benchmark comparison report (v2)")
    parser.add_argument("--langchain", default="langchain_results_ollama.json", help="Path to LangChain results JSON")
    parser.add_argument("--rustchain", default="rustchain_results_ollama.json", help="Path to RustChain results JSON")
    parser.add_argument("--output", default="benchmark_report.md", help="Output markdown path")
    args = parser.parse_args()

    print("Loading benchmark results...")
    langchain = load_results(args.langchain)
    rustchain = load_results(args.rustchain)

    print("Generating comparison report...")
    report = generate_report(langchain, rustchain)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Report saved to: {args.output}")
    print()
    
    # Print summary to console
    lc_benchmarks = {b["operation"]: b for b in langchain.get("benchmarks", []) if "operation" in b}
    rc_benchmarks = {b["operation"]: b for b in rustchain.get("benchmarks", []) if "operation" in b}
    
    print("=" * 50)
    print("  QUICK SUMMARY")
    print("=" * 50)
    
    for op in ["workflow_parsing", "chain_execution", "parallel_execution", "memory_operations"]:
        lc = lc_benchmarks.get(op, {})
        rc = rc_benchmarks.get(op, {})
        
        if "mean_ms" in lc and "mean_ms" in rc:
            speedup = lc["mean_ms"] / rc["mean_ms"]
            print(f"  {op}: {speedup:.1f}x faster")
    
    print("=" * 50)


if __name__ == "__main__":
    main()
