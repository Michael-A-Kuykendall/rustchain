#!/bin/bash
#
# RustChain vs LangChain Benchmark Runner
# =======================================
# Runs both benchmarks and generates comparison report.
#
# Usage:
#   ./run_benchmark.sh           # Full benchmark (requires OPENAI_API_KEY for LLM tests)
#   ./run_benchmark.sh --no-llm  # Skip LLM tests (no API key needed)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "  RustChain vs LangChain Head-to-Head Benchmark"
echo "============================================================"
echo ""

# Parse arguments
NO_LLM_FLAG=""
if [[ "$1" == "--no-llm" ]]; then
    NO_LLM_FLAG="--no-llm"
    echo "Mode: Framework-only (no LLM calls)"
else
    echo "Mode: Full benchmark (including LLM calls if API key present)"
fi
echo ""

# Capture system information
echo "System Information:"
echo "-------------------"
echo "Date: $(date -Iseconds)"
echo "OS: $(uname -s) $(uname -r)"
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")"
echo "Cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "Unknown")"
echo "Memory: $(free -h 2>/dev/null | grep Mem | awk '{print $2}' || sysctl -n hw.memsize 2>/dev/null | awk '{print $1/1024/1024/1024 " GB"}' || echo "Unknown")"
echo ""

# Check prerequisites
echo "Checking prerequisites..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found. Please install Python 3.9+"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo "  ✓ $PYTHON_VERSION"

# Check LangChain
if python3 -c "import langchain" 2>/dev/null; then
    LANGCHAIN_VERSION=$(python3 -c "import langchain; print(langchain.__version__)")
    echo "  ✓ LangChain $LANGCHAIN_VERSION"
else
    echo "  ✗ LangChain not installed"
    echo "    Install with: pip install langchain langchain-openai langchain-core pyyaml"
    exit 1
fi

# Check Rust binary
RUST_BIN="../../target/release/rustchain-benchmark"
if [[ ! -f "$RUST_BIN" ]]; then
    echo "  Building RustChain benchmark..."
    (cd ../.. && cargo build --release --bin rustchain-benchmark)
fi
echo "  ✓ RustChain benchmark binary"
echo ""

# Run LangChain benchmark
echo "============================================================"
echo "  Running LangChain Benchmark (Python)"
echo "============================================================"
python3 langchain_benchmark.py $NO_LLM_FLAG
echo ""

# Run RustChain benchmark  
echo "============================================================"
echo "  Running RustChain Benchmark (Rust)"
echo "============================================================"
$RUST_BIN $NO_LLM_FLAG
echo ""

# Generate comparison report
echo "============================================================"
echo "  Generating Comparison Report"
echo "============================================================"
python3 generate_report.py
echo ""

echo "============================================================"
echo "  Benchmark Complete!"
echo "============================================================"
echo ""
echo "Results saved to:"
echo "  - langchain_results.json"
echo "  - rustchain_results.json"
echo "  - benchmark_report.md"
