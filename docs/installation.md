# RustChain Installation Guide

## Requirements

- **Rust 1.70+**: Install from [rustup.rs](https://rustup.rs)
- **Git**: For cloning the repository

## Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/Michael-A-Kuykendall/rustchain.git
cd rustchain

# Build with default features
cargo build --release --features "cli,tools,llm"

# The binary will be at target/release/rustchain
```

### Install to PATH

```bash
# Linux/macOS
cp target/release/rustchain ~/.local/bin/

# Windows (PowerShell)
copy target\release\rustchain.exe $env:USERPROFILE\.cargo\bin\
```

### Verify Installation

```bash
rustchain --version
rustchain --help
```

## Build Features

RustChain uses Cargo feature flags for modular compilation:

| Feature | Description | Default |
|---------|-------------|---------|
| `cli` | Command-line interface | ✅ |
| `tools` | Built-in tool framework | ✅ |
| `llm` | LLM provider integrations | ✅ |
| `transpiler` | Workflow transpilation | ✅ |
| `agent` | AI agent system | ❌ |
| `chain` | Chain workflows | ❌ |
| `rag` | Retrieval-augmented generation | ❌ |
| `server` | HTTP server (library only) | ❌ |

### Build Examples

```bash
# Minimal build (CLI only)
cargo build --release --features cli

# Full build with all features
cargo build --release --all-features

# Development build (faster compilation)
cargo build --features "cli,tools,llm"
```

## LLM Setup (Optional)

For LLM features, you need either:

### Option 1: Ollama (Local, Free)

```bash
# Install Ollama from ollama.ai
ollama serve

# Pull a model
ollama pull llama3.2:1b
```

### Option 2: Cloud Providers

Set environment variables:

```bash
# OpenAI
export OPENAI_API_KEY="your-key"

# Anthropic
export ANTHROPIC_API_KEY="your-key"
```

## Quick Test

```bash
# Validate a mission
rustchain mission validate examples/hello_world.yaml

# Check build status
rustchain build status
```

## Troubleshooting

### Build Fails

```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build --release --features "cli,tools,llm"
```

### Missing Features

If commands are missing, ensure you built with the right features:

```bash
cargo build --release --features "cli,tools,llm,transpiler"
```
