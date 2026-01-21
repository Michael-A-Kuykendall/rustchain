<p align="center">
  <img src="assets/rustchain_logo_tight_transparent.png" alt="RustChain" width="400">
</p>

<p align="center">
  <strong>Keep your existing workflows. RustChain runs them all.</strong>
</p>

<p align="center">
  <a href="https://github.com/Michael-A-Kuykendall/rustchain/actions/workflows/ci.yml"><img src="https://github.com/Michael-A-Kuykendall/rustchain/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.70+-orange.svg" alt="Rust"></a>
</p>

---

RustChain consumes workflows from the tools you already use:

| Platform | Status | Command |
|----------|--------|---------|
| **LangChain** (Python) | ✅ Supported | `rustchain transpile lang-chain script.py` |
| **Apache Airflow** | ✅ Supported | `rustchain transpile airflow dag.py` |
| **GitHub Actions** | ✅ Supported | `rustchain transpile github-actions workflow.yml` |
| **Kubernetes** | ✅ Supported | `rustchain transpile kubernetes deployment.yaml` |
| **Docker Compose** | ✅ Supported | `rustchain transpile docker-compose compose.yaml` |

**You don't have to rewrite anything.** Point RustChain at your existing files and it generates executable missions.

```bash
# Your existing LangChain script
rustchain transpile lang-chain my_agent.py -o mission.yaml

# Now run it with RustChain
rustchain run mission.yaml
```

## Why migrate?

| Problem with current tools | RustChain solution |
|---------------------------|-------------------|
| Python's GIL limits parallelism | True multi-threading, no GIL |
| GC pauses cause latency spikes | Deterministic memory management |
| Container startup overhead | Native binary, instant startup |
| Vendor lock-in | Universal format, portable everywhere |

---

## How Transpilation Works

RustChain's transpiler parses your existing workflow definitions and generates equivalent RustChain missions:

```
Your Workflow          RustChain              Output
─────────────          ─────────              ──────
LangChain.py      ──▶  Transpiler        ──▶  mission.yaml
Airflow DAG            (parses & converts)    (executable)
GitHub Actions
K8s manifest
Docker Compose
```

### What gets converted

- **Steps/Tasks** → Mission steps with proper types
- **Dependencies** → `depends_on` relationships preserved
- **Configuration** → Parameters mapped to RustChain equivalents
- **Secrets/Env vars** → Environment variable references preserved

### Auto-detection

Don't know the format? RustChain figures it out:

```bash
rustchain transpile auto my_workflow.py
# Detects: LangChain Python
# Output: my_workflow.yaml
```

### Supported conversions

| From | Detected by | What's preserved |
|------|------------|------------------|
| LangChain | `from langchain`, `from openai` | Chains, agents, tools, prompts |
| Airflow | `@dag`, `DAG(`, `airflow` imports | Operators, dependencies, schedules |
| GitHub Actions | `on:`, `jobs:` | Steps, runners, secrets |
| Kubernetes | `apiVersion:`, `kind:` | Containers, resources, volumes |
| Docker Compose | `services:`, `image:` | Services, networks, volumes |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/Michael-A-Kuykendall/rustchain
cd rustchain
cargo build --release --features "cli,tools,llm"
```

### 2. Convert an existing workflow

```bash
# Have a LangChain script?
rustchain transpile lang-chain your_script.py -o mission.yaml

# Have an Airflow DAG?
rustchain transpile airflow your_dag.py -o mission.yaml

# Not sure what format?
rustchain transpile auto your_file.py -o mission.yaml
```

### 3. Validate and run

```bash
# Check it first
rustchain mission validate mission.yaml

# Dry run (no side effects)
rustchain run mission.yaml --dry-run

# Execute
rustchain run mission.yaml
```

---

## Native Mission Format

If you want to write missions directly (instead of converting), use YAML:

```yaml
name: "Data Pipeline"
version: "1.0"
steps:
  - id: "fetch_data"
    name: "Fetch from API"
    step_type: "http_request"
    parameters:
      url: "https://api.example.com/data"
      method: "GET"

  - id: "process"
    name: "Process with LLM"
    step_type: "llm"
    depends_on: ["fetch_data"]
    parameters:
      provider: "ollama"
      model: "llama2"
      prompt: "Summarize: ${fetch_data.output}"

  - id: "save"
    name: "Save results"
    step_type: "create_file"
    depends_on: ["process"]
    parameters:
      path: "output.txt"
      content: "${process.output}"
```

---

## CLI Reference

```
rustchain run <file>           Execute a mission
rustchain transpile <cmd>      Convert from other formats
rustchain mission <cmd>        Mission management
rustchain safety <cmd>         Safety validation
rustchain tools <cmd>          Tool management
rustchain audit <cmd>          Audit queries
rustchain policy <cmd>         Policy management
rustchain config <cmd>         Configuration
rustchain interactive          Interactive mode
```

See `rustchain --help` for full details.

---

## Documentation

- [Installation](docs/installation.md)
- [Quick Start](docs/quickstart.md)
- [Transpilation Guide](docs/transpilation.md)
- [CLI Reference](docs/cli-reference.md)
- [Examples](examples/)

---

## Requirements

- **Rust 1.70+**: Required for compilation
- **Optional**: Ollama or compatible LLM backend for AI features

---

## License

Dual-licensed under MIT or Apache-2.0, at your option.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Contributing

RustChain is **open source but not open contribution**. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).
