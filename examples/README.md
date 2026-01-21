# RustChain Examples

## Quick Start

```bash
# Validate a mission
rustchain mission validate examples/hello_world.yaml

# Dry run (shows what would execute)
rustchain run examples/hello_world.yaml --dry-run

# Execute a mission
rustchain run examples/hello_world.yaml
```

## YAML Mission Files

| File | Description | Requirements |
|------|-------------|--------------|
| [hello_world.yaml](hello_world.yaml) | First mission - file creation and commands | None |
| [data_processing.yaml](data_processing.yaml) | CSV loading and processing | None |
| [api_integration.yaml](api_integration.yaml) | HTTP GET/POST and error handling | Internet access |
| [llm_demo.yaml](llm_demo.yaml) | LLM prompt execution | Ollama or LLM backend |
| [agent_demo.yaml](agent_demo.yaml) | Autonomous agent reasoning | Ollama or LLM backend |
| [agent_reasoning.yaml](agent_reasoning.yaml) | ReAct pattern agent | Ollama or LLM backend |
| [chain_demo.yaml](chain_demo.yaml) | Sequential LLM chains | Ollama or LLM backend |
| [tool_demo.yaml](tool_demo.yaml) | Tool invocation via step | None |

## Rust Examples

Programmatic examples for library integration:

```bash
cargo run --example test_step_validation --all-features
```

| File | Description |
|------|-------------|
| [test_step_validation.rs](test_step_validation.rs) | Basic step type execution |
| [basic_error_validation.rs](basic_error_validation.rs) | Error handling patterns |
| [error_handling_validation.rs](error_handling_validation.rs) | Comprehensive error tests |
| [cross_platform_validation.rs](cross_platform_validation.rs) | Cross-platform compatibility |
| [test_security_fixes.rs](test_security_fixes.rs) | Security constraint validation |
| [documentation_validation.rs](documentation_validation.rs) | Doc verification tests |

## Mission File Format

```yaml
name: "Mission Name"
version: "1.0"

steps:
  - id: "step_1"
    name: "Create output file"
    step_type: "create_file"
    parameters:
      path: "output.txt"
      content: "Hello from RustChain"

  - id: "step_2"
    step_type: "command"
    parameters:
      command: "echo"
      args: ["done"]
    depends_on: ["step_1"]
    timeout_seconds: 10

config:
  timeout_seconds: 60
  fail_fast: true
```

## Step Types

**File Operations**: `create_file`, `edit_file`, `delete_file`, `copy_file`, `move_file`, `read_file`

**Execution**: `command`, `http`, `noop`

**AI/LLM**: `llm`, `agent`, `chain`, `rag_query`, `rag_add`

**Data**: `parse_json`, `parse_yaml`, `csv_process`, `tool`

**Git**: `git_status`, `git_commit`, `git_diff`

## Validation

```bash
rustchain mission validate examples/hello_world.yaml
```
