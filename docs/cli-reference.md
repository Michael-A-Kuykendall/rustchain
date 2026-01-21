# RustChain CLI Reference

Complete command-line reference for RustChain Community Edition.

## Quick Start

```bash
# Run a mission
rustchain run examples/hello_world.yaml

# Validate before running
rustchain mission validate examples/hello_world.yaml

# Check system status
rustchain build status
```

## Command Structure

```
rustchain <COMMAND> [OPTIONS] [ARGS]
```

## Commands

### `run` - Execute Missions

Execute a mission directly from a YAML file.

```bash
rustchain run <MISSION_FILE> [OPTIONS]

# Examples
rustchain run examples/hello_world.yaml
rustchain run mission.yaml --dry-run
rustchain run mission.yaml --skip-safety
```

**Options:**
- `--dry-run` - Validate without executing
- `--skip-safety` - Skip safety validation (use with caution)

---

### `interactive` - Conversational Mode

Start an interactive session for conversational mission building.

```bash
rustchain interactive
```

---

### `mission` - Mission Management

Manage and inspect mission files.

```bash
rustchain mission <SUBCOMMAND>
```

**Subcommands:**
- `list` - List available missions in the current directory
- `validate <FILE>` - Validate a mission file syntax and structure
- `info <FILE>` - Show detailed mission information

```bash
# Examples
rustchain mission list
rustchain mission validate my_mission.yaml
rustchain mission info my_mission.yaml
```

---

### `safety` - Safety Validation

Validate missions for safety and security concerns.

```bash
rustchain safety <SUBCOMMAND>
```

**Subcommands:**
- `validate <FILE>` - Validate mission safety
- `check` - Run safety validation checks
- `report` - Generate safety report

```bash
# Examples
rustchain safety validate mission.yaml
rustchain safety check
rustchain safety report
```

---

### `tools` - Tool Management

Manage and execute built-in tools.

```bash
rustchain tools <SUBCOMMAND>
```

**Subcommands:**
- `list` - List available tools
- `info <TOOL>` - Show tool information
- `execute <TOOL>` - Execute a tool with parameters

```bash
# Examples
rustchain tools list
rustchain tools info create_file
rustchain tools execute create_file --params '{"path":"test.txt","content":"Hello"}'
```

---

### `audit` - Audit Operations

Query and manage audit trails.

```bash
rustchain audit <SUBCOMMAND>
```

**Subcommands:**
- `query` - Query audit entries
- `report` - Generate audit report
- `verify` - Verify audit chain integrity
- `export` - Export audit data
- `stats` - Show audit statistics

```bash
# Examples
rustchain audit stats
rustchain audit report
rustchain audit verify
```

---

### `policy` - Policy Management

Manage security and governance policies.

```bash
rustchain policy <SUBCOMMAND>
```

**Subcommands:**
- `list` - List active policies
- `validate` - Validate policy configuration
- `status` - Show policy status

```bash
# Examples
rustchain policy list
rustchain policy status
```

---

### `config` - Configuration

Manage RustChain configuration.

```bash
rustchain config <SUBCOMMAND>
```

**Subcommands:**
- `show` - Show current configuration
- `validate` - Validate configuration
- `init` - Initialize default configuration

```bash
# Examples
rustchain config show
rustchain config init
```

---

### `build` - Build Dashboard

System health and build status tracking.

```bash
rustchain build <SUBCOMMAND>
```

**Subcommands:**
- `dashboard` - Show build dashboard with system health
- `status` - Generate build status report
- `update` - Update dashboard with current test results
- `save` - Save dashboard to file
- `load` - Load dashboard from file

```bash
# Examples
rustchain build status
rustchain build dashboard
```

---

### `transpile` - Workflow Transpilation

Convert workflows between different formats.

```bash
rustchain transpile <SUBCOMMAND>
```

**Subcommands:**
- `lang-chain` - Convert LangChain Python to RustChain YAML
- `airflow` - Convert Airflow DAG to RustChain YAML
- `git-hub-actions` - Convert GitHub Actions to RustChain YAML
- `kubernetes` - Convert Kubernetes manifest to RustChain YAML
- `docker-compose` - Convert Docker Compose to RustChain YAML
- `auto` - Auto-detect format and convert
- `showcase-all` - Convert to all supported formats (demo)

```bash
# Examples
rustchain transpile lang-chain script.py
rustchain transpile auto workflow.yaml
```

---

### `benchmark` - Performance Benchmarking

Run performance benchmarks.

```bash
rustchain benchmark
```

---

## Global Options

- `-h, --help` - Print help information
- `-V, --version` - Print version information

## Environment Variables

- `RUST_LOG` - Set logging level (e.g., `info`, `debug`, `trace`)
- `OPENAI_API_KEY` - OpenAI API key for LLM features
- `ANTHROPIC_API_KEY` - Anthropic API key for Claude models

## Examples

### Basic Workflow

```bash
# 1. Validate your mission
rustchain mission validate my_workflow.yaml

# 2. Check safety
rustchain safety validate my_workflow.yaml

# 3. Run the mission
rustchain run my_workflow.yaml
```

### Development Workflow

```bash
# Check system status
rustchain build status

# List available tools
rustchain tools list

# View configuration
rustchain config show
```
