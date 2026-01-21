# Transpilation Guide

RustChain can consume workflows from other platforms and execute them. This guide explains how.

## The Idea

You have existing workflows—LangChain scripts, Airflow DAGs, GitHub Actions, Kubernetes manifests. You don't want to rewrite them. RustChain converts them to its native format and runs them.

```
Your existing workflow  →  RustChain transpiler  →  Executable mission
```

## Supported Platforms

| Platform | File Types | Detection |
|----------|-----------|-----------|
| LangChain | `.py` | `from langchain`, `from openai` |
| Apache Airflow | `.py` | `@dag`, `DAG(`, airflow imports |
| GitHub Actions | `.yml`, `.yaml` | `on:`, `jobs:` |
| Kubernetes | `.yml`, `.yaml` | `apiVersion:`, `kind:` |
| Docker Compose | `.yml`, `.yaml` | `services:`, `image:` |

## Basic Usage

### Convert a specific format

```bash
# LangChain Python
rustchain transpile lang-chain my_agent.py -o mission.yaml

# Airflow DAG
rustchain transpile airflow my_dag.py -o mission.yaml

# GitHub Actions
rustchain transpile github-actions .github/workflows/ci.yml -o mission.yaml

# Kubernetes
rustchain transpile kubernetes deployment.yaml -o mission.yaml

# Docker Compose
rustchain transpile docker-compose docker-compose.yml -o mission.yaml
```

### Auto-detect format

If you're not sure what format a file is:

```bash
rustchain transpile auto my_workflow.py
```

RustChain examines the file content and picks the right parser.

## What Gets Converted

### LangChain

| LangChain Concept | RustChain Equivalent |
|-------------------|---------------------|
| `LLMChain` | `llm` step type |
| `Agent` | Multiple steps with tool calls |
| `Tool` | `tool_call` step type |
| Prompt templates | `prompt` parameter with variables |
| `ChatOpenAI` | `provider: openai` |
| `ChatOllama` | `provider: ollama` |

Example input:
```python
from langchain import LLMChain
from langchain.llms import OpenAI

llm = OpenAI(temperature=0.7)
chain = LLMChain(llm=llm, prompt="What is {topic}?")
```

Generated output:
```yaml
name: langchain_mission
version: '1.0'
steps:
  - id: step_1
    name: LLM Chain Step 1
    step_type: llm
    parameters:
      provider: openai
      model: gpt-3.5-turbo
      prompt: "What is {topic}?"
      variables:
        - topic
```

### Airflow

| Airflow Concept | RustChain Equivalent |
|-----------------|---------------------|
| `PythonOperator` | `command` step with Python |
| `BashOperator` | `command` step |
| `HttpOperator` | `http_request` step |
| Task dependencies (`>>`) | `depends_on` |
| `@dag` decorator | Mission metadata |

Example input:
```python
from airflow import DAG
from airflow.operators.python import PythonOperator

with DAG('my_dag') as dag:
    task1 = PythonOperator(task_id='extract', python_callable=extract_data)
    task2 = PythonOperator(task_id='transform', python_callable=transform_data)
    task1 >> task2
```

Generated output:
```yaml
name: my_dag
version: '1.0'
steps:
  - id: extract
    name: extract
    step_type: command
    parameters:
      command: python
      args: ["-c", "extract_data()"]
  - id: transform
    name: transform
    step_type: command
    depends_on: [extract]
    parameters:
      command: python
      args: ["-c", "transform_data()"]
```

### GitHub Actions

| GitHub Actions Concept | RustChain Equivalent |
|-----------------------|---------------------|
| `jobs` | Mission sections |
| `steps` | Mission steps |
| `run` | `command` step type |
| `uses` | `tool_call` (where applicable) |
| `needs` | `depends_on` |
| `env` | Environment variables |

Example input:
```yaml
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: cargo build
      - name: Test
        run: cargo test
```

Generated output:
```yaml
name: CI
version: '1.0'
steps:
  - id: checkout
    name: Checkout
    step_type: command
    parameters:
      command: git
      args: [clone, .]
  - id: build
    name: Build
    step_type: command
    depends_on: [checkout]
    parameters:
      command: cargo
      args: [build]
  - id: test
    name: Test
    step_type: command
    depends_on: [build]
    parameters:
      command: cargo
      args: [test]
```

### Kubernetes

| Kubernetes Concept | RustChain Equivalent |
|-------------------|---------------------|
| `Deployment` | Mission with container steps |
| `containers` | Individual steps |
| `env` | Environment variables |
| `command` | Command parameters |

### Docker Compose

| Docker Compose Concept | RustChain Equivalent |
|-----------------------|---------------------|
| `services` | Mission steps |
| `depends_on` | `depends_on` |
| `command` | Command parameters |
| `environment` | Environment variables |

## Validation After Conversion

Always validate the generated mission:

```bash
# Convert
rustchain transpile lang-chain my_script.py -o mission.yaml

# Validate
rustchain mission validate mission.yaml

# Dry run (no side effects)
rustchain run mission.yaml --dry-run

# Execute
rustchain run mission.yaml
```

## Limitations

Transpilation isn't magic. Some things require manual adjustment:

1. **Complex control flow**: Loops and conditionals may need restructuring
2. **External dependencies**: Library imports need equivalent tools registered
3. **Secrets**: Credentials should be moved to environment variables
4. **Platform-specific features**: Some features don't have direct equivalents

## Tips

1. **Start with simple workflows** to understand the conversion
2. **Use auto-detect** when you're not sure about the format
3. **Review the output** before running in production
4. **Keep the original** files as reference
5. **Test with dry-run** first

## Troubleshooting

### "Could not auto-detect input format"

The file content doesn't match any known patterns. Use a specific transpile command:
```bash
rustchain transpile lang-chain my_script.py  # Instead of auto
```

### Missing dependencies

Some converted steps may reference tools that aren't registered:
```bash
rustchain tools list  # See what's available
```

### Validation errors

If the generated mission doesn't validate:
1. Check the error message for specifics
2. Review the generated YAML for issues
3. Adjust parameters or step types manually

## Next Steps

- [CLI Reference](cli-reference.md) - All transpile commands
- [Mission Syntax](mission-syntax.md) - Native mission format
- [Examples](../examples/) - Sample missions
