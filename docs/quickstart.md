# RustChain Quick Start

Get running in 5 minutes.

## 1. Build

```bash
git clone https://github.com/Michael-A-Kuykendall/rustchain.git
cd rustchain
cargo build --release --features "cli,tools,llm"
```

## 2. Verify

```bash
./target/release/rustchain --version
./target/release/rustchain --help
```

## 3. Validate a Mission

```bash
./target/release/rustchain mission validate examples/hello_world.yaml
```

Expected output:
```
✓ Validating mission file: examples/hello_world.yaml
✓ Mission file is valid!
  Name: Hello World - Your First RustChain Mission
  Version: 1.0
  Steps: 2
```

## 4. Check System Status

```bash
./target/release/rustchain build status
```

## 5. Explore Commands

```bash
# List available tools
./target/release/rustchain tools list

# View policies
./target/release/rustchain policy list

# Check safety
./target/release/rustchain safety validate examples/hello_world.yaml
```

## Mission File Format

Missions are YAML files:

```yaml
name: "My First Mission"
description: "A simple example"
version: "1.0"

steps:
  - id: "step_1"
    name: "Create a file"
    step_type: "create_file"
    parameters:
      path: "output.txt"
      content: "Hello from RustChain!"

  - id: "step_2"
    name: "Run a command"
    step_type: "command"
    parameters:
      command: "echo"
      args: ["Mission complete!"]
    depends_on: ["step_1"]
```

## Next Steps

- See [CLI Reference](cli-reference.md) for all commands
- Check [examples/](../examples/) for more mission templates
- Read [Usage Guide](usage-guide.md) for common patterns
