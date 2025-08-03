# Executive Officer (XO) — AI-Enhanced Mission Runner with RAG Mission Queue

**Executive Officer (XO)** is an intelligent, single-file Python automation system for executing mission stacks (YAML-based procedural workflows) with integrated AI analysis, context search, concise auditing, cross-language test orchestration, and **automated mission queue management**.

---

## 🚦 What is XO?

XO is a drop-in, developer-first automation engine for running, testing, and analyzing complex procedural builds and code transformations—while always producing a clear, auditable log and summary. XO is the evolution of "mission runners" for AI-enabled development, with native support for:
- **Mission Queue Management**: Automatic validation, queuing, and batch processing
- **RAG-Based Mission Intelligence**: SQLite-powered mission tracking and validation
- File creation/editing with validation
- Shell commands with error handling
- Linting across multiple languages
- AI-powered code generation (Ollama)
- Language-native testing (with ultra-concise error summaries)
- Context document search and indexing
- Comprehensive audit logging and reporting

XO is **designed for high-volume, iterative work** in environments where traditional CI/test outputs are too voluminous for stepwise AI or human review. The new **mission queue system** enables professional workflow orchestration with automatic validation and intelligent scheduling.

---

## ✨ Key Features

### 🎯 Mission Queue & Validation
- **Mission Inbox Processing**: Drop YAML files in `missions_inbox/` for automatic validation
- **Intelligent Queue Management**: Priority-based scheduling with dependency tracking
- **Invalid Mission Quarantine**: Automatically flags and isolates broken missions
- **Mission Status Tracking**: Comprehensive execution history and completion status
- **Batch Validation**: Process multiple missions with detailed error reporting

### 🚀 Core Automation
- **Mission Stack Protocol**: Write your automation as YAML steps—XO interprets and executes each, with robust error handling and audit trails
- **Language-Aware Test Summaries**: Runs Python, Go, Rust, or JavaScript tests and automatically extracts just the pass/fail/error/summary lines for stateful AI or human review
- **AI Context Search**: XO indexes your markdown/doc files for instant context retrieval during code gen or audit steps
- **Concise Auditing**: Every step and its result are logged (with minimal output by default, full logs saved on failure only)
- **Drop-in Simplicity**: Just one Python file. No frameworks, no server, no Docker, no magic. Runs anywhere Python 3.x does

---

## 🚀 Quickstart

1. **Install dependencies (optional, but recommended for AI features):**
    ```bash
    pip install langchain_ollama pyyaml
    ```

2. **Write your mission stack YAML (see below) or use the mission queue system:**

3. **Run XO with Mission Queue:**
    ```bash
    # Validate all missions in inbox
    python executive_officer.py --validate-inbox
    
    # View mission queue status
    python executive_officer.py --list-queue
    
    # Run next priority mission
    python executive_officer.py --run-next
    
    # Run specific mission (classic mode)
    python executive_officer.py my_mission.yaml
    ```

---

## 🎯 Mission Queue Workflow

### Quick Start: RAG Mission Processing
The Executive Officer uses your existing `mission-stacks/` directory as the source and processes missions through an intelligent RAG-based queue system:

```bash
# 1. Setup directories (auto-created, but you can pre-create)
mkdir -p missions_invalid rag_store audit_logs

# 2. Your missions are already in mission-stacks/ 
ls mission-stacks/*.yaml  # 13 mission files ready to process

# 3. Ingest missions into RAG storage + validate
python executive_officer.py --validate-inbox
# → Valid missions go to context.db (RAG storage + mission queue)
# → Invalid missions flagged in database with error reports

# 4. View what's in your RAG mission queue
python executive_officer.py --list-queue
# → Shows all missions with status: validated/invalid/completed

# 5. Run missions from RAG queue (one at a time)
python executive_officer.py --run-next
# → Automatically pulls next validated mission from RAG and executes

# 6. Check queue status after each run
python executive_officer.py --list-queue
# → See completed/failed missions, what's next in queue

# 7. Repeat step 5-6 until all missions complete
# → Each mission runs independently with full audit trail
```

### Step-by-Step Process

### Step 1: Validate All Missions
```bash
python executive_officer.py --validate-inbox
```
**Output:**
```
🚀 Starting XO Mission Inbox Validation...
🔍 Validating 13 mission files in mission-stacks...

📋 Validating: 00-error-foundation.yaml
✅ Valid: Error Foundation System

📋 Validating: 01-tool-discovery.yaml
✅ Valid: RustChain LLM Tools

📊 Validation complete: 13 valid, 0 invalid
```

### Step 2: Check Mission Queue Status
```bash
python executive_officer.py --list-queue
```
**Output:**
```
📋 Mission Queue (13 missions):
======================================================================
✅ RustChain: Error Foundation System
   Status: validated | Steps: 6 | Est: 180s
   Created: 2025-08-03 14:23:00

✅ RustChain: LLM Tools Implementation  
   Status: validated | Steps: 8 | Est: 240s
   Created: 2025-08-03 14:23:00
```

### Step 3: Execute Next Mission
```bash
python executive_officer.py --run-next
```
**Output:**
```
🚀 Running next mission: 00-error-foundation.yaml
🚀 Starting Executive Officer (XO) Mission Runner...
📋 Mission: RustChain: Error Foundation System
📝 Description: Core error handling and foundation types
🔧 Steps to execute: 6
==================================================
[Full mission execution with step-by-step progress]
```

### Step 4: Monitor Progress
```bash
python executive_officer.py --list-queue
```
**Shows updated status:**
```
📋 Mission Queue (13 missions):
======================================================================
🎉 RustChain: Error Foundation System
   Status: completed | Steps: 6 | Est: 180s
   Created: 2025-08-03 14:23:00

✅ RustChain: LLM Tools Implementation  
   Status: validated | Steps: 8 | Est: 240s
   Created: 2025-08-03 14:23:00
```

---

## 🎯 Legacy Mission Queue Workflow (Alternative)

### Step 1: Set Up Mission Directory
```bash
# XO uses your existing mission-stacks directory
ls mission-stacks/          # Your mission files are here
mkdir missions_invalid      # Invalid missions flagged here (auto-created)
```

### Step 2: Missions are Already Available
```bash
# Your missions are already in mission-stacks/
ls mission-stacks/*.yaml
```

### Step 3: Validate Mission Directory
```bash
python executive_officer.py --validate-inbox
```
**Output:**
```
🚀 Starting XO Mission Inbox Validation...
🔍 Validating 13 mission files in mission-stacks...

📋 Validating: 00-error-foundation.yaml
✅ Valid: Error Foundation System

📋 Validating: 01-tool-discovery.yaml
❌ Invalid mission: 01-tool-discovery.yaml
   Error: Step step1: missing command

📊 Validation complete: 12 valid, 1 invalid
⚠️ Invalid missions remain in mission-stacks/ - check errors above
```

### Step 4: Check Mission Queue
```bash
python executive_officer.py --list-queue
```
**Output:**
```
📋 Mission Queue (1 missions):
======================================================================
✅ RustChain MVP Build
   Status: validated | Steps: 5 | Est: 150s
   Created: 2025-08-03 14:23:00
```

### Step 5: Execute Missions
```bash
# Run next mission from queue
python executive_officer.py --run-next

# Or run specific mission
python executive_officer.py mission-stacks/00-error-foundation.yaml
```

---

## 📄 Example Mission Stack (YAML)

```yaml
mission:
  name: "RustChain MVP Build"
  description: "Run all tests, lint, and AI code gen for RustChain."
  steps:
    - id: python_tests
      type: test
      language: python
      description: "Run Python tests and summarize failures"
    - id: go_tests
      type: test
      language: go
      description: "Run Go tests"
    - id: lint_code
      type: lint
      language: python
      description: "Lint Python code"
    - id: ai_codegen
      type: ai_generate
      language: python
      requirements: "Generate a new CLI tool with argparse."
      output_file: "generated/cli.py"
      description: "LLM generates a new CLI tool"
    - id: create_readme
      type: create_file
      file_path: "README.md"
      content: |
        # RustChain MVP
        This file was created by XO.
      description: "Create README.md"
```

---

## 📚 Complete Step Types Reference

### 🗂️ File Operations
```yaml
# Create new files
- id: create_file_step
  type: create_file  # or 'create'
  file_path: "src/new_module.py"
  content: |
    def hello():
        return "Hello, World!"
  description: "Create a new Python module"

# Edit existing files (legacy format support)
- id: edit_file_step
  type: edit
  file_path: "existing_file.py"
  content: "Additional content to append"
  description: "Append content to existing file"
```

### ⚡ Execution Steps
```yaml
# Run shell commands
- id: command_step
  type: command
  command: "echo 'Building project...' && make build"
  working_dir: "optional/subdirectory"  # Optional
  description: "Run build command"

# Language-native testing with smart summaries
- id: test_step
  type: test
  language: python  # python, go, rust, javascript
  min_coverage: 0.8  # Optional coverage threshold
  description: "Run tests with coverage"

# Code linting
- id: lint_step
  type: lint
  language: python  # python, go, rust, javascript
  description: "Lint codebase for style issues"
```

### 🤖 AI-Powered Steps
```yaml
# LLM code generation
- id: ai_generate_step
  type: ai_generate
  language: python  # Target language
  requirements: "Create a REST API client with error handling"
  output_file: "generated/api_client.py"
  description: "Generate API client code"

# Pre-mission audit
- id: audit_step
  type: audit
  fail_on_blocker: true  # Optional: stop on critical issues
  description: "Scan codebase for issues"

# Post-mission reporting
- id: report_step
  type: report
  title: "Mission Results"
  sections: ["overview", "findings", "recommendations"]
  output_file: "reports/mission_report.md"
  description: "Generate comprehensive report"
```

### 🔧 Advanced Options
```yaml
# Step failure handling
- id: optional_step
  type: command
  command: "might_fail_command"
  fail_on_error: false  # Continue on failure (default: true)
  description: "Optional step that won't stop mission"

# Approval gates
mission:
  name: "Production Deployment"
  require_approval_on: [deploy_step]  # Pause for human approval
  steps:
    - id: deploy_step
      type: command
      command: "deploy_to_production.sh"
```

---

## ⚙️ Configuration & Environment

### 🔌 Ollama Setup (for AI features)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a lightweight model
ollama pull tinyllama

# Start Ollama service
ollama serve
```

### 🌍 Environment Variables
```bash
# Ollama configuration
export OLLAMA_ENDPOINT="http://localhost:11434"
export OLLAMA_MODEL="tinyllama"  # or phi3:mini, llama2, etc.

# XO paths (optional)
export XO_AUDIT_DIR="./audit_logs"
export XO_CONTEXT_DIR="./rag_store"
```

### 📁 Directory Structure
```
project/
├── executive_officer.py        # The XO engine
├── mission-stacks/             # Your mission files (source directory)
├── missions_invalid/           # Database flags for invalid missions
├── audit_logs/                # Execution logs (auto-created)
├── rag_store/                 # Context docs (auto-indexed)
├── generated/                 # AI-generated files
└── context.db                # SQLite database for mission queue & context
```

---

## 🗄️ Mission Queue Database

XO uses SQLite to track mission status, validation, and execution history:

### Mission Queue Table Schema
```sql
CREATE TABLE mission_queue (
    id INTEGER PRIMARY KEY,
    mission_file TEXT UNIQUE,
    mission_name TEXT,
    mission_hash TEXT,
    status TEXT DEFAULT 'pending',  -- pending, validated, invalid, completed, failed
    validation_error TEXT,
    step_count INTEGER,
    estimated_duration INTEGER,
    priority INTEGER DEFAULT 1,
    dependencies TEXT,  -- JSON array of required missions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMP,
    executed_at TIMESTAMP,
    completion_status TEXT
);
```

### Mission Status Lifecycle
```
📝 pending → 🔍 validated → ▶️ executing → ✅ completed
             ↘ ❌ invalid             ↘ 💥 failed
```

### Advanced Queue Management
```bash
# Check database directly (optional)
sqlite3 context.db "SELECT mission_name, status, step_count FROM mission_queue;"

# View detailed mission status
python executive_officer.py --list-queue

# Priority can be set in mission YAML:
mission:
  name: "High Priority Task"
  priority: 10  # Higher numbers = higher priority
  dependencies: ["prerequisite_mission"]  # Must complete first
```

---

## 🔧 Mission Validation System

### Automatic Validation Checks
- ✅ **YAML Syntax**: Valid YAML structure
- ✅ **Required Fields**: Mission name, steps/tasks
- ✅ **Step Validation**: Type, required parameters
- ✅ **File Path Validation**: Required paths for create/edit steps
- ✅ **Command Validation**: Required commands for command steps
- ✅ **Language Defaults**: Auto-assigns 'python' for lint/test steps

### Common Validation Errors
```yaml
# ❌ Missing mission name
mission:
  description: "Task without name"  # ERROR: Missing mission name

# ❌ Missing step type
steps:
  - id: broken_step  # ERROR: Missing type/op field

# ❌ Missing file path for create
steps:
  - id: create_step
    type: create  # ERROR: Missing file_path

# ✅ Valid mission
mission:
  name: "Valid Mission"
  steps:
    - id: valid_step
      type: create
      file_path: "output.txt"
      content: "Hello World"
```

### Custom Validation Messages
Invalid missions are moved to `missions_invalid/` with detailed error messages:
```
❌ Invalid mission moved to: missions_invalid/broken_mission_20250803_142300.yaml
   Error: Step step1: missing file_path for create
```

---

## 🎯 Mission Protocol Formats

XO supports **three YAML formats** for maximum flexibility:

### Format 1: Standard Mission Stack (Recommended)
```yaml
mission:
  name: "My Mission"
  description: "Complete workflow description"
  require_approval_on: [critical_step]  # Optional approval gates
  steps:
    - id: step1
      type: test
      language: python
      description: "Run Python tests"
```

### Format 2: Legacy Tasks Format
```yaml
tasks:
  - op: create     # 'op' maps to 'type'
    file: "path"   # 'file' maps to 'file_path'
    edit: "content"  # 'edit' maps to 'content'
```

### Format 3: Simple File Format
```yaml
file: src/simple.py
---
def simple_function():
    return "Created by XO"
```

---

## 🔧 Advanced Usage Patterns

### 🔄 Multi-Language Testing Pipeline
```yaml
mission:
  name: "Full Stack Test Suite"
  steps:
    - id: backend_tests
      type: test
      language: go
      description: "Test Go backend"
    
    - id: frontend_tests
      type: test
      language: javascript
      description: "Test React frontend"
    
    - id: integration_tests
      type: test
      language: python
      min_coverage: 0.85
      description: "Run integration tests"
```

### 🚀 AI-Assisted Development Workflow
```yaml
mission:
  name: "AI-Enhanced Feature Development"
  steps:
    - id: audit_existing
      type: audit
      description: "Check current code quality"
    
    - id: generate_feature
      type: ai_generate
      language: python
      requirements: "Create user authentication module with JWT tokens"
      output_file: "src/auth.py"
    
    - id: test_feature
      type: test
      language: python
      description: "Test new authentication module"
    
    - id: lint_code
      type: lint
      language: python
      description: "Ensure code style compliance"
```

### 🛡️ Error Handling & Recovery
```yaml
mission:
  name: "Resilient Deployment"
  steps:
    - id: backup_db
      type: command
      command: "backup_database.sh"
      description: "Create database backup"
    
    - id: deploy_app
      type: command
      command: "deploy.sh"
      fail_on_error: false  # Continue even if deployment fails
      description: "Attempt application deployment"
    
    - id: verify_deployment
      type: test
      language: python
      description: "Verify deployment success"
    
    - id: rollback_on_failure
      type: command
      command: "if [ $? -ne 0 ]; then rollback.sh; fi"
      description: "Rollback if verification fails"
```

---

## 📊 Output & Logging

### 📝 Audit Trail
- **Location**: `audit_logs/` directory
- **Format**: `{step_id}_{timestamp}.log`
- **Content**: Step details, output, errors, timing

### 🧠 Smart Test Summaries
XO extracts only relevant information from test output:

**Python Example:**
```
=== FAILURES ===
test_auth.py::test_login_invalid FAILED
E   AssertionError: Expected 401, got 200
=== 2 failed, 8 passed in 1.24s ===
```

**Full output saved separately** only on failure for debugging.

### 📋 Context Database
- **SQLite database**: `context.db`
- **Auto-indexes**: Markdown files in `rag_store/`
- **Used for**: AI context retrieval during code generation

---

## 🚨 Troubleshooting

### Common Issues & Solutions

**❌ "Ollama connection failed"**
```bash
# Check if Ollama is running
ollama list
# Start Ollama if needed
ollama serve
```

**❌ "No test runner found"**
```bash
# Install test dependencies
pip install pytest coverage  # Python
go mod tidy                  # Go
npm install                  # JavaScript
```

**❌ "Permission denied on file creation"**
```bash
# Check directory permissions
chmod +w target_directory
```

**❌ "YAML parsing error"**
- Ensure proper indentation (spaces, not tabs)
- Validate YAML syntax with online tools
- Check for special characters in strings

### Mission Queue Troubleshooting

**❌ "No validated missions in queue"**
```bash
# Check if missions were added to inbox
ls missions_inbox/

# Validate inbox again
python executive_officer.py --validate-inbox

# Check queue status
python executive_officer.py --list-queue
```

**❌ "Mission validation failed"**
```bash
# Check invalid missions directory
ls missions_invalid/

# Review validation errors in database
sqlite3 context.db "SELECT mission_name, validation_error FROM mission_queue WHERE status='invalid';"
```

**❌ "Database locked error"**
```bash
# Ensure no other XO instances are running
ps aux | grep executive_officer

# If needed, remove lock (use with caution)
rm context.db-wal context.db-shm
```

**❌ "Mission file not found after queuing"**
- Missions are moved from `missions_inbox/` to their final location after validation
- Check if mission was moved to `missions_invalid/` due to validation failure
- Use `--list-queue` to see current mission file paths

### Debug Mode
```bash
# Enable verbose logging (if implemented)
PYTHONPATH=. python -v executive_officer.py --list-queue

# Check database integrity
sqlite3 context.db ".schema"
sqlite3 context.db "PRAGMA integrity_check;"
```

---

## 🎯 Real-World Examples

### Example 1: Microservice Development
```yaml
mission:
  name: "Microservice CI/CD Pipeline"
  description: "Complete microservice build, test, and deploy"
  require_approval_on: [deploy_prod]
  steps:
    - id: lint_code
      type: lint
      language: go
      description: "Lint Go microservice code"
    
    - id: unit_tests
      type: test
      language: go
      description: "Run unit tests"
    
    - id: build_docker
      type: command
      command: "docker build -t myservice:latest ."
      description: "Build Docker image"
    
    - id: integration_tests
      type: test
      language: python
      description: "Run API integration tests"
    
    - id: deploy_staging
      type: command
      command: "kubectl apply -f k8s/staging/"
      description: "Deploy to staging"
    
    - id: smoke_tests
      type: command
      command: "pytest tests/smoke/ --staging"
      description: "Run smoke tests on staging"
    
    - id: deploy_prod
      type: command
      command: "kubectl apply -f k8s/production/"
      description: "Deploy to production"
```

### Example 2: Documentation Generation
```yaml
mission:
  name: "Auto-Generate Documentation"
  description: "AI-powered documentation pipeline"
  steps:
    - id: analyze_codebase
      type: audit
      description: "Analyze code structure"
    
    - id: generate_api_docs
      type: ai_generate
      language: markdown
      requirements: "Generate API documentation from Python docstrings in src/ directory"
      output_file: "docs/api.md"
      description: "Generate API documentation"
    
    - id: generate_readme
      type: ai_generate
      language: markdown
      requirements: "Create comprehensive README with installation, usage, and examples"
      output_file: "README.md"
      description: "Generate project README"
    
    - id: validate_docs
      type: command
      command: "markdownlint docs/ README.md"
      description: "Validate markdown syntax"
```

### Example 3: Code Quality Gate
```yaml
mission:
  name: "Quality Gate Pipeline"
  description: "Comprehensive code quality checks"
  steps:
    - id: security_scan
      type: command
      command: "bandit -r src/"
      description: "Security vulnerability scan"
    
    - id: complexity_check
      type: command
      command: "radon cc src/ --min B"
      description: "Check cyclomatic complexity"
    
    - id: coverage_test
      type: test
      language: python
      min_coverage: 0.90
      description: "Enforce 90% test coverage"
    
    - id: lint_strict
      type: lint
      language: python
      description: "Strict linting with no warnings"
    
    - id: generate_quality_report
      type: report
      title: "Code Quality Assessment"
      sections: ["security", "complexity", "coverage", "style"]
      output_file: "reports/quality_gate.md"
      description: "Generate quality gate report"
```

---

## 🏆 Best Practices

### ✅ Mission Design
- **Use descriptive step IDs** and descriptions
- **Keep steps atomic** - one responsibility per step
- **Add approval gates** for critical operations
- **Use fail_on_error: false** for optional steps
- **Group related operations** in logical sequence

### 🎯 Mission Queue Management
- **Validate frequently** - Run `--validate-inbox` regularly
- **Monitor invalid missions** - Check `missions_invalid/` for broken missions
- **Use priority wisely** - Reserve high priorities (>5) for critical missions
- **Set dependencies** - Use mission dependencies for proper execution order
- **Clean up completed** - Archive or remove completed missions from queue

### 🔧 Performance Tips
- **Place fast steps first** (lint before tests)
- **Use language-specific test runners** for best summaries
- **Leverage AI context** by organizing docs in `rag_store/`
- **Monitor audit logs** for optimization opportunities
- **Batch validate** - Process multiple missions together for efficiency

### 🛡️ Security Considerations
- **Never commit credentials** in mission files
- **Use environment variables** for sensitive data
- **Review AI-generated code** before production use
- **Set appropriate file permissions** on generated files
- **Validate mission sources** - Only process trusted mission files
- **Monitor invalid missions** - Review quarantined missions for security issues

### 📊 Workflow Integration
```bash
# Daily workflow example
python executive_officer.py --validate-inbox   # Morning validation
python executive_officer.py --list-queue       # Review pending work
python executive_officer.py --run-next         # Execute priority missions

# CI/CD Integration
#!/bin/bash
# validate_and_run.sh
set -e
python executive_officer.py --validate-inbox
if python executive_officer.py --list-queue | grep -q "validated"; then
    python executive_officer.py --run-next
fi
```

### 🔄 Mission Lifecycle Management
```yaml
# Template for production missions
mission:
  name: "Descriptive Mission Name"
  description: "Clear purpose and expected outcomes"
  priority: 1  # 1-10 scale
  dependencies: []  # List of prerequisite missions
  require_approval_on: [critical_step]  # Human oversight
  steps:
    - id: validate_prereqs
      type: audit
      description: "Verify prerequisites"
    
    - id: main_task
      type: command
      command: "main_operation.sh"
      description: "Primary mission objective"
    
    - id: verify_results
      type: test
      language: python
      description: "Validate mission success"
    
    - id: cleanup
      type: command
      command: "cleanup.sh"
      fail_on_error: false  # Allow mission success even if cleanup fails
      description: "Clean up temporary resources"
```

---

*Executive Officer (XO) - Empowering developers with intelligent automation and mission queue management since 2025* 🚀
