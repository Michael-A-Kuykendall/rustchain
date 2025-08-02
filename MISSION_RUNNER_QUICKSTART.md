# Mission Runner Quick Start Guide - Dreaming Protocol

## 🚀 Getting Started

### Files in Your Directory
dreaming-protocol/
├── lightweight_ai_agent.py      # Main mission runner engine
├── simple_mission_gui.py        # GUI interface (optional)
├── context_inspector.py         # SQLite context database viewer
├── missions/                    # Your mission files go here
│   ├── web_react_setup.yaml    # Example: React project setup
│   └── web_deploy.yaml         # Example: Deployment workflow
├── MissionRunner-OneClick/      # Portable executable package
│   ├── MissionRunner.exe       # Standalone GUI application
│   ├── install.bat             # One-click installer
│   └── README.md               # Installation instructions
└── install_simple_mission_runner.bat  # Setup script for new systems
```

```
<your-project-root>/
├── lightweight_ai_agent.py      # Main mission runner engine
├── simple_mission_gui.py        # GUI interface (optional)
├── context_inspector.py         # SQLite context database viewer
├── missions/                    # Your mission files go here
│   ├── web_react_setup.yaml    # Example: React project setup
│   └── web_deploy.yaml         # Example: Deployment workflow
├── MissionRunner-OneClick/      # Portable executable package
│   ├── MissionRunner.exe       # Standalone GUI application
│   ├── install.bat             # One-click installer
│   └── README.md               # Installation instructions
└── install_simple_mission_runner.bat  # Setup script for new systems
```

## 🎯 Quick Usage

### Run a Mission (Command Line)
```bash
cd <your-project-root>
python lightweight_ai_agent.py missions/your_mission.yaml
```

### Run with GUI
```bash
python simple_mission_gui.py
```

### Use Portable Executable
```bash
./MissionRunner-OneClick/MissionRunner.exe
```

## 🧠 AI Configuration

### Current Setup (Optimized for Small Tasks)
- **Primary AI**: TinyLlama 1.1b (637MB) - Fast, deterministic, perfect for automation
- **Backup AI**: phi3:mini (2.2GB) - Available if needed for complex analysis
- **Database**: SQLite context store (16KB) - No heavy RAG overhead
- **Connection**: Ollama at `http://localhost:11434`
- **Context**: Automatic project file indexing into SQLite for AI retrieval

### AI Model Selection Strategy
- **TinyLlama**: Use for code generation, simple analysis, deterministic tasks
- **phi3:mini**: Use for complex reasoning, analysis, debugging help
- **Context Window**: Models work with project-specific context from SQLite

### Check AI Status
```bash
ollama list  # See available models
ollama ps    # See running models
ollama pull tinyllama:1.1b  # Install primary model if needed
```

### AI Context System
The system automatically:
1. Indexes all project files into SQLite context database
2. Retrieves relevant context for each mission step
3. Provides AI with project-specific knowledge
4. Logs AI insights and recommendations for each step

## 📝 Mission File Structure

### Basic Template
```yaml
env: dev
mission:
  name: "Your Mission Name"
  description: "What this mission accomplishes"
  steps:
    - id: step_1
      type: ai_generate
      language: python
      requirements: "Create a simple hello world function"
      output_file: "hello.py"
      description: "Generate hello world"
    
    - id: step_2
      type: command
      command: "python hello.py"
      description: "Run the generated script"
```

### Step Types Available

#### Core Steps
```yaml
- id: audit_code
  type: audit
  fail_on_blocker: true
  description: "Scans codebase for issues and blockers"

- id: lint_code
  type: lint
  language: python
  description: "Runs language-specific linters with AI analysis"

- id: run_tests
  type: test
  language: python
  min_coverage: 0.8
  description: "Executes test suites with coverage analysis"

- id: apply_patch
  type: patch
  patch_file: "fixes.patch"
  description: "Applies patches to codebase"

- id: commit_changes
  type: commit
  message: "Add new feature"
  description: "Creates git commits"

- id: run_command
  type: command
  command: "npm install"
  description: "Executes shell commands"
```

#### AI-Enhanced Steps
```yaml
- id: generate_code
  type: ai_generate
  language: python|javascript|typescript|go|yaml|json|rust|bash|markdown
  requirements: "Detailed description of what to generate"
  output_file: "path/to/output/file.py"
  description: "Uses LLM to generate code based on requirements"

- id: create_report
  type: report
  title: "Analysis Report"
  sections: ["overview", "findings", "recommendations"]
  output_file: "analysis_report.md"
  description: "Creates comprehensive reports with AI summaries"
```

#### Mission Control Features
```yaml
mission:
  name: "Mission Name"
  description: "What this mission accomplishes"
  steps: [...]
  require_approval_on: [step_id_1, step_id_2]  # Human approval gates for critical steps
```

## 🎨 Real-World Examples

### 1. Simple Python Project Setup
```yaml
env: dev
mission:
  name: "Python Project Bootstrap"
  description: "Create a new Python project with testing"
  steps:
    - id: create_main
      type: ai_generate
      language: python
      requirements: "Create a main.py with a Calculator class that has add, subtract, multiply, divide methods"
      output_file: "main.py"
      description: "Generate main calculator module"
    
    - id: create_tests
      type: ai_generate
      language: python
      requirements: "Create comprehensive unit tests for the Calculator class using pytest"
      output_file: "test_calculator.py"
      description: "Generate test suite"
    
    - id: create_requirements
      type: ai_generate
      language: text
      requirements: "Create requirements.txt with pytest and any other needed dependencies"
      output_file: "requirements.txt"
      description: "Generate dependency list"
    
    - id: install_deps
      type: command
      command: "pip install -r requirements.txt"
      description: "Install project dependencies"
    
    - id: run_tests
      type: command
      command: "python -m pytest test_calculator.py -v"
      description: "Execute test suite"
```

### 2. Web Development Workflow
```yaml
env: dev
mission:
  name: "Express API Setup"
  description: "Bootstrap Express.js API with TypeScript"
  steps:
    - id: create_package
      type: ai_generate
      language: json
      requirements: "Create package.json for Express + TypeScript + Jest + ESLint + Prettier"
      output_file: "package.json"
      description: "Generate package configuration"
    
    - id: create_server
      type: ai_generate
      language: typescript
      requirements: "Create Express server with basic routes for users (GET, POST, PUT, DELETE) and error handling"
      output_file: "src/server.ts"
      description: "Generate main server file"
    
    - id: create_types
      type: ai_generate
      language: typescript
      requirements: "Create TypeScript interfaces for User model and API responses"
      output_file: "src/types.ts"
      description: "Generate type definitions"
    
    - id: install_deps
      type: command
      command: "npm install"
      description: "Install all dependencies"
    
    - id: compile_ts
      type: command
      command: "npx tsc --noEmit"
      description: "Check TypeScript compilation"
```

### 3. Documentation Generation
```yaml
env: dev
mission:
  name: "Project Documentation"
  description: "Generate comprehensive project documentation"
  steps:
    - id: scan_codebase
      type: audit
      description: "Analyze current codebase structure"
    
    - id: generate_readme
      type: ai_generate
      language: markdown
      requirements: "Create comprehensive README.md with installation, usage, API docs, and examples based on the codebase"
      output_file: "README.md"
      description: "Generate project README"
    
    - id: generate_api_docs
      type: ai_generate
      language: markdown
      requirements: "Create API documentation with endpoints, request/response examples, and error codes"
      output_file: "docs/API.md"
      description: "Generate API documentation"
    
    - id: generate_contributing
      type: ai_generate
      language: markdown
      requirements: "Create CONTRIBUTING.md with development setup, coding standards, and PR process"
      output_file: "CONTRIBUTING.md"
      description: "Generate contribution guide"
```

## 🔧 Pro Tips & Best Practices

### Mission Design
1. **Start Small**: Begin with 2-3 steps, then expand
2. **Clear Descriptions**: Make each step's purpose obvious
3. **Logical Flow**: Order steps in dependency sequence
4. **Error Handling**: Use `fail_on_blocker: true` for critical steps

### AI Requirements Writing
```yaml
# ❌ Vague
requirements: "Make a function"

# ✅ Specific
requirements: "Create a Python function called 'process_data' that takes a list of dictionaries, filters out entries where 'status' is 'inactive', and returns the count of remaining items"
```

### File Organization
```
missions/
├── setup/           # Project bootstrapping missions
├── development/     # Daily development workflows  
├── deployment/      # Build and deploy missions
├── maintenance/     # Cleanup and update missions
└── templates/       # Reusable mission templates
```

### Context Management
- The system automatically indexes your project files into SQLite
- Place relevant docs in your project for AI context
- Use descriptive variable names and comments in generated code
- The AI learns from your project structure

### AI Integration Best Practices
1. **Start with Audit Steps**: Always begin missions with `audit` to understand current state
2. **Leverage AI Analysis**: Use AI-generated steps for repetitive code creation
3. **Review AI Output**: Always review AI analysis output for insights
4. **Test Failure Analysis**: Let AI help diagnose test failures and suggest fixes
5. **Documentation Context**: Place relevant documentation in project for AI context

### Security & Approval Gates
1. **Human Approval for Critical Steps**: Use `require_approval_on: [step_ids]` for:
   - Commits and patches
   - Destructive operations
   - Production deployments
2. **Audit Before Changes**: Always run audits before making changes
3. **Review Generated Code**: Inspect AI-generated code before execution
4. **Use Blockers**: Set `fail_on_blocker: true` for critical audit steps

### Advanced Mission Patterns
```yaml
# Mission with approval gates
mission:
  name: "Production Deploy"
  require_approval_on: [deploy_step, commit_step]
  steps:
    - id: audit
      type: audit
      fail_on_blocker: true
    - id: commit_step
      type: commit
      message: "Deploy v1.0"
    - id: deploy_step
      type: command
      command: "docker deploy prod"
```

### Step Failure Analysis
Understanding common failure patterns helps the AI diagnose issues:

#### Audit Failures
- **TODO/FIXME Detection**: Usually indicate incomplete code
- **Security Issues**: Potential vulnerabilities or bad practices
- **Dependency Problems**: Missing or outdated dependencies

#### Lint Failures  
- **Code Style Issues**: Formatting, naming conventions
- **Static Analysis**: Type errors, unused variables, imports
- **Complexity Warnings**: Functions too long or complex

#### Test Failures
- **Breaking Changes**: API changes affecting existing tests
- **Coverage Issues**: Insufficient test coverage (below min_coverage)
- **Environment Problems**: Missing test dependencies or setup

#### Patch Failures
- **Merge Conflicts**: Code has changed since patch creation
- **Missing Files**: Patch references non-existent files
- **Permission Issues**: Cannot write to target files

## 🚨 Troubleshooting

### Common Issues

#### AI Not Responding
```bash
# Check Ollama status
ollama ps

# Start Ollama if needed
ollama serve

# Verify TinyLlama is available
ollama list | grep tinyllama
```

#### Mission File Errors
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('missions/your_mission.yaml'))"
```

#### Generated Code Issues
- The AI uses TinyLlama for speed and consistency
- For complex code, break into smaller, specific requirements
- Review and edit generated files as needed
- Use the context inspector: `python context_inspector.py`

### Debug Mode
```bash
# Run with verbose output
python lightweight_ai_agent.py missions/your_mission.yaml --verbose
```

## 🎯 Next Steps

1. **Try the Examples**: Run the existing missions in `missions/`
2. **Create Your First Mission**: Start with a simple 2-step workflow
3. **Explore the GUI**: Use `python simple_mission_gui.py` for easier mission creation
4. **Check the Context**: Use `python context_inspector.py` to see what the AI knows about your project
5. **Scale Up**: Build more complex multi-step automation workflows

## 📊 System Status

- **Database**: `context.db` (16KB SQLite database)
- **Logs**: `audit_logs/` (detailed execution logs)
- **Generated Files**: Created in your current directory
- **AI Model**: TinyLlama 1.1b (optimized for automation tasks)

The Mission Runner is designed to be your AI-powered development assistant - start simple and gradually build more sophisticated automation workflows! 🚀
