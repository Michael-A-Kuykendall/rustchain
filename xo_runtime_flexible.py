import os
import sys
import subprocess
import git
import yaml
import datetime
import sqlite3
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

# Lightweight version with SQLite instead of heavy RAG
from langchain_ollama import OllamaLLM

REPO_PATH = Path(__file__).parent.resolve()
AUDIT_DIR = REPO_PATH / "audit_logs"
RAG_DIR = REPO_PATH / "rag_store"
CONTEXT_DB = REPO_PATH / "context.db"
OLLAMA_ENDPOINT = "http://localhost:11434"

# Initialize simple SQLite context store
def init_context_db():
    """Initialize lightweight SQLite database for context storage"""
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contexts (
            id INTEGER PRIMARY KEY,
            source_file TEXT,
            content_hash TEXT,
            title TEXT,
            content TEXT,
            keywords TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_keywords ON contexts(keywords);
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_title ON contexts(title);
    ''')
    
    conn.commit()
    conn.close()


def run_mission_stack(path: str):
    import yaml

    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)


    mission_block = data.get('mission', data)
    steps = mission_block.get('steps', [])

    llm = OllamaLLM(model='phi', base_url=OLLAMA_ENDPOINT)

    for i, step in enumerate(steps):
        step_id = step.get('id')
        args = step.get('args', {})

        if step_id == 'generate':
            prompt = args.get('prompt', '')
            result = llm(prompt)
            print(f"[{i+1}] generate: {prompt} ->\n{result}")

        elif step_id == 'run_tool':
            name = args.get('name', 'unnamed')
            input_text = args.get('input', '')
            print(f"[{i+1}] run_tool: {name}({input_text}) [stubbed]")

        else:
            print(f"[{i+1}] unknown step id: {step_id}")


    """Index documents from rag_store into SQLite"""
    if not RAG_DIR.exists():
        return
    
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    
    for md_file in RAG_DIR.glob("**/*.md"):
        try:
            with open(md_file, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Calculate content hash to avoid duplicates
            content_hash = hashlib.md5(content.encode()).hexdigest()
            
            # Check if already indexed
            cursor.execute("SELECT id FROM contexts WHERE source_file = ? AND content_hash = ?", 
                         (str(md_file), content_hash))
            if cursor.fetchone():
                continue  # Skip if already indexed
            
            # Extract title (first # heading)
            title = md_file.stem
            lines = content.split('\n')
            for line in lines:
                if line.startswith('# '):
                    title = line[2:].strip()
                    break
            
            # Extract keywords (simple approach)
            keywords = ' '.join([
                'yaml', 'mission', 'runner', 'ai', 'ollama', 'audit', 'test', 'lint',
                'python', 'go', 'javascript', 'typescript', 'git', 'commit', 'patch'
            ])
            
            # Insert into database
            cursor.execute('''
                INSERT OR REPLACE INTO contexts 
                (source_file, content_hash, title, content, keywords)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(md_file), content_hash, title, content, keywords))
            
            print(f"📚 Indexed: {md_file.name}")
            
        except Exception as e:
            print(f"⚠️ Failed to index {md_file}: {e}")
    
    conn.commit()
    conn.close()

def search_context(query: str, limit: int = 3) -> List[Dict[str, str]]:
    """Simple text search in SQLite context store"""
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    
    # Simple text search using LIKE and FTS if available
    search_terms = query.lower().split()
    results = []
    
    for term in search_terms:
        cursor.execute('''
            SELECT title, content, source_file 
            FROM contexts 
            WHERE LOWER(content) LIKE ? OR LOWER(title) LIKE ? OR LOWER(keywords) LIKE ?
            ORDER BY updated_at DESC
            LIMIT ?
        ''', (f'%{term}%', f'%{term}%', f'%{term}%', limit))
        
        results.extend(cursor.fetchall())
    
    conn.close()
    
    # Remove duplicates and return
    unique_results = []
    seen = set()
    for title, content, source_file in results:
        if source_file not in seen:
            unique_results.append({
                'title': title,
                'content': content[:1000] + '...' if len(content) > 1000 else content,
                'source': Path(source_file).name
            })
            seen.add(source_file)
            if len(unique_results) >= limit:
                break
    
    return unique_results

# Initialize AI with just LLM (no embeddings needed)
def initialize_ai():
    try:
        print("🔗 Connecting to Ollama...")
        llm = OllamaLLM(
            model="tinyllama",
            base_url=OLLAMA_ENDPOINT,
            temperature=0.1,
            timeout=10  # Shorter timeout
        )
        # Quick test
        test_response = llm.invoke("Say 'OK'")
        print(f"✅ LLM connected: {test_response.strip()}")
        return llm
    except Exception as e:
        print(f"⚠️ AI initialization failed: {e}")
        return None

# Utility functions
def ensure_dirs():
    AUDIT_DIR.mkdir(exist_ok=True)
    RAG_DIR.mkdir(exist_ok=True)
    # Create missions directory for organized workflow storage
    (REPO_PATH / "missions").mkdir(exist_ok=True)
    (REPO_PATH / "generated").mkdir(exist_ok=True)
    (REPO_PATH / "scripts").mkdir(exist_ok=True)

    init_context_db()

def index_rag_documents():
    """Index documents from rag_store into SQLite"""
    if not RAG_DIR.exists():
        return
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    for md_file in RAG_DIR.glob("**/*.md"):
        try:
            with open(md_file, "r", encoding="utf-8") as f:
                content = f.read()
            # Calculate content hash to avoid duplicates
            content_hash = hashlib.md5(content.encode()).hexdigest()
            # Check if already indexed
            cursor.execute("SELECT id FROM contexts WHERE source_file = ? AND content_hash = ?", 
                         (str(md_file), content_hash))
            if cursor.fetchone():
                continue  # Skip if already indexed
            # Extract title (first # heading)
            title = md_file.stem
            lines = content.split('\n')
            for line in lines:
                if line.startswith('# '):
                    title = line[2:].strip()
                    break
            # Extract keywords (simple approach)
            keywords = ' '.join([
                'yaml', 'mission', 'runner', 'ai', 'ollama', 'audit', 'test', 'lint',
                'python', 'go', 'javascript', 'typescript', 'git', 'commit', 'patch'
            ])
            # Insert into database
            cursor.execute('''
                INSERT OR REPLACE INTO contexts 
                (source_file, content_hash, title, content, keywords)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(md_file), content_hash, title, content, keywords))
            print(f"📚 Indexed: {md_file.name}")
        except Exception as e:
            print(f"⚠️ Failed to index {md_file}: {e}")
    conn.commit()
    conn.close()

def log_audit(step: Dict[str, Any], output: str, error: str = ""):    
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = AUDIT_DIR / f"{step['id']}_{ts}.log"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"STEP: {step['id']}\nDESC: {step.get('description','')}\n\nOUTPUT:\n{output}\n\nERROR:\n{error}\n")

# AI-powered step analysis with lightweight context
def ai_analyze_step(llm, step, context=""):
    if not llm:
        return f"Executing step: {step['id']}"
    
    # Search for relevant context
    context_results = search_context(f"{step['type']} {step.get('description', '')}")
    context_text = ""
    if context_results:
        context_text = "\n".join([f"- {r['title']}: {r['content'][:200]}..." for r in context_results[:2]])
    
    prompt = f"""Analyze this mission step briefly:

STEP: {step['id']} ({step['type']})
DESCRIPTION: {step.get('description', '')}

CONTEXT: {context_text}

Provide a 1-2 sentence analysis of what this step will do and any potential issues."""
    
    try:
        response = llm.invoke(prompt)
        return response[:200] + "..." if len(response) > 200 else response
    except Exception as e:
        return f"AI analysis failed: {e}"

# Core step implementations (same as before but with AI analysis)
def ai_pre_mission_audit(llm):
    blockers = []
    issues = []
    
    for dirpath, _, filenames in os.walk(REPO_PATH):
        for fname in filenames:
            if fname.endswith(('.go', '.py', '.js', '.ts')):
                fpath = Path(dirpath)/fname
                try:
                    with open(fpath, "r", encoding="utf-8", errors='ignore') as f:
                        src = f.read()
                        if any(key in src for key in ['TODO', 'panic(', 'FIXME', 'stub', 'pass  # TODO']):
                            issues.append(str(fpath))
                except Exception as e:
                    print(f"Warning: Could not read {fpath}: {e}")
    
    result = ""
    if issues:
        result += f"Issues found in: {len(issues)} files\n"
        if llm:
            try:
                analysis = llm.invoke(f"Analyze these code issues briefly: {issues[:3]}")
                result += f"AI Analysis: {analysis[:200]}"
            except:
                pass
    
    return len(issues) == 0, result if result else "Clean audit - no issues found"

def ai_generate_code(llm, language, requirements, output_file):
    if not llm:
        return False, "AI code generation not available"
    
    # Get relevant context for code generation
    context_results = search_context(f"{language} code generation {requirements}")
    context_text = ""
    if context_results:
        context_text = f"Reference: {context_results[0]['content'][:300]}"
    
    # Enhanced prompts for different file types
    prompts = {
        'json': f"Generate valid JSON for: {requirements}\n{context_text}\n\nReturn only the JSON, no explanations:",
        'javascript': f"Generate modern JavaScript/ES6+ code for: {requirements}\n{context_text}\n\nInclude proper error handling and comments. Code only:",
        'typescript': f"Generate TypeScript code for: {requirements}\n{context_text}\n\nUse proper types, interfaces, and modern patterns. Code only:",
        'python': f"Generate Python code for: {requirements}\n{context_text}\n\nInclude docstrings and type hints. Code only:",
        'bash': f"Generate bash script for: {requirements}\n{context_text}\n\nInclude error handling and comments. Script only:",
        'yaml': f"Generate YAML configuration for: {requirements}\n{context_text}\n\nValid YAML only:",
        'dockerfile': f"Generate Dockerfile for: {requirements}\n{context_text}\n\nOptimized, multi-stage if needed. Dockerfile only:",
        'nginx': f"Generate nginx configuration for: {requirements}\n{context_text}\n\nComplete nginx config only:",
        'html': f"Generate modern HTML5 for: {requirements}\n{context_text}\n\nSemantic, accessible HTML only:",
        'css': f"Generate modern CSS for: {requirements}\n{context_text}\n\nClean, responsive CSS only:",
        'markdown': f"Generate comprehensive Markdown documentation for: {requirements}\n{context_text}\n\nWell-structured Markdown only:",
        'text': f"Generate text content for: {requirements}\n{context_text}\n\nPlain text only:"
    }
    
    prompt = prompts.get(language.lower(), f"Generate {language} code for: {requirements}\n{context_text}\n\nCode only:")
    
    try:
        code = llm.invoke(prompt)
        
        # Clean up the response (remove code block markers if present)
        code = code.strip()
        if code.startswith('```'):
            lines = code.split('\n')
            if len(lines) > 2:
                code = '\n'.join(lines[1:-1])  # Remove first and last lines
        
        # Save to file
        file_path = REPO_PATH / output_file
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)
        
        return True, f"Code generated and saved to {output_file} ({len(code)} chars)"
    except Exception as e:
        return False, f"Code generation failed: {e}"

def generate_report(logs, llm=None):
    report = "# AI-Enhanced Mission Report\n\n"
    report += f"**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    for log in logs:
        report += f"## Step: {log['step_id']}\n"
        report += f"**Output**: {log['output']}\n"
        if log['error']:
            report += f"**Error**: {log['error']}\n"
        report += "\n---\n\n"
    
    # AI summary if available
    if llm:
        try:
            summary_prompt = f"Summarize this mission execution in 2-3 sentences: {[log['step_id'] for log in logs]}"
            ai_summary = llm.invoke(summary_prompt)
            report = f"# Executive Summary\n{ai_summary}\n\n---\n\n{report}"
        except:
            pass
    
    out_file = AUDIT_DIR / f"mission_report_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(report)
    return True, f"Report generated: {out_file}"

# Other step implementations (same as original)
def run_linter(language="go", llm=None):
    if language == "python":
        try:
            proc = subprocess.run(["flake8", "."], cwd=REPO_PATH, capture_output=True, text=True)
            return proc.returncode == 0, proc.stdout + proc.stderr
        except FileNotFoundError:
            return True, "flake8 not found - skipping linting"
    return True, f"No linter configured for language: {language}"

def run_tests(language="python", min_coverage=0.5, llm=None):
    if language == "python":
        try:
            proc = subprocess.run(["python", "-m", "pytest", "-v"], cwd=REPO_PATH, capture_output=True, text=True)
            return proc.returncode == 0, proc.stdout + proc.stderr
        except Exception as e:
            return False, f"Python test failed: {e}"
    return True, f"No test runner configured for language: {language}"

def create_file_step(file_path, content):
    try:
        file_path = REPO_PATH / file_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True, f"File created: {file_path}"
    except Exception as e:
        return False, f"File creation failed: {e}"

def run_command_step(command, working_dir=None):
    try:
        cwd = REPO_PATH / working_dir if working_dir else REPO_PATH
        proc = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, text=True)
        output = f"Command: {command}\nReturn code: {proc.returncode}\nOutput:\n{proc.stdout}"
        if proc.stderr:
            output += f"\nError:\n{proc.stderr}"
        return proc.returncode == 0, output
    except Exception as e:
        return False, f"Command execution failed: {e}"

# Main lightweight AI mission runner
def main():
    print("🚀 Starting Crew Chief AI Agent...")
    ensure_dirs()

    # Index RAG documents into SQLite
    print("📚 Indexing context documents...")
    index_rag_documents()

    # Initialize AI (LLM only)
    llm = initialize_ai()    # Allow mission file as command line argument
    mission_file = REPO_PATH / (sys.argv[1] if len(sys.argv) > 1 else "mission_stack.yaml")
    if not mission_file.exists():
        print(f"❌ Mission file not found: {mission_file}")
        sys.exit(1)
    
    try:
        with open(mission_file, "r", encoding="utf-8") as f:
            mission_data = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Failed to load mission file: {e}")
        sys.exit(1)

    # Support both schemas: with or without top-level 'mission', and with 'steps' or 'tasks'
    mission_block = mission_data.get('mission', mission_data)
    steps = mission_block.get('steps')
    if steps is None:
        # Try tasks/op legacy format
        tasks = mission_block.get('tasks', [])
        # Convert tasks to steps format
        steps = []
        for idx, task in enumerate(tasks):
            step = dict(task)  # shallow copy
            # Map 'op' to 'type', 'file' to 'file_path', 'edit' to 'content', etc.
            if 'op' in step:
                step['type'] = step.pop('op')
            if 'file' in step:
                step['file_path'] = step.pop('file')
            if 'edit' in step:
                step['content'] = step.pop('edit')
            if 'id' not in step:
                step['id'] = f"step{idx+1}"
            steps.append(step)
    approval_steps = set(mission_block.get('require_approval_on', []))
    logs = []

    print(f"📋 Mission: {mission_block.get('name', 'Unnamed Mission')}")
    print(f"📝 Description: {mission_block.get('description', mission_block.get('description', 'No description'))}")
    print(f"🔧 Steps to execute: {len(steps)}")
    print("=" * 50)

    for i, step in enumerate(steps, 1):
        print(f"\n🔄 Step {i}/{len(steps)}: {step['id']}")
        # Synthesize a description if missing
        desc = step.get('description')
        if not desc:
            # Try to build a description from type/op and file_path/content/command
            t = step.get('type', 'unknown')
            if t in ("create", "create_file") and step.get('file_path'):
                desc = f"Create file {step['file_path']}"
            elif t == "command" and step.get('command'):
                desc = f"Run command: {step['command']}"
            elif t == "ai_generate" and step.get('output_file'):
                desc = f"AI generate {step.get('language', 'code')} to {step['output_file']}"
            elif t == "lint":
                desc = f"Lint code ({step.get('language', 'python')})"
            elif t == "test":
                desc = f"Run tests ({step.get('language', 'python')})"
            elif t == "audit":
                desc = "Pre-mission code audit"
            elif t == "report":
                desc = "Generate mission report"
            else:
                desc = f"Step type: {t}"
        print(f"📄 {desc}")

        # Quick AI analysis
        if llm:
            analysis = ai_analyze_step(llm, step)
            print(f"🤖 {analysis}")

        ok = True
        output = ""
        error = ""


        # Step type dispatch
        if step['type'] == "audit":
            ok, output = ai_pre_mission_audit(llm)
        elif step['type'] == "lint":
            ok, output = run_linter(step.get('language','python'), llm)
        elif step['type'] == "test":
            ok, output = run_tests(step.get('language','python'), step.get('min_coverage',0.5), llm)
        elif step['type'] == "report":
            ok, output = generate_report(logs, llm)
        elif step['type'] in ("create_file", "create", "edit"):
            # Treat 'edit' as an overwrite of the file with the given content
            ok, output = create_file_step(step.get('file_path', ''), step.get('content', ''))
        elif step['type'] == "command":
            ok, output = run_command_step(step.get('command', ''), step.get('working_dir'))
        elif step['type'] == "ai_generate":
            ok, output = ai_generate_code(llm, step.get('language', 'python'), 
                                        step.get('requirements', ''), step.get('output_file', 'generated.py'))
        else:
            output = f"Unknown step type: {step['type']}"
            ok = False

        # Log the step
        log_audit(step, output, error)
        logs.append({"step_id": step['id'], "output": output, "error": error})

        # Display result
        if ok:
            print(f"✅ Success: {output[:100]}{'...' if len(output) > 100 else ''}")
        else:
            print(f"❌ Failed: {error or output}")
            if step.get('fail_on_error', True):
                print("🛑 Mission aborted due to step failure.")
                break

    print("\n" + "=" * 50)
    print("🏁 Crew Chief mission completed!")
    print(f"📊 Audit logs saved to: {AUDIT_DIR}")
    print(f"🗄️ Context database: {CONTEXT_DB}")

if __name__ == "__main__":
    main()
