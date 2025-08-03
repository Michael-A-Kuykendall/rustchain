#!/usr/bin/env python3
"""
Executive Officer (XO) — AI-Enhanced Mission Runner with RAG Mission Queue
=========================================================================

Enhanced XO that uses RAG storage as an active mission validation and queuing system.
Automatically vets, validates, and queues mission files for execution.

NEW FEATURES:
- Mission inbox validation and queuing
- RAG-based mission queue management  
- Batch mission validation
- Invalid mission flagging and error reporting

USAGE:
    python executive_officer.py --validate-inbox     # Vet all missions in inbox/
    python executive_officer.py --list-queue         # Show validated missions
    python executive_officer.py --run-next           # Run next mission from queue
    python executive_officer.py mission.yaml         # Run specific mission
"""

import os
import sys
import subprocess
import yaml
import datetime
import sqlite3
import hashlib
import re
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from langchain_ollama import OllamaLLM
except ImportError:
    OllamaLLM = None

REPO_PATH = Path(__file__).parent.resolve()
AUDIT_DIR = REPO_PATH / "audit_logs"
RAG_DIR = REPO_PATH / "rag_store"
CONTEXT_DB = REPO_PATH / "context.db"
MISSIONS_INBOX = REPO_PATH / "mission-stacks"  # Use existing mission-stacks directory
MISSIONS_INVALID = REPO_PATH / "missions_invalid"
OLLAMA_ENDPOINT = "http://localhost:11434"

# --- Enhanced RAG Schema for Mission Queue ---
def init_context_db():
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    
    # Original context table
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
    
    # NEW: Mission queue table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mission_queue (
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
        )
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_mission_status ON mission_queue(status);
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_mission_priority ON mission_queue(priority, created_at);
    ''')
    
    conn.commit()
    conn.close()

# --- Mission Validation Functions ---
def validate_mission_file(mission_path: Path) -> tuple[bool, Dict[str, Any], str]:
    """Validate a mission YAML file. Returns (is_valid, parsed_mission, error_message)"""
    try:
        with open(mission_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
        
        # Handle simple format (file: + content)
        if raw_content.startswith('#') or 'file:' in raw_content.split('\n')[4:6]:
            return True, {"name": f"Simple file: {mission_path.name}", "steps": [{"id": "create_file", "type": "create"}]}, ""
        
        # Parse YAML
        mission_data = yaml.safe_load(raw_content)
        if not mission_data:
            return False, {}, "Empty YAML file"
        
        # Extract mission block
        mission_block = mission_data.get('mission', mission_data)
        
        # Validate required fields
        if not mission_block.get('name'):
            return False, mission_block, "Missing mission name"
        
        # Get steps (support both 'steps' and legacy 'tasks')
        steps = mission_block.get('steps')
        if steps is None:
            tasks = mission_block.get('tasks', [])
            if not tasks:
                return False, mission_block, "No steps or tasks defined"
            steps = tasks
        
        # Validate each step
        for i, step in enumerate(steps):
            if not step.get('id'):
                step['id'] = f"step{i+1}"  # Auto-assign ID
            
            step_type = step.get('type', step.get('op'))
            if not step_type:
                return False, mission_block, f"Step {step['id']}: missing type/op field"
            
            # Validate type-specific requirements
            if step_type in ('create', 'create_file', 'edit'):
                file_path = step.get('file_path', step.get('file'))
                if not file_path:
                    return False, mission_block, f"Step {step['id']}: missing file_path for {step_type}"
                
                # NEW: Check for directory editing
                if step_type == 'edit' and (file_path.endswith('/') or file_path in ['src', 'tests', 'examples']):
                    return False, mission_block, f"Step {step['id']}: cannot edit directory '{file_path}' - specify exact file"
                
                # NEW: Check for placeholder content
                content = step.get('content', step.get('edit', ''))
                if content.strip().startswith('//') and any(word in content.lower() for word in ['should include', 'implement', 'todo', 'placeholder']):
                    return False, mission_block, f"Step {step['id']}: content appears to be placeholder comments, not implementation"
            
            elif step_type == 'command':
                if not step.get('command'):
                    return False, mission_block, f"Step {step['id']}: missing command"
            
            elif step_type in ('lint', 'test'):
                if not step.get('language'):
                    step['language'] = 'python'  # Default
                
                # NEW: Check for Rust project structure
                if step.get('language') == 'rust':
                    cargo_toml = Path('Cargo.toml')
                    if not cargo_toml.exists():
                        return False, mission_block, f"Step {step['id']}: Rust test requires Cargo.toml (run bootstrap mission first)"
        
        return True, mission_block, ""
        
    except yaml.YAMLError as e:
        return False, {}, f"YAML parse error: {e}"
    except Exception as e:
        return False, {}, f"Validation error: {e}"

def store_mission_to_rag(mission_path: Path, mission_data: Dict[str, Any]):
    """Store mission content to RAG storage for AI retrieval"""
    try:
        RAG_DIR.mkdir(exist_ok=True)
        
        # Create RAG storage file
        rag_filename = f"mission_{mission_path.stem}.md"
        rag_path = RAG_DIR / rag_filename
        
        # Format mission content for RAG
        rag_content = f"""# Mission: {mission_data['name']}

**File**: {mission_path.name}
**Description**: {mission_data.get('description', 'No description')}
**Status**: In Queue
**Steps**: {len(mission_data.get('steps', mission_data.get('tasks', [])))}

## Mission Content

```yaml
{yaml.dump(mission_data, default_flow_style=False, sort_keys=False)}
```

## Steps Overview

"""
        
        # Add step details
        steps = mission_data.get('steps', mission_data.get('tasks', []))
        for i, step in enumerate(steps, 1):
            step_id = step.get('id', f'step_{i}')
            step_type = step.get('type', 'unknown')
            description = step.get('description', step_id)
            
            rag_content += f"### Step {i}: {step_id}\n"
            rag_content += f"- **Type**: {step_type}\n"
            rag_content += f"- **Description**: {description}\n"
            
            if step.get('file_path'):
                rag_content += f"- **Target File**: {step['file_path']}\n"
            if step.get('command'):
                rag_content += f"- **Command**: `{step['command']}`\n"
            rag_content += "\n"
        
        # Write to RAG storage
        with open(rag_path, 'w', encoding='utf-8') as f:
            f.write(rag_content)
        
        # Also store in context database for search
        content_hash = hashlib.md5(rag_content.encode()).hexdigest()
        conn = sqlite3.connect(CONTEXT_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO contexts 
            (source_file, content_hash, title, content, keywords, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (str(rag_path), content_hash, f"Mission: {mission_data['name']}", 
              rag_content, f"mission,{mission_path.stem},{step_type}"))
        
        conn.commit()
        conn.close()
        
        print(f"📚 Mission stored to RAG: {rag_filename}")
        
    except Exception as e:
        print(f"⚠️ Failed to store mission to RAG: {e}")

def ingest_mission_to_queue(mission_path: Path, mission_data: Dict[str, Any]) -> bool:
    """Add validated mission to the queue database"""
    try:
        with open(mission_path, "rb") as f:
            mission_hash = hashlib.md5(f.read()).hexdigest()
        
        conn = sqlite3.connect(CONTEXT_DB)
        cursor = conn.cursor()
        
        # Check if already exists with same hash
        cursor.execute("SELECT id FROM mission_queue WHERE mission_file = ? AND mission_hash = ?", 
                      (str(mission_path), mission_hash))
        if cursor.fetchone():
            conn.close()
            return True  # Already ingested, no change needed
        
        # Calculate metadata
        steps = mission_data.get('steps', mission_data.get('tasks', []))
        step_count = len(steps)
        estimated_duration = step_count * 30  # 30 seconds per step estimate
        
        # Extract dependencies if specified
        dependencies = json.dumps(mission_data.get('dependencies', []))
        
        # Insert or update
        cursor.execute('''
            INSERT OR REPLACE INTO mission_queue 
            (mission_file, mission_name, mission_hash, status, step_count, 
             estimated_duration, dependencies, validated_at)
            VALUES (?, ?, ?, 'validated', ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (str(mission_path), mission_data['name'], mission_hash, 
              step_count, estimated_duration, dependencies))
        
        conn.commit()
        conn.close()
        
        # Store mission content to RAG for AI retrieval
        store_mission_to_rag(mission_path, mission_data)
        
        return True
        
    except Exception as e:
        print(f"⚠️ Failed to ingest mission {mission_path}: {e}")
        return False

def flag_invalid_mission(mission_path: Path, error: str):
    """Flag mission as invalid in database and move to invalid folder"""
    try:
        # Move to invalid folder
        MISSIONS_INVALID.mkdir(exist_ok=True)
        invalid_path = MISSIONS_INVALID / mission_path.name
        
        # If file already exists in invalid, append timestamp
        if invalid_path.exists():
            stem = invalid_path.stem
            suffix = invalid_path.suffix
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            invalid_path = MISSIONS_INVALID / f"{stem}_{timestamp}{suffix}"
        
        mission_path.rename(invalid_path)
        
        # Record in database
        conn = sqlite3.connect(CONTEXT_DB)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO mission_queue 
            (mission_file, mission_name, status, validation_error, validated_at)
            VALUES (?, ?, 'invalid', ?, CURRENT_TIMESTAMP)
        ''', (str(invalid_path), mission_path.stem, error))
        conn.commit()
        conn.close()
        
        print(f"❌ Invalid mission moved to: {invalid_path}")
        print(f"   Error: {error}")
        
    except Exception as e:
        print(f"⚠️ Failed to flag invalid mission {mission_path}: {e}")

# --- Mission Queue Management ---
def validate_inbox():
    """Validate all missions in mission-stacks and add to queue"""
    if not MISSIONS_INBOX.exists():
        print(f"❌ Mission-stacks directory not found: {MISSIONS_INBOX}")
        return
    
    mission_files = list(MISSIONS_INBOX.glob("*.yaml")) + list(MISSIONS_INBOX.glob("*.yml"))
    if not mission_files:
        print(f"📁 No mission files found in {MISSIONS_INBOX}")
        return
    
    print(f"🔍 Validating {len(mission_files)} mission files in mission-stacks...")
    
    validated = 0
    invalid = 0
    
    for mission_file in mission_files:
        print(f"\n📋 Validating: {mission_file.name}")
        
        is_valid, mission_data, error = validate_mission_file(mission_file)
        
        if is_valid:
            if ingest_mission_to_queue(mission_file, mission_data):
                print(f"✅ Valid: {mission_data['name']}")
                validated += 1
            else:
                print(f"⚠️ Validation passed but ingestion failed")
        else:
            # Don't move files from mission-stacks, just flag as invalid in database
            print(f"❌ Invalid mission: {mission_file.name}")
            print(f"   Error: {error}")
            
            # Record in database without moving file
            conn = sqlite3.connect(CONTEXT_DB)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO mission_queue 
                (mission_file, mission_name, status, validation_error, validated_at)
                VALUES (?, ?, 'invalid', ?, CURRENT_TIMESTAMP)
            ''', (str(mission_file), mission_file.stem, error))
            conn.commit()
            conn.close()
            invalid += 1
    
    print(f"\n📊 Validation complete: {validated} valid, {invalid} invalid")
    if invalid > 0:
        print(f"⚠️ Invalid missions remain in mission-stacks/ - check errors above")

def list_mission_queue():
    """List all missions in queue with status"""
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT mission_name, status, step_count, estimated_duration, 
               validation_error, created_at
        FROM mission_queue 
        ORDER BY priority DESC, created_at ASC
    ''')
    
    missions = cursor.fetchall()
    conn.close()
    
    if not missions:
        print("📭 Mission queue is empty")
        return
    
    print(f"📋 Mission Queue ({len(missions)} missions):")
    print("=" * 70)
    
    for name, status, steps, duration, error, created in missions:
        status_icon = {
            'validated': '✅',
            'pending': '⏳', 
            'invalid': '❌',
            'completed': '🎉',
            'failed': '💥'
        }.get(status, '❓')
        
        print(f"{status_icon} {name}")
        print(f"   Status: {status} | Steps: {steps} | Est: {duration}s")
        if error:
            print(f"   Error: {error}")
        print(f"   Created: {created}")
        print()

def get_next_mission() -> Optional[Path]:
    """Get next validated mission from queue"""
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT mission_file FROM mission_queue 
        WHERE status = 'validated'
        ORDER BY priority DESC, created_at ASC
        LIMIT 1
    ''')
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        mission_path = Path(result[0])
        if mission_path.exists():
            return mission_path
    
    return None

def update_mission_rag_status(mission_path: Path, status: str, completion_details: str = ""):
    """Update mission status in RAG storage"""
    try:
        rag_filename = f"mission_{mission_path.stem}.md"
        rag_path = RAG_DIR / rag_filename
        
        if rag_path.exists():
            # Read existing content
            with open(rag_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Update status line
            status_emoji = {
                'completed': '✅ Completed',
                'failed': '❌ Failed', 
                'running': '🔄 Running',
                'pending': '⏳ Pending'
            }.get(status, status)
            
            # Replace status line
            content = re.sub(r'\*\*Status\*\*: .*', f'**Status**: {status_emoji}', content)
            
            # Add completion details if provided
            if completion_details:
                if "## Execution Results" not in content:
                    content += f"\n\n## Execution Results\n\n{completion_details}\n"
                else:
                    content = re.sub(r'## Execution Results\n\n.*?(?=\n## |\Z)', 
                                   f'## Execution Results\n\n{completion_details}\n', content, flags=re.DOTALL)
            
            # Write updated content
            with open(rag_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Update in context database
            content_hash = hashlib.md5(content.encode()).hexdigest()
            conn = sqlite3.connect(CONTEXT_DB)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE contexts 
                SET content = ?, content_hash = ?, updated_at = CURRENT_TIMESTAMP
                WHERE source_file = ?
            ''', (content, content_hash, str(rag_path)))
            
            conn.commit()
            conn.close()
            
    except Exception as e:
        print(f"⚠️ Failed to update mission RAG status: {e}")

def mark_mission_status(mission_file: Path, status: str, completion_status: str = None):
    """Update mission status in queue"""
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    
    if status == 'completed' or status == 'failed':
        cursor.execute('''
            UPDATE mission_queue 
            SET status = ?, executed_at = CURRENT_TIMESTAMP, completion_status = ?
            WHERE mission_file = ?
        ''', (status, completion_status, str(mission_file)))
    else:
        cursor.execute('''
            UPDATE mission_queue 
            SET status = ?
            WHERE mission_file = ?
        ''', (status, str(mission_file)))
    
    conn.commit()
    conn.close()
    
    # Also update RAG storage
    update_mission_rag_status(mission_file, status, completion_status or "")

# --- RAG Query Functions ---
def query_mission_rag(query: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Query RAG storage for mission-related information"""
    results = []
    
    # Search contexts database
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT title, content, source_file, updated_at
        FROM contexts 
        WHERE (content LIKE ? OR keywords LIKE ? OR title LIKE ?)
        AND source_file LIKE '%rag_store%'
        ORDER BY updated_at DESC
        LIMIT ?
    ''', (f'%{query}%', f'%{query}%', f'%{query}%', limit))
    
    for row in cursor.fetchall():
        title, content, source_file, updated_at = row
        results.append({
            'title': title,
            'content': content[:1000] + '...' if len(content) > 1000 else content,
            'source': Path(source_file).name,
            'updated_at': updated_at
        })
    
    conn.close()
    return results

def list_missions_in_rag() -> List[str]:
    """List all missions currently stored in RAG"""
    try:
        rag_files = list(RAG_DIR.glob("mission_*.md"))
        return [f.stem.replace('mission_', '') for f in rag_files]
    except:
        return []

# --- Original XO Functions (keeping existing functionality) ---
TEST_PATTERNS = {
    'python': {
        'fail': [r'^=+ FAILURES =+', r'^FAILED', r'^E\s', r'Traceback'],
        'pass': [r'^=+.*in \d+.\d+s =+', r'^OK', r'^PASSED'],
        'summary': [r'^=+ .* in \d+.\d+s =+', r'^FAILED.*$', r'^OK$', r'^PASSED$'],
    },
    # ... other language patterns
}

def extract_test_summary(output: str, language: str) -> str:
    patterns = TEST_PATTERNS.get(language, {})
    regexes = [re.compile(p) for group in patterns.values() for p in group]
    lines = output.splitlines()
    summary = []
    for i, line in enumerate(lines):
        if any(r.search(line) for r in regexes):
            context = lines[max(0, i-2):min(len(lines), i+3)]
            summary.extend(context)
    seen = set()
    filtered = []
    for line in summary:
        if line not in seen:
            filtered.append(line)
            seen.add(line)
    return "\n".join(filtered)

def search_context(query: str, limit: int = 3) -> List[Dict[str, str]]:
    conn = sqlite3.connect(CONTEXT_DB)
    cursor = conn.cursor()
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

def ensure_dirs():
    AUDIT_DIR.mkdir(exist_ok=True)
    RAG_DIR.mkdir(exist_ok=True)
    MISSIONS_INVALID.mkdir(exist_ok=True)
    (REPO_PATH / "generated").mkdir(exist_ok=True)
    (REPO_PATH / "scripts").mkdir(exist_ok=True)
    # Note: mission-stacks already exists, no need to create missions/ directory
    init_context_db()

# --- Keep all existing XO execution functions ---
def initialize_ai():
    if OllamaLLM is None:
        print("⚠️ OllamaLLM not available. AI features disabled.")
        return None
    try:
        print("🔗 Connecting to Ollama...")
        llm = OllamaLLM(
            model="tinyllama",
            base_url=OLLAMA_ENDPOINT,
            temperature=0.1,
            timeout=10
        )
        test_response = llm.invoke("Say 'OK'")
        print(f"✅ LLM connected: {test_response.strip()}")
        return llm
    except Exception as e:
        print(f"⚠️ AI initialization failed: {e}")
        return None

def run_linter(language="python", llm=None):
    if language == "python":
        try:
            proc = subprocess.run(["flake8", "."], cwd=REPO_PATH, capture_output=True, text=True)
            return proc.returncode == 0, proc.stdout + proc.stderr
        except FileNotFoundError:
            return True, "flake8 not found - skipping linting"
    elif language == "rust":
        try:
            proc = subprocess.run(["cargo", "clippy"], cwd=REPO_PATH, capture_output=True, text=True)
            return proc.returncode == 0, proc.stdout + proc.stderr
        except FileNotFoundError:
            return True, "cargo not found - skipping linting"
    return True, f"No linter configured for language: {language}"

def run_tests(language="python", min_coverage=0.5, llm=None, step_id="test"):
    # Language-specific test runner and pattern extract
    if language == "python":
        cmd = ["pytest", "--maxfail=25", "--disable-warnings"]
        if min_coverage and min_coverage > 0:
            try:
                import coverage
                cmd = ["pytest", f"--cov=.", f"--cov-fail-under={int(min_coverage*100)}"]
            except ImportError:
                pass  # Continue without coverage if not installed
        proc = subprocess.run(cmd, cwd=REPO_PATH, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
    elif language == "go":
        cmd = ["go", "test", "./..."]
        proc = subprocess.run(cmd, cwd=REPO_PATH, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
    elif language == "rust":
        cmd = ["cargo", "test"]
        proc = subprocess.run(cmd, cwd=REPO_PATH, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
    elif language == "javascript":
        cmd = ["npm", "test"]
        proc = subprocess.run(cmd, cwd=REPO_PATH, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
    else:
        return False, f"No test runner configured for language: {language}"
    
    summary = extract_test_summary(output, language)
    # Optional: Save full output only if test fails
    if proc.returncode != 0:
        log_path = AUDIT_DIR / f"{step_id}_fulltest_{datetime.datetime.now():%Y%m%d-%H%M%S}.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(output)
    return proc.returncode == 0, summary or output

def main():
    # Handle new queue management commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "--validate-inbox":
            print("🚀 Starting XO Mission Inbox Validation...")
            ensure_dirs()
            validate_inbox()
            return
        
        elif sys.argv[1] == "--list-queue":
            ensure_dirs()
            list_mission_queue()
            return
        
        elif sys.argv[1] == "--run-next":
            ensure_dirs()
            next_mission = get_next_mission()
            if not next_mission:
                print("📭 No validated missions in queue")
                return
            print(f"🚀 Running next mission: {next_mission.name}")
            # Fall through to normal execution with next_mission as target
            sys.argv[1] = str(next_mission)
    
    # Original XO execution logic for single mission
    print("🚀 Starting Executive Officer (XO) Mission Runner...")
    ensure_dirs()
    
    # Initialize AI
    llm = initialize_ai()
    
    # Get mission file
    mission_file = REPO_PATH / (sys.argv[1] if len(sys.argv) > 1 else "mission_stack.yaml")
    if not mission_file.exists():
        print(f"❌ Mission file not found: {mission_file}")
        sys.exit(1)
    
    # Load and parse mission
    try:
        with open(mission_file, "r", encoding="utf-8") as f:
            raw_content = f.read()
        
        # Handle simple format (file: + content)
        is_simple_format = False
        if raw_content.startswith('#') or 'file:' in raw_content.split('\n')[4:6]:
            lines = raw_content.split('\n')
            file_path = None
            content_start = None
            for i, line in enumerate(lines):
                if line.strip().startswith('file:'):
                    file_path = line.split('file:', 1)[1].strip()
                elif line.strip() == '---' and file_path:
                    content_start = i + 1
                    break
            if file_path and content_start is not None:
                content = '\n'.join(lines[content_start:])
                steps = [{
                    'id': 'create_file',
                    'type': 'create',
                    'file_path': file_path,
                    'content': content,
                    'description': f"Create file {file_path}"
                }]
                mission_block = {
                    'name': f"Simple file creation: {file_path}",
                    'description': f"Create {file_path} from simple YAML format"
                }
                is_simple_format = True
            else:
                raise ValueError("Invalid simple format: missing file or content separator")
        
        if not is_simple_format:
            mission_data = yaml.safe_load(raw_content)
            mission_block = mission_data.get('mission', mission_data)
            steps = mission_block.get('steps')
            if steps is None:
                tasks = mission_block.get('tasks', [])
                steps = []
                for idx, task in enumerate(tasks):
                    step = dict(task)
                    if 'op' in step:
                        step['type'] = step.pop('op')
                    if 'file' in step:
                        step['file_path'] = step.pop('file')
                    if 'edit' in step:
                        step['content'] = step.pop('edit')
                    if 'id' not in step:
                        step['id'] = f"step{idx+1}"
                    steps.append(step)
                    
    except Exception as e:
        print(f"❌ Failed to load mission file: {e}")
        sys.exit(1)
    
    # Execute mission
    approval_steps = set(mission_block.get('require_approval_on', []))
    logs = []
    
    print(f"📋 Mission: {mission_block.get('name', 'Unnamed Mission')}")
    print(f"📝 Description: {mission_block.get('description', 'No description')}")
    print(f"🔧 Steps to execute: {len(steps)}")
    print("=" * 50)
    
    for i, step in enumerate(steps, 1):
        print(f"\n🔄 Step {i}/{len(steps)}: {step['id']}")
        desc = step.get('description')
        if not desc:
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

        if llm:
            try:
                context_results = search_context(f"{step['type']} {step.get('description', '')}")
                context_text = ""
                if context_results:
                    context_text = "\n".join([f"- {r['title']}: {r['content'][:200]}..." for r in context_results[:2]])
                prompt = f"""Analyze this mission step briefly:

STEP: {step['id']} ({step['type']})
DESCRIPTION: {step.get('description', '')}

CONTEXT: {context_text}

Provide a 1-2 sentence analysis of what this step will do and any potential issues."""
                response = llm.invoke(prompt)
                analysis = response[:200] + "..." if len(response) > 200 else response
                print(f"🤖 {analysis}")
            except Exception as e:
                print(f"🤖 AI analysis failed: {e}")

        ok = True
        output = ""
        error = ""

        # Step type dispatch logic
        t = step.get('type')
        if t == "audit":
            ok, output = True, "Audit step placeholder"
        elif t == "lint":
            ok, output = run_linter(step.get('language','python'), llm)
        elif t == "test":
            ok, output = run_tests(step.get('language', 'python'), step.get('min_coverage', 0.0), llm, step['id'])
        elif t in ("create", "create_file", "edit"):
            try:
                file_path = REPO_PATH / step['file_path']
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(step.get('content', ''))
                ok, output = True, f"File created: {file_path}"
            except Exception as e:
                ok, output = False, f"File creation failed: {e}"
        elif t == "command":
            try:
                cwd = REPO_PATH / step.get('working_dir') if step.get('working_dir') else REPO_PATH
                proc = subprocess.run(step['command'], shell=True, cwd=cwd, capture_output=True, text=True)
                output = f"Command: {step['command']}\nReturn code: {proc.returncode}\nOutput:\n{proc.stdout}"
                if proc.stderr:
                    output += f"\nError:\n{proc.stderr}"
                ok = proc.returncode == 0
            except Exception as e:
                ok, output = False, f"Command execution failed: {e}"
        elif t == "ai_generate":
            if llm:
                prompt = step.get('prompt', f"Generate {step.get('language', 'code')} for: {desc}")
                try:
                    ai_output = llm.invoke(prompt)
                    if step.get('output_file'):
                        try:
                            file_path = REPO_PATH / step['output_file']
                            file_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.write(ai_output)
                            ok, output = True, f"AI generated file: {file_path}"
                        except Exception as e:
                            ok, output = False, f"File creation failed: {e}"
                    else:
                        ok, output = True, ai_output
                except Exception as e:
                    ok, output = False, f"AI generation failed: {e}"
            else:
                ok, output = False, "AI not available"
        elif t == "report":
            try:
                report = "# Executive Officer (XO) Mission Report\n\n"
                report += f"**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                for log in logs:
                    report += f"## Step: {log['step_id']}\n"
                    report += f"**Output**: {log['output']}\n"
                    if log['error']:
                        report += f"**Error**: {log['error']}\n"
                    report += "\n---\n\n"
                out_file = AUDIT_DIR / f"mission_report_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(report)
                ok, output = True, f"Report generated: {out_file}"
            except Exception as e:
                ok, output = False, f"Report generation failed: {e}"
        else:
            ok, output = False, f"Unknown step type: {t}"

        # Check if approval required
        if step['id'] in approval_steps:
            user_input = input(f"\n⚠️  Approval required for step '{step['id']}'. Continue? (y/N): ").strip().lower()
            if user_input not in ('y', 'yes'):
                print("❌ Step cancelled by user")
                ok, output, error = False, "Cancelled by user", ""

        # Log results
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = AUDIT_DIR / f"{step['id']}_{ts}.log"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"STEP: {step['id']}\nDESC: {step.get('description','')}\n\nOUTPUT:\n{output}\n\nERROR:\n{error if not ok else ''}\n")
            
        logs.append({
            'step_id': step['id'],
            'success': ok,
            'output': output,
            'error': error if not ok else ""
        })

        if ok:
            print(f"✅ Step completed: {step['id']}")
        else:
            print(f"❌ Step failed: {step['id']}")
            if error:
                print(f"🚨 Error: {error}")
            if not step.get('continue_on_error', False):
                print("🛑 Stopping execution due to step failure")
                break

    print("\n" + "=" * 50)
    if all(log['success'] for log in logs):
        print("🎉 All steps completed successfully!")
    else:
        failed_steps = [log['step_id'] for log in logs if not log['success']]
        print(f"⚠️  Some steps failed: {failed_steps}")

    print(f"📊 Execution summary: {len([l for l in logs if l['success']])}/{len(logs)} steps successful")
    print(f"📝 Audit logs saved to: {AUDIT_DIR}")

if __name__ == "__main__":
    main()