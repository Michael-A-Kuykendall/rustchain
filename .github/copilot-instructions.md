When the user says “deep engineering”, interpret it as running the “Deep Engineering Integrity Review” defined in .github/prompts/deep-engineering.prompt.md.

# RustChain Community — AI Agent Notes
## ⚠️ INTERNAL DOCUMENTATION RULE
**All internal documentation, audit files, scratch notes, and errata MUST be placed in `.internal/`** (not repo root).

This includes:
- Audit checklists and reports → `.internal/audit/`
- Working notes and scratch files → `.internal/notes/`
- Test output files → `.internal/scratch/` or delete after use
- Any markdown created during development sessions

**Why?** Files in repo root get committed and tangled into git history. The `.internal/` directory is gitignored, keeping the repo clean. When the user creates a file that looks like internal notes, suggest moving it to `.internal/` instead.

---
## Big Picture
- This crate ships a `rustchain` library (`src/lib.rs`) plus a feature-gated CLI binary (`src/main.rs` → `rustchain::cli::run()`).
- The core “spine” is Mission execution: YAML → `engine::Mission` → DAG execution (`src/engine/mod.rs`) with safety validation (`src/safety/`) and audit logging (`src/core/`).
- Prefer using the high-level facade `RustChainRuntime` (`src/runtime/mod.rs`) unless you need lower-level engine control.

## Entrypoints & Where Things Live
- CLI command definitions: `src/cli/commands.rs` (clap subcommands, docs in `docs/cli-reference.md`).
- CLI dispatch/behavior: `src/cli/handlers/mod.rs` (calls `MissionLoader`, `SafetyValidator`, `RustChainRuntime`).
- Mission model + step types + execution semantics: `src/engine/mod.rs` (DAG + `depends_on`, per-step timeouts, `{variable}` substitution).
- Optional modules are feature-gated in `src/lib.rs` (e.g., `llm`, `rag`, `server`, `registry`).

## Cargo Features (Important)
- Default features are `cli`, `transpiler`, `tools` (see `Cargo.toml`). If you’re missing symbols, confirm the feature gate.
- Common local dev builds:
	- `cargo run --features cli -- run examples/hello_world.yaml`
	- `cargo test --all-features`

## Local AI / LLM Integration
- Ollama connectivity checks target `localhost:11434` (`src/llm/test_connectivity.rs`).
- Shimmy integration exists in both tools + server:
	- Tools include “Shimmy file ops” registered in `src/tools/mod.rs`.
	- Server exposes an OpenAI-compatible endpoint (`/v1/chat/completions`) for Shimmy (`src/server/agent_api.rs`, behind the `server` feature).
- VS Code tasks in this workspace can start local services:
	- “LLM: Start Ollama (serve)” (`ollama serve`)
	- “LLM: Start Shimmy (11435)” (`shimmy serve --host 127.0.0.1 --port 11435`)

## Conventions You Should Follow Here
- Logging is via `tracing`; CLI sets `RUST_LOG=info` by default (`src/cli/mod.rs`). Prefer `tracing::{info,warn,error}` over `println!` in library code.
- Errors use `anyhow`/`thiserror`; CLI prints user-friendly errors via `core::error_formatting` (`src/cli/handlers/mod.rs`).
- Many execution paths are async (`tokio`); avoid blocking calls in async contexts unless isolated.

## Website Directory (Nested Git Repo)
The `website/` directory is a **separate git repository** (git-ignored by this parent repo):
- Remote: `https://github.com/Michael-A-Kuykendall/rust-chain-forge.git`
- Deploys: `main` branch → rustchain.dev (via Cloudflare Workers)
- Stack: Vite + React + TypeScript + Tailwind
- **This is git-ignored** in `.gitignore` as `/website/` - changes here don't affect rustchain-community commits
- To sync with live: `cd website && git fetch origin && git reset --hard origin/main`

## Terminal Commands - CRITICAL RULE
**NEVER pipe long-running commands through `tail`, `head`, or similar filters.** This causes silent failures where the agent locks up forever with no visibility.

For any command that might take more than a few seconds (tests, builds, etc.):
- Use trailing `&` to background in shell: `cargo test --all-features &`
- Use `isBackground: true` so the tool returns immediately
- **IMMEDIATELY continue working** - don't wait, don't ask "what next", just keep going
- Check results later with `get_terminal_output` when relevant

Bad: `cargo test 2>&1 | tail -30` (silent failure trap)
Bad: `cargo test` with `isBackground: true` then waiting silently
Good: `cargo test &` with `isBackground: true`, then immediately continue other work
