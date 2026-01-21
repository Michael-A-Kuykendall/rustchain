//! # RustChain - Enterprise Workflow Automation Framework
//!
//! RustChain is a high-performance, type-safe workflow automation framework written in Rust.
//! It provides mission-based orchestration with built-in safety and AI capabilities.
//!
//! ## Features
//!
//! - **Mission Engine**: DAG-based workflow execution with dependency resolution
//! - **AI Integration**: LLM support, agent systems, and RAG (Retrieval-Augmented Generation)
//! - **Safety**: Policy engine with formal verification and security controls
//! - **Transpilation**: Convert workflows from GitHub Actions, Airflow, Jenkins, Terraform, and more
//! - **Tools**: Extensible tool system with built-in tools
//! - **Memory**: Vector stores and context management for AI workflows
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rustchain::engine::{Mission, MissionStep, StepType, DagExecutor};
//! use rustchain::core::RuntimeContext;
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create runtime context
//!     let ctx = RuntimeContext::new();
//!     
//!     // Define a simple mission
//!     let mission = Mission {
//!         version: "1.0".to_string(),
//!         name: "Hello World".to_string(),
//!         description: Some("My first mission".to_string()),
//!         steps: vec![
//!             MissionStep {
//!                 id: "greet".to_string(),
//!                 name: "Greet User".to_string(),
//!                 step_type: StepType::Command,
//!                 parameters: json!({
//!                     "command": "echo",
//!                     "args": ["Hello, RustChain!"]
//!                 }),
//!                 depends_on: None,
//!                 timeout_seconds: Some(30),
//!                 continue_on_error: None,
//!             }
//!         ],
//!         config: None,
//!     };
//!     
//!     // Execute the mission
//!     let result = DagExecutor::execute_mission(mission, &ctx).await?;
//!     println!("Mission completed: {:?}", result.status);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! RustChain follows a modular architecture designed for safety, extensibility, and performance:
//!
//! - **Core**: Runtime context, configuration, audit logging, and error handling
//! - **Engine**: Mission execution with DAG-based dependency resolution and async step processing
//! - **Policy**: Safety validation and compliance enforcement with rule-based policies
//! - **Tools**: Extensible tool system with type-safe parameters and capability detection
//! - **AI**: LLM integration, autonomous agents, and memory systems for intelligent workflows
//! - **Transpiler**: Universal workflow import/export supporting multiple formats
//! - **Safety**: Runtime security controls and audit trail verification
//!
//! ## Feature Flags
//!
//! RustChain uses cargo features to enable optional functionality.
//! Core modules (core, engine, policy, runtime, safety, telemetry, validation, performance, build_dashboard, benchmarks) are always available.
//!
//! - `llm` - LLM integration (OpenAI, Anthropic, etc.)
//! - `agent` - Autonomous agent systems
//! - `tools` - Built-in tool library
//! - `rag` - Retrieval-Augmented Generation
//! - `transpiler` - Workflow import/export
//! - `enterprise` - Enterprise features and security
//! - `memory` - Vector stores and context management
//! - `chain` - Chain-based workflows
//! - `smt` - Satisfiability modulo theories
//! - `registry` - Tool and model registry
//! - `server` - HTTP server functionality
//! - `cli` - Command-line interface
//! - `concurrency` - Advanced concurrency features
//! - `invariants` - Runtime invariant checking
//! - `sandbox` - Sandboxed execution
//!
//! ## Safety and Compliance
//!
//! RustChain provides built-in safety guarantees:
//!
//! - Path traversal prevention
//! - Command injection protection  
//! - Resource usage limits
//! - Audit logging with cryptographic chain verification
//! - Policy engine with safety validation and compliance enforcement
//!
//! ## Performance
//!
//! - Async/await throughout for maximum concurrency
//! - Memory safety with Rust's ownership system
//!
//! For more information, see the [documentation](https://docs.rs/rustchain) and
//! [examples](https://github.com/rustchain/rustchain/tree/main/examples).

#[cfg(feature = "llm")]
pub mod llm;

#[cfg(feature = "tools")]
pub mod tools;

#[cfg(feature = "rag")]
pub mod rag;

#[cfg(feature = "sandbox")]
pub mod sandbox;

#[cfg(any(feature = "registry", feature = "enterprise"))]
pub mod registry;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "cli")]
pub mod cli;

pub mod invariant_ppt;

// Universal Transpiler System
#[cfg(feature = "transpiler")]
pub mod transpiler;

// Enterprise features (gated by enterprise feature)
#[cfg(feature = "enterprise")]
pub mod security;

// Core modules always available
pub mod benchmarks;
pub mod build_dashboard;
pub mod core;
pub mod engine;
pub mod performance;
pub mod policy;
pub mod runtime;
pub mod safety;
pub mod telemetry;
pub mod validation;
// Note: Some enterprise modules may be conditionally available
// - security (available with enterprise feature)
// - visual (moved to rustchain-enterprise)
// - registry (available with registry/enterprise features)
