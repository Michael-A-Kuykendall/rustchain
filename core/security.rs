#[derive(Clone)]
pub struct SecurityConfig {
    pub allow_tools: Vec<String>,
    pub deny_sandbox: bool,
    pub deny_wasm: bool,
    pub max_tool_time_ms: u64,
}

impl SecurityConfig {
    pub fn default() -> Self {
        Self {
            allow_tools: vec!["echo".into(), "math".into()],
            deny_sandbox: false,
            deny_wasm: false,
            max_tool_time_ms: 2000,
        }
    }

    pub fn is_tool_allowed(&self, name: &str) -> bool {
        self.allow_tools.contains(&name.to_string())
    }
}
---

file: engine/context.rs
---
use crate::core::security::SecurityConfig;

pub struct RuntimeContext {
    pub security: SecurityConfig,
    // existing fields...
}

impl RuntimeContext {
    pub fn new() -> Self {
        Self {
            security: SecurityConfig::default(),
            // existing init...
        }
    }
}
---

file: lib.rs
---
pub mod security;
---
