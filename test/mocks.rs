use std::sync::Arc;
use async_trait::async_trait;
use crate::core::tools::Tool;
use crate::core::llm::LLMBackend;

pub struct MockTool {
    name: String,
    expected_input: String,
    output: String,
}

impl MockTool {
    pub fn new(name: &str, expected_input: &str, output: &str) -> Self {
        Self {
            name: name.into(),
            expected_input: expected_input.into(),
            output: output.into(),
        }
    }
}

#[async_trait]
impl Tool for MockTool {
    async fn name(&self) -> String {
        self.name.clone()
    }

    async fn call(&self, input: &str) -> String {
        if input == self.expected_input {
            self.output.clone()
        } else {
            "unexpected input".to_string()
        }
    }
}

pub struct MockLLM;

#[async_trait]
impl LLMBackend for MockLLM {
    async fn generate(&self, prompt: &str) -> Result<String, String> {
        Ok(format!("[mocked] {}", prompt))
    }
}
---

file: core/tools.rs
---
#[cfg(test)]
mod test_mocks {
    pub use crate::test::mocks::*;
}
---
