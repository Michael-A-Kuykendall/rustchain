pub trait PromptOptimizer {
    fn optimize(&self, input: &str) -> String;
}

pub struct BasicOptimizer {
    pub max_len: usize,
}

impl BasicOptimizer {
    pub fn new(max_len: usize) -> Self {
        Self { max_len }
    }
}

impl PromptOptimizer for BasicOptimizer {
    fn optimize(&self, input: &str) -> String {
        let trimmed = input.trim().replace("


", "

");
        if trimmed.len() > self.max_len {
            trimmed[..self.max_len].to_string()
        } else {
            trimmed
        }
    }
}
---

file: lib.rs
---
pub mod prompt_optimizer;
---
