use crate::tools::{Tool, ToolResult};
use crate::core::error::Result;
use async_trait::async_trait;

pub struct MathTool;

impl MathTool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tool for MathTool {
    fn name(&self) -> &'static str {
        "math"
    }
    
    async fn invoke(&self, input: &str) -> Result<ToolResult> {
        match evalexpr::eval(input) {
            Ok(result) => Ok(ToolResult::Success(result.to_string())),
            Err(e) => Ok(ToolResult::Error(format!("Math error: {}", e))),
        }
    }
}
