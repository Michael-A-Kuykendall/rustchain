use crate::tools::{Tool, ToolResult};
use crate::core::error::Result;
use async_trait::async_trait;

pub struct EchoTool;

impl EchoTool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }
    
    async fn invoke(&self, input: &str) -> Result<ToolResult> {
        Ok(ToolResult::Success(input.to_string()))
    }
}
