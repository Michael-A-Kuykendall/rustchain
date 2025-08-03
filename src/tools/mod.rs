pub mod echo;
pub mod math;
pub mod registry;

pub use echo::*;
pub use math::*;
pub use registry::*;

use crate::core::error::Result;
use async_trait::async_trait;

#[derive(Debug)]
pub enum ToolResult {
    Success(String),
    Error(String),
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;
    async fn invoke(&self, input: &str) -> Result<ToolResult>;
}
