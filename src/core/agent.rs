use crate::core::{LLMBackend, Result, RustChainError};
use crate::tools::{Tool, ToolResult};
use std::collections::HashMap;
use std::sync::Arc;

pub struct Agent {
    llm: Arc<dyn LLMBackend>,
    tools: HashMap<String, Arc<dyn Tool>>,
    memory: HashMap<String, String>,
}

impl Agent {
    pub fn new(llm: Arc<dyn LLMBackend>) -> Self {
        Self {
            llm,
            tools: HashMap::new(),
            memory: HashMap::new(),
        }
    }
    
    pub fn add_tool(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }
    
    pub async fn run(&mut self, input: &str) -> Result<String> {
        self.memory.insert("user_input".to_string(), input.to_string());
        
        let tool_list: Vec<String> = self.tools.keys().cloned().collect();
        let tools_str = tool_list.join(", ");
        
        let prompt = format!(
            "Available tools: {}. User: {}. If you need a tool, respond: TOOL:name:input",
            tools_str, input
        );
        
        let llm_response = self.llm.generate(&prompt).await?;
        
        if llm_response.starts_with("TOOL:") {
            let parts: Vec<&str> = llm_response.splitn(3, ':').collect();
            if parts.len() == 3 {
                let tool_name = parts[1];
                let tool_input = parts[2];
                
                if let Some(tool) = self.tools.get(tool_name) {
                    match tool.invoke(tool_input).await? {
                        ToolResult::Success(result) => {
                            let final_prompt = format!("Tool result: {}. Respond to user.", result);
                            return self.llm.generate(&final_prompt).await;
                        }
                        ToolResult::Error(err) => {
                            return Err(RustChainError::Tool(err));
                        }
                    }
                }
            }
        }
        
        Ok(llm_response)
    }
}
