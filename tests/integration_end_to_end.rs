use crate::test::mocks::{MockTool, MockLLM};
use crate::core::tools::register_plugin_tools;
use crate::engine::context::RuntimeContext;
use std::sync::Arc;

#[tokio::test]
async fn test_agent_tool_llm_memory_flow() {
    let mut ctx = RuntimeContext::new();

    // Register mock tool
    let echo_tool = Arc::new(MockTool::new("echo", "hello", "world"));
    {
        let mut registry = crate::core::tools::TOOL_REGISTRY.write().await;
        registry.insert("echo".into(), echo_tool.clone());
    }

    // Register mock LLM
    let llm = Arc::new(MockLLM);
    if let Some(manager) = &mut ctx.model_manager {
        manager.register_model("default".into(), llm).await;
    }

    // Simulate agent calling tool and generating response
    let result = echo_tool.call("hello").await;
    assert_eq!(result, "world");

    let model = ctx.get_model_for("default").await.unwrap();
    let reply = model.generate("echoed world").await.unwrap();
    assert!(reply.contains("mocked"));
}
---
