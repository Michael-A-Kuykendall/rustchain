use std::sync::Arc;
use crate::test::mocks::{MockTool, MockLLM};
use crate::core::tools::{Tool, get_tool};

#[tokio::test]
async fn test_mock_tool_response() {
    let tool = Arc::new(MockTool::new("greet", "hi", "hello"));
    let output = tool.call("hi").await;
    assert_eq!(output, "hello");
}

#[tokio::test]
async fn test_mock_llm_generate() {
    let llm = MockLLM;
    let result = llm.generate("ping").await.unwrap();
    assert!(result.contains("[mocked] ping"));
}
---

file: tests/missions/sample_chain.yaml
---
# Sample test mission file (integration placeholder)
mission:
  name: demo
  tasks:
    - tool: "echo"
      input: "Hello"
---
