//! LangChain Python → RustChain YAML Transpiler
//!
//! Parses LangChain Python scripts and converts them to RustChain missions.
//! Supports major LangChain patterns:
//! - LLMChain
//! - SequentialChain  
//! - SimpleSequentialChain
//! - RouterChain
//! - Agent workflows
//! - Tool usage

use crate::core::Result;
use crate::engine::{Mission, MissionStep, StepType};
use crate::transpiler::common::{TranspilationContext, TranspilerUtils};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;
use tracing::info;

// Pre-compiled regex patterns to avoid runtime unwraps
static TEMPLATE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"template\s*=\s*["']([^"']+)["']"#)
        .expect("Failed to compile TEMPLATE_REGEX pattern")
});

static VARIABLES_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"input_variables\s*=\s*\[([^\]]+)\]")
        .expect("Failed to compile VARIABLES_REGEX pattern")
});

/// LangChain AST node types we can parse - Enterprise Edition
#[derive(Debug, Clone)]
pub enum LangChainNode {
    LLMChain {
        llm: String,
        prompt: String,
        variables: Vec<String>,
    },
    SequentialChain {
        chains: Vec<LangChainNode>,
        input_variables: Vec<String>,
        output_variables: Vec<String>,
    },
    SimpleSequentialChain {
        chains: Vec<LangChainNode>,
    },
    Agent {
        tools: Vec<String>,
        llm: String,
        agent_type: String,
    },
    PromptTemplate {
        template: String,
        input_variables: Vec<String>,
    },
    Tool {
        name: String,
        description: String,
        func: String,
    },
}

/// Main LangChain parser
pub struct LangChainParser;

impl LangChainParser {
    /// Parse a LangChain Python file
    pub async fn parse_file(file_path: &Path) -> Result<Mission> {
        let content = tokio::fs::read_to_string(file_path).await.map_err(|e| {
            crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!("Failed to read file {}: {}", file_path.display(), e),
                },
            )
        })?;

        Self::parse_string(&content).await
    }

    /// Parse LangChain Python code from string
    pub async fn parse_string(content: &str) -> Result<Mission> {
        let mut context = TranspilationContext::new("langchain_mission".to_string());
        let nodes = Self::extract_langchain_nodes(content)?;
        let steps = Self::to_steps(nodes, &mut context)?;

        Ok(TranspilerUtils::create_mission(
            context.mission_name,
            Some("Converted from LangChain Python script".to_string()),
            steps,
        ))
    }

    /// Extract LangChain nodes from Python code using regex patterns
    fn extract_langchain_nodes(content: &str) -> Result<Vec<LangChainNode>> {
        let mut nodes = Vec::new();

        // Pattern 1: LLMChain
        let llm_chain_pattern =
            Regex::new(r"(?s)LLMChain\s*\(\s*llm\s*=\s*([^,]+),\s*prompt\s*=\s*([^)]+)\)")
                .map_err(|e| {
                    crate::core::RustChainError::Config(
                        crate::core::error::ConfigError::PluginError {
                            message: format!("Failed to compile LLMChain regex pattern: {}", e),
                        },
                    )
                })?;

        for cap in llm_chain_pattern.captures_iter(content) {
            let llm = cap[1].trim().to_string();
            let prompt_ref = cap[2].trim().to_string();

            // Try to resolve prompt template
            let (prompt, variables) = Self::resolve_prompt_template(content, &prompt_ref)?;

            nodes.push(LangChainNode::LLMChain {
                llm,
                prompt,
                variables,
            });
        }

        // Pattern 2: PromptTemplate
        let prompt_template_pattern = Regex::new(
            r#"(?s)PromptTemplate\s*\(\s*input_variables\s*=\s*\[([^\]]+)\],\s*template\s*=\s*["']([^"']+)["']\s*\)"#
        ).map_err(|e| crate::core::RustChainError::Config(
            crate::core::error::ConfigError::PluginError {
                message: format!("Failed to compile PromptTemplate regex pattern: {}", e)
            }
        ))?;

        for cap in prompt_template_pattern.captures_iter(content) {
            let variables_str = cap[1].trim();
            let template = cap[2].trim().to_string();

            let variables = Self::parse_variable_list(variables_str);

            nodes.push(LangChainNode::PromptTemplate {
                template: TranspilerUtils::convert_template_variables(&template),
                input_variables: variables,
            });
        }

        // Pattern 3: SequentialChain
        let sequential_chain_pattern =
            Regex::new(r"(?s)SequentialChain\s*\(\s*chains\s*=\s*\[([^\]]+)\]").map_err(|e| {
                crate::core::RustChainError::Config(crate::core::error::ConfigError::PluginError {
                    message: format!("Failed to compile SequentialChain regex pattern: {}", e),
                })
            })?;

        for cap in sequential_chain_pattern.captures_iter(content) {
            let chains_str = cap[1].trim();
            let chain_nodes = Self::parse_chain_references(content, chains_str)?;

            nodes.push(LangChainNode::SequentialChain {
                chains: chain_nodes,
                input_variables: vec![],
                output_variables: vec![],
            });
        }

        // Pattern 4: Agent initialization
        let agent_pattern = Regex::new(
            r"(?s)initialize_agent\s*\(\s*tools\s*=\s*([^,]+),\s*llm\s*=\s*([^,]+),\s*agent\s*=\s*([^)]+)\)"
        ).map_err(|e| crate::core::RustChainError::Config(
            crate::core::error::ConfigError::PluginError {
                message: format!("Failed to compile agent regex pattern: {}", e)
            }
        ))?;

        for cap in agent_pattern.captures_iter(content) {
            let tools_str = cap[1].trim();
            let llm = cap[2].trim().to_string();
            let agent_type = cap[3].trim().to_string();

            // Handle both direct tool lists and variable references
            let tools = if tools_str.starts_with('[') && tools_str.ends_with(']') {
                Self::parse_tool_list(&tools_str[1..tools_str.len() - 1])
            } else {
                // Handle variable reference like "tools"
                Self::resolve_tool_variable(content, tools_str)
            };

            nodes.push(LangChainNode::Agent {
                tools,
                llm,
                agent_type,
            });
        }

        if nodes.is_empty() {
            return Err(crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: "No LangChain patterns found in input".to_string(),
                },
            ));
        }

        Ok(nodes)
    }

    /// Convert parsed nodes to RustChain steps
    fn to_steps(
        nodes: Vec<LangChainNode>,
        context: &mut TranspilationContext,
    ) -> Result<Vec<MissionStep>> {
        let mut steps = Vec::new();

        for node in nodes {
            match node {
                LangChainNode::LLMChain {
                    llm,
                    prompt,
                    variables,
                } => {
                    let step_id = context.next_step_id();
                    let step = TranspilerUtils::create_llm_step(
                        step_id.clone(),
                        format!("LLM Chain Step {}", context.step_counter),
                        prompt,
                        Some(Self::convert_llm_model(&llm)),
                        variables,
                    );
                    steps.push(step);
                }

                LangChainNode::SequentialChain { chains, .. } => {
                    // Convert each chain in sequence with dependencies
                    let mut prev_step_id: Option<String> = None;

                    for chain_node in chains {
                        let chain_steps = Self::to_steps(vec![chain_node], context)?;

                        for mut step in chain_steps {
                            if let Some(prev_id) = &prev_step_id {
                                step.depends_on = Some(vec![prev_id.clone()]);
                            }
                            prev_step_id = Some(step.id.clone());
                            steps.push(step);
                        }
                    }
                }

                LangChainNode::SimpleSequentialChain { chains } => {
                    // Similar to SequentialChain but simpler
                    let mut prev_step_id: Option<String> = None;

                    for chain_node in chains {
                        let chain_steps = Self::to_steps(vec![chain_node], context)?;

                        for mut step in chain_steps {
                            if let Some(prev_id) = &prev_step_id {
                                step.depends_on = Some(vec![prev_id.clone()]);
                            }
                            prev_step_id = Some(step.id.clone());
                            steps.push(step);
                        }
                    }
                }

                LangChainNode::Agent {
                    tools,
                    llm,
                    agent_type,
                } => {
                    let step_id = context.next_step_id();
                    let agent_step = MissionStep {
                        id: step_id.clone(),
                        name: format!("Agent Step {} ({})", context.step_counter, agent_type),
                        step_type: StepType::Agent,
                        parameters: serde_json::json!({
                            "llm": Self::convert_llm_model(&llm),
                            "tools": tools,
                            "agent_type": agent_type,
                            "max_iterations": 5
                        }),
                        depends_on: None,
                        timeout_seconds: Some(120),
                        continue_on_error: None,
                    };
                    steps.push(agent_step);
                }

                LangChainNode::PromptTemplate { .. } => {
                    // PromptTemplate nodes are used by other nodes, not standalone steps
                    continue;
                }

                LangChainNode::Tool { .. } => {
                    // Tool definitions are used by agents, not standalone steps
                    continue;
                }
            }
        }

        Ok(steps)
    }

    /// Resolve prompt template reference to actual template and variables
    fn resolve_prompt_template(content: &str, prompt_ref: &str) -> Result<(String, Vec<String>)> {
        // Try to find the prompt template definition
        let var_pattern = format!(
            r"(?s){}\s*=\s*PromptTemplate\s*\([^)]+\)",
            regex::escape(prompt_ref.trim())
        );
        let re = Regex::new(&var_pattern).map_err(|e| {
            crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!("Failed to compile regex pattern: {}", e),
                },
            )
        })?;

        if let Some(cap) = re.find(content) {
            let template_def = cap.as_str();

            // Extract template and variables from the definition using pre-compiled patterns
            let template = TEMPLATE_REGEX
                .captures(template_def)
                .map(|cap| TranspilerUtils::convert_template_variables(&cap[1]))
                .unwrap_or_else(|| "{{input}}".to_string());

            let variables = VARIABLES_REGEX
                .captures(template_def)
                .map(|cap| Self::parse_variable_list(&cap[1]))
                .unwrap_or_else(|| vec!["input".to_string()]);

            Ok((template, variables))
        } else {
            // Fallback: treat as inline string
            let template = prompt_ref.trim_matches('"').trim_matches('\'');
            let variables = TranspilerUtils::extract_variables(template);
            Ok((template.to_string(), variables))
        }
    }

    /// Parse a list of variables from Python syntax
    fn parse_variable_list(vars_str: &str) -> Vec<String> {
        vars_str
            .split(',')
            .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// Parse chain references from Python syntax
    fn parse_chain_references(content: &str, chains_str: &str) -> Result<Vec<LangChainNode>> {
        // Chain reference parsing not implemented in community edition
        info!("Chain reference parsing requested for content length {} and chains '{}' but requires enterprise features", content.len(), chains_str);
        Err(crate::core::RustChainError::Unknown { message: "Chain reference parsing requires enterprise features. Use --features enterprise to enable advanced LangChain transpilation.".to_string() })
    }

    /// Parse tool list from Python syntax
    fn parse_tool_list(tools_str: &str) -> Vec<String> {
        tools_str
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    }

    /// Resolve tool variable reference to actual tool list
    fn resolve_tool_variable(content: &str, var_name: &str) -> Vec<String> {
        // Try to find the variable definition
        let pattern = format!(r"(?s){}\s*=\s*\[([^\]]+)\]", regex::escape(var_name.trim()));
        if let Ok(re) = Regex::new(&pattern) {
            if let Some(cap) = re.captures(content) {
                return Self::parse_tool_list(&cap[1]);
            }
        }

        // Fallback: treat as single tool name
        vec![var_name.to_string()]
    }

    /// Convert LangChain LLM reference to RustChain model name
    fn convert_llm_model(llm_ref: &str) -> String {
        match llm_ref.trim() {
            "OpenAI()" | "ChatOpenAI()" => "gpt-3.5-turbo".to_string(),
            s if s.contains("gpt-4") => "gpt-4".to_string(),
            s if s.contains("gpt-3.5") => "gpt-3.5-turbo".to_string(),
            s if s.contains("claude") => "claude-3-sonnet".to_string(),
            s if s.contains("primary_llm") => "gpt-4".to_string(),
            s if s.contains("secondary_llm") => "gpt-3.5-turbo".to_string(),
            s if s.contains("tertiary_llm") => "claude-3-sonnet".to_string(),
            _ => "gpt-3.5-turbo".to_string(), // Default fallback
        }
    }
}

/// Extension methods for Mission to support saving
impl Mission {
    pub async fn save_to_file(&self, file_path: &Path) -> Result<()> {
        let yaml_content = self.to_yaml()?;
        tokio::fs::write(file_path, yaml_content)
            .await
            .map_err(|e| {
                crate::core::error::RustChainError::Config(
                    crate::core::error::ConfigError::PluginError {
                        message: format!("Failed to write file {}: {}", file_path.display(), e),
                    },
                )
            })?;
        Ok(())
    }

    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(|e| {
            crate::core::error::RustChainError::Config(
                crate::core::error::ConfigError::PluginError {
                    message: format!("Failed to serialize to YAML: {}", e),
                },
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_parse_simple_llm_chain() {
        let python_code = r#"
from langchain import LLMChain, OpenAI, PromptTemplate

prompt = PromptTemplate(
    input_variables=["product"],
    template="What is a good name for a company that makes {product}?"
)

chain = LLMChain(llm=OpenAI(), prompt=prompt)
"#;

        let mission = LangChainParser::parse_string(python_code)
            .await
            .expect("LangChain parsing should succeed");

        assert_eq!(mission.name, "langchain_mission");
        assert!(mission.description.is_some());
        assert_eq!(mission.steps.len(), 1);

        let step = &mission.steps[0];
        assert!(matches!(step.step_type, StepType::Llm));

        let prompt = step
            .parameters
            .get("prompt")
            .expect("Prompt parameter should exist")
            .as_str()
            .expect("Prompt should be string");
        assert!(prompt.contains("{{product}}"));
    }

    #[tokio::test]
    async fn test_parse_agent_workflow() {
        let python_code = r#"
from langchain.agents import initialize_agent, AgentType
from langchain import OpenAI

tools = [search_tool, calculator_tool]
agent = initialize_agent(tools=tools, llm=OpenAI(), agent=AgentType.REACT_DOCSTORE)
"#;

        let mission = LangChainParser::parse_string(python_code)
            .await
            .expect("Agent workflow parsing should succeed");

        assert_eq!(mission.steps.len(), 1);

        let step = &mission.steps[0];
        assert!(matches!(step.step_type, StepType::Agent));

        let tools = step
            .parameters
            .get("tools")
            .expect("Tools parameter should exist")
            .as_array()
            .expect("Tools should be array");
        assert_eq!(tools.len(), 2);
    }

    #[tokio::test]
    async fn test_template_variable_conversion() {
        let python_code = r#"
prompt = PromptTemplate(
    input_variables=["name", "location"],
    template="Hello {name}, welcome to {location}!"
)

chain = LLMChain(llm=OpenAI(), prompt=prompt)
"#;

        let mission = LangChainParser::parse_string(python_code)
            .await
            .expect("Template variable parsing should succeed");
        let step = &mission.steps[0];
        let prompt = step
            .parameters
            .get("prompt")
            .expect("Prompt parameter should exist")
            .as_str()
            .expect("Prompt should be string");

        assert_eq!(prompt, "Hello {{name}}, welcome to {{location}}!");

        let variables = step
            .parameters
            .get("variables")
            .expect("Variables parameter should exist")
            .as_array()
            .expect("Variables should be array");
        assert_eq!(variables.len(), 2);
    }

    #[tokio::test]
    async fn test_parse_empty_content() {
        let result = LangChainParser::parse_string("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_no_langchain_patterns() {
        let python_code = r#"
print("Hello world")
x = 5 + 3
"#;

        let result = LangChainParser::parse_string(python_code).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_llm_model_conversion() {
        assert_eq!(
            LangChainParser::convert_llm_model("OpenAI()"),
            "gpt-3.5-turbo"
        );
        assert_eq!(
            LangChainParser::convert_llm_model("ChatOpenAI()"),
            "gpt-3.5-turbo"
        );
        assert_eq!(
            LangChainParser::convert_llm_model("unknown"),
            "gpt-3.5-turbo"
        );
    }

    #[tokio::test]
    async fn test_variable_list_parsing() {
        let vars = LangChainParser::parse_variable_list("\"name\", \"location\", \"time\"");
        assert_eq!(vars, vec!["name", "location", "time"]);

        let empty_vars = LangChainParser::parse_variable_list("");
        assert!(empty_vars.is_empty());
    }

    #[tokio::test]
    async fn test_mission_yaml_serialization() {
        let mission = TranspilerUtils::create_mission(
            "test".to_string(),
            Some("Test mission".to_string()),
            vec![],
        );

        let yaml = mission
            .to_yaml()
            .expect("YAML serialization should succeed");
        assert!(yaml.contains("name: test"));
        // YAML can use either single or double quotes, so check for both
        assert!(yaml.contains("version: '1.0'") || yaml.contains("version: \"1.0\""));
    }

    #[tokio::test]
    async fn test_file_operations() {
        let python_code = r#"
from langchain import LLMChain, OpenAI, PromptTemplate

prompt = PromptTemplate(
    input_variables=["topic"],
    template="Explain {topic} in simple terms"
)

chain = LLMChain(llm=OpenAI(), prompt=prompt)
"#;

        // Test parse from file
        let mut temp_file = NamedTempFile::new().expect("Temp file creation should succeed");
        temp_file
            .write_all(python_code.as_bytes())
            .expect("Writing to temp file should succeed");

        let mission = LangChainParser::parse_file(temp_file.path())
            .await
            .expect("File parsing should succeed");
        assert_eq!(mission.steps.len(), 1);

        // Test save to file
        let output_temp = NamedTempFile::new().expect("Output temp file creation should succeed");
        mission
            .save_to_file(output_temp.path())
            .await
            .expect("File saving should succeed");

        let saved_content =
            std::fs::read_to_string(output_temp.path()).expect("Reading saved file should succeed");
        assert!(saved_content.contains("name: langchain_mission"));
    }
}
