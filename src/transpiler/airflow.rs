//! Airflow DAG Parser
//!
//! Converts Apache Airflow DAG definitions to RustChain missions.
//! Supports common Airflow operators and converts them to equivalent RustChain step types.

use crate::core::Result;
use crate::engine::{Mission, MissionStep, StepType};
use crate::transpiler::common::{TranspilationContext, TranspilerUtils};
use regex::Regex;
use std::collections::HashMap;

/// Airflow DAG parser for converting Python DAG definitions to RustChain missions
pub struct AirflowParser;

/// Airflow operator types that can be converted to RustChain step types
#[derive(Debug, Clone)]
pub enum AirflowOperator {
    BashOperator {
        bash_command: String,
    },
    PythonOperator {
        python_callable: String,
        op_args: Vec<String>,
    },
    HttpSensor {
        endpoint: String,
        method: String,
    },
    EmailOperator {
        to: Vec<String>,
        subject: String,
        html_content: String,
    },
    SqlOperator {
        sql: String,
        database: String,
    },
    FileOperator {
        src: String,
        dest: String,
    },
    DummyOperator,
    Custom {
        operator_type: String,
        parameters: HashMap<String, String>,
    },
}

/// Airflow DAG representation
#[derive(Debug, Clone)]
pub struct AirflowDAG {
    pub dag_id: String,
    pub description: Option<String>,
    pub schedule_interval: Option<String>,
    pub start_date: Option<String>,
    pub catchup: bool,
    pub tasks: Vec<AirflowTask>,
}

/// Airflow task representation
#[derive(Debug, Clone)]
pub struct AirflowTask {
    pub task_id: String,
    pub operator: AirflowOperator,
    pub dependencies: Vec<String>,
    pub retries: Option<i32>,
    pub retry_delay: Option<String>,
}

impl AirflowParser {
    /// Parse Airflow DAG from Python string content
    pub async fn parse_string(content: &str) -> Result<Mission> {
        let dag = Self::extract_dag_definition(content)?;
        Self::to_mission(dag).await
    }

    /// Parse Airflow DAG from file
    pub async fn parse_file(file_path: &str) -> Result<Mission> {
        let content = tokio::fs::read_to_string(file_path)
            .await
            .map_err(|e| format!("Failed to read Airflow DAG file: {}", e))?;
        Self::parse_string(&content).await
    }

    /// Extract DAG definition from Python code using regex patterns
    fn extract_dag_definition(content: &str) -> Result<AirflowDAG> {
        let mut dag = AirflowDAG {
            dag_id: "airflow_dag".to_string(),
            description: None,
            schedule_interval: None,
            start_date: None,
            catchup: false,
            tasks: Vec::new(),
        };

        // Extract DAG ID from DAG instantiation
        if let Some(dag_id) = Self::extract_dag_id(content) {
            dag.dag_id = dag_id;
        }

        // Extract DAG description
        if let Some(description) = Self::extract_dag_description(content) {
            dag.description = Some(description);
        }

        // Extract schedule interval
        if let Some(schedule) = Self::extract_schedule_interval(content) {
            dag.schedule_interval = Some(schedule);
        }

        // Extract tasks
        dag.tasks = Self::extract_tasks(content)?;

        Ok(dag)
    }

    /// Extract DAG ID from DAG instantiation
    fn extract_dag_id(content: &str) -> Option<String> {
        let dag_id_re =
            Regex::new(r#"DAG\s*\(\s*['"]([^'"]+)['"]"#).expect("DAG ID regex pattern is valid");
        dag_id_re.captures(content).map(|caps| caps[1].to_string())
    }

    /// Extract DAG description from docstring or description parameter
    fn extract_dag_description(content: &str) -> Option<String> {
        // Try to find description parameter first
        let desc_re = Regex::new(r#"description\s*=\s*['"]([^'"]+)['"]"#)
            .expect("Description regex pattern is valid");
        if let Some(caps) = desc_re.captures(content) {
            return Some(caps[1].to_string());
        }

        // Fall back to docstring
        let docstring_re =
            Regex::new(r#"'''([^']+)'''|"""([^"]+)""""#).expect("Docstring regex pattern is valid");
        docstring_re.captures(content).map(|caps| {
            caps.get(1)
                .or(caps.get(2))
                .expect("Regex match guarantees group 1 or 2 exists")
                .as_str()
                .trim()
                .to_string()
        })
    }

    /// Extract schedule interval from DAG definition
    fn extract_schedule_interval(content: &str) -> Option<String> {
        let schedule_re = Regex::new(r#"schedule_interval\s*=\s*['"]([^'"]+)['"]"#)
            .expect("Schedule interval regex pattern is valid");
        schedule_re
            .captures(content)
            .map(|caps| caps[1].to_string())
    }

    /// Extract all tasks from the DAG definition
    fn extract_tasks(content: &str) -> Result<Vec<AirflowTask>> {
        let mut tasks = Vec::new();

        // Find all task definitions using various operator patterns
        let task_patterns = vec![
            (r"(\w+)\s*=\s*BashOperator\s*\(", "BashOperator"),
            (r"(\w+)\s*=\s*PythonOperator\s*\(", "PythonOperator"),
            (r"(\w+)\s*=\s*HttpSensor\s*\(", "HttpSensor"),
            (r"(\w+)\s*=\s*EmailOperator\s*\(", "EmailOperator"),
            (r"(\w+)\s*=\s*SqlOperator\s*\(", "SqlOperator"),
            (r"(\w+)\s*=\s*DummyOperator\s*\(", "DummyOperator"),
        ];

        for (pattern, operator_type) in task_patterns {
            let re = Regex::new(pattern).expect("Task pattern regex is valid (hardcoded pattern)");
            for caps in re.captures_iter(content) {
                let task_id = caps[1].to_string();

                // Extract task definition block
                if let Some(task_block) = Self::extract_task_block(content, &task_id, operator_type)
                {
                    if let Some(task) =
                        Self::parse_task_block(&task_id, operator_type, &task_block)?
                    {
                        tasks.push(task);
                    }
                }
            }
        }

        // Extract dependencies using >> and << operators
        Self::extract_dependencies(content, &mut tasks)?;

        Ok(tasks)
    }

    /// Extract the full task definition block from content
    fn extract_task_block(content: &str, task_id: &str, operator_type: &str) -> Option<String> {
        // Find the start of the task definition
        let start_pattern = format!(
            r"{}\s*=\s*{}\s*\(",
            regex::escape(task_id),
            regex::escape(operator_type)
        );
        let start_re = Regex::new(&start_pattern).expect("Task block regex pattern is valid");

        if let Some(start_match) = start_re.find(content) {
            let start_pos = start_match.end() - 1; // Position of opening parenthesis

            // Find matching closing parenthesis
            let chars: Vec<char> = content.chars().collect();
            let mut paren_count = 0;
            let mut in_string = false;
            let mut string_char = '"';
            let mut i = start_pos;

            while i < chars.len() {
                let ch = chars[i];

                // Handle string literals
                if (ch == '"' || ch == '\'') && (i == 0 || chars[i - 1] != '\\') {
                    if !in_string {
                        in_string = true;
                        string_char = ch;
                    } else if ch == string_char {
                        in_string = false;
                    }
                } else if !in_string {
                    if ch == '(' {
                        paren_count += 1;
                    } else if ch == ')' {
                        paren_count -= 1;
                        if paren_count == 0 {
                            // Found the matching closing parenthesis
                            let content_between =
                                chars[start_pos + 1..i].iter().collect::<String>();
                            return Some(content_between);
                        }
                    }
                }
                i += 1;
            }
        }

        None
    }

    /// Parse individual task block into AirflowTask
    fn parse_task_block(
        task_id: &str,
        operator_type: &str,
        block: &str,
    ) -> Result<Option<AirflowTask>> {
        let operator = match operator_type {
            "BashOperator" => {
                let bash_command = Self::extract_parameter(block, "bash_command")
                    .unwrap_or_else(|| "echo 'No command specified'".to_string());
                AirflowOperator::BashOperator { bash_command }
            }
            "PythonOperator" => {
                let python_callable = Self::extract_parameter(block, "python_callable")
                    .unwrap_or_else(|| "print".to_string());
                let op_args = Self::extract_list_parameter(block, "op_args").unwrap_or_default();
                AirflowOperator::PythonOperator {
                    python_callable,
                    op_args,
                }
            }
            "HttpSensor" => {
                let endpoint = Self::extract_parameter(block, "endpoint")
                    .unwrap_or_else(|| "/health".to_string());
                let method =
                    Self::extract_parameter(block, "method").unwrap_or_else(|| "GET".to_string());
                AirflowOperator::HttpSensor { endpoint, method }
            }
            "EmailOperator" => {
                let to = Self::extract_list_parameter(block, "to")
                    .unwrap_or_else(|| vec!["admin@example.com".to_string()]);
                let subject = Self::extract_parameter(block, "subject")
                    .unwrap_or_else(|| "Airflow Task".to_string());
                let html_content = Self::extract_parameter(block, "html_content")
                    .unwrap_or_else(|| "Task completed successfully".to_string());
                AirflowOperator::EmailOperator {
                    to,
                    subject,
                    html_content,
                }
            }
            "SqlOperator" => {
                let sql =
                    Self::extract_parameter(block, "sql").unwrap_or_else(|| "SELECT 1".to_string());
                let database = Self::extract_parameter(block, "database")
                    .unwrap_or_else(|| "default".to_string());
                AirflowOperator::SqlOperator { sql, database }
            }
            "DummyOperator" => AirflowOperator::DummyOperator,
            _ => {
                let mut parameters = HashMap::new();
                // Extract all parameters for custom operators
                let param_re = Regex::new(r#"(\w+)\s*=\s*['"]([^'"]+)['"]"#)
                    .expect("Parameter regex pattern is valid");
                for caps in param_re.captures_iter(block) {
                    parameters.insert(caps[1].to_string(), caps[2].to_string());
                }
                AirflowOperator::Custom {
                    operator_type: operator_type.to_string(),
                    parameters,
                }
            }
        };

        let retries = Self::extract_parameter(block, "retries").and_then(|s| s.parse().ok());

        let retry_delay = Self::extract_parameter(block, "retry_delay");

        // Extract actual task_id from block, fallback to variable name
        let actual_task_id =
            Self::extract_parameter(block, "task_id").unwrap_or_else(|| task_id.to_string());

        Ok(Some(AirflowTask {
            task_id: actual_task_id,
            operator,
            dependencies: Vec::new(), // Will be filled by extract_dependencies
            retries,
            retry_delay,
        }))
    }

    /// Extract parameter value from task block
    fn extract_parameter(block: &str, param_name: &str) -> Option<String> {
        // Try quoted strings first
        let pattern = format!(r#"{}\s*=\s*['"]([^'"]+)['"]"#, regex::escape(param_name));
        let re = Regex::new(&pattern).expect("Parameter extraction regex pattern is valid");
        if let Some(caps) = re.captures(block) {
            return Some(caps[1].to_string());
        }

        // Try unquoted values (numbers, variables, etc.)
        let pattern = format!(r#"{}\s*=\s*([^,)]+)"#, regex::escape(param_name));
        let re = Regex::new(&pattern).expect("Unquoted parameter regex pattern is valid");
        re.captures(block).map(|caps| caps[1].trim().to_string())
    }

    /// Extract list parameter from task block
    fn extract_list_parameter(block: &str, param_name: &str) -> Option<Vec<String>> {
        let pattern = format!(r#"{}\s*=\s*\[(.*?)\]"#, regex::escape(param_name));
        let re = Regex::new(&pattern).expect("List parameter regex pattern is valid");
        re.captures(block).map(|caps| {
            caps[1]
                .split(',')
                .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
    }

    /// Extract task dependencies from >> and << operators
    fn extract_dependencies(content: &str, tasks: &mut [AirflowTask]) -> Result<()> {
        // Find patterns like task1 >> task2 or [task1, task2] >> task3
        // Also handle chained patterns: start >> [middle1, middle2] >> end
        let _dep_re = Regex::new(r"(\w+|\[[\w\s,]+\])\s*>>\s*(\w+|\[[\w\s,]+\])")
            .expect("Dependency regex pattern is valid");

        // Create a mapping from variable names to task_ids
        let mut var_to_task_id = std::collections::HashMap::new();
        for task in tasks.iter() {
            // Find the variable name for this task by parsing the content
            // Look for pattern: variable_name = SomeOperator(...task_id='task_id'...)
            let task_pattern = format!(
                "(?s)(\\w+)\\s*=\\s*\\w+Operator\\s*\\([^)]*task_id\\s*=\\s*['\"]{}['\"].*?\\)",
                regex::escape(&task.task_id)
            );
            if let Ok(task_re) = Regex::new(&task_pattern) {
                if let Some(caps) = task_re.captures(content) {
                    var_to_task_id.insert(caps[1].to_string(), task.task_id.clone());
                }
            }
        }

        // Handle simple patterns and split chained patterns
        for line in content.lines() {
            let line = line.trim();
            if line.contains(">>") {
                // Split by >> to handle chains like: start >> [middle1, middle2] >> end
                let parts: Vec<&str> = line.split(">>").map(|s| s.trim()).collect();

                // Process each adjacent pair
                for i in 0..parts.len() - 1 {
                    let upstream = parts[i];
                    let downstream = parts[i + 1];

                    let upstream_vars = Self::parse_task_list(upstream);
                    let downstream_vars = Self::parse_task_list(downstream);

                    // Convert variable names to task_ids and set dependencies
                    for downstream_var in &downstream_vars {
                        if let Some(downstream_task_id) = var_to_task_id.get(downstream_var) {
                            if let Some(task) =
                                tasks.iter_mut().find(|t| &t.task_id == downstream_task_id)
                            {
                                for upstream_var in &upstream_vars {
                                    if let Some(upstream_task_id) = var_to_task_id.get(upstream_var)
                                    {
                                        task.dependencies.push(upstream_task_id.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse task list from string (handles both single tasks and [task1, task2] format)
    fn parse_task_list(task_str: &str) -> Vec<String> {
        if task_str.starts_with('[') && task_str.ends_with(']') {
            let inner = &task_str[1..task_str.len() - 1];
            inner
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            vec![task_str.to_string()]
        }
    }

    /// Convert AirflowDAG to RustChain Mission
    async fn to_mission(dag: AirflowDAG) -> Result<Mission> {
        let mut context = TranspilationContext::new(dag.dag_id.clone());
        let mut steps = Vec::new();

        for task in dag.tasks {
            let step = Self::to_step(task, &mut context)?;
            steps.push(step);
        }

        let mission = TranspilerUtils::create_mission(dag.dag_id, dag.description, steps);

        Ok(mission)
    }

    /// Convert AirflowTask to RustChain MissionStep
    fn to_step(task: AirflowTask, _context: &mut TranspilationContext) -> Result<MissionStep> {
        let (step_type, parameters) = match task.operator {
            AirflowOperator::BashOperator { bash_command } => (
                StepType::Command,
                serde_json::json!({
                    "command": "bash",
                    "args": ["-c", bash_command]
                }),
            ),
            AirflowOperator::PythonOperator {
                python_callable,
                op_args,
            } => (
                StepType::Command,
                serde_json::json!({
                    "command": "python",
                    "args": ["-c", format!("{}({})", python_callable, op_args.join(", "))]
                }),
            ),
            AirflowOperator::HttpSensor { endpoint, method } => (
                StepType::Http,
                serde_json::json!({
                    "url": endpoint,
                    "method": method,
                    "expect_status": 200
                }),
            ),
            AirflowOperator::EmailOperator {
                to,
                subject,
                html_content,
            } => (
                StepType::Tool,
                serde_json::json!({
                    "tool": "email_sender",
                    "parameters": {
                        "to": to,
                        "subject": subject,
                        "content": html_content
                    }
                }),
            ),
            AirflowOperator::SqlOperator { sql, database } => (
                StepType::SqlQuery,
                serde_json::json!({
                    "query": sql,
                    "database": database
                }),
            ),
            AirflowOperator::DummyOperator => (StepType::Noop, serde_json::json!({})),
            AirflowOperator::FileOperator { src, dest } => (
                StepType::Command,
                serde_json::json!({
                    "command": "cp",
                    "args": [src, dest]
                }),
            ),
            AirflowOperator::Custom {
                operator_type,
                parameters,
            } => (
                StepType::Tool,
                serde_json::json!({
                    "tool": operator_type.to_lowercase(),
                    "parameters": parameters
                }),
            ),
        };

        let depends_on = if task.dependencies.is_empty() {
            None
        } else {
            Some(task.dependencies)
        };

        // Calculate timeout based on retries
        let timeout_seconds = match task.retries {
            Some(retries) if retries > 0 => Some(300 * (retries + 1) as u64), // 5 minutes per retry
            _ => Some(300),                                                   // Default 5 minutes
        };

        Ok(MissionStep {
            id: task.task_id.clone(),
            name: format!("Airflow Task: {}", task.task_id),
            step_type,
            parameters,
            depends_on,
            timeout_seconds,
            continue_on_error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_simple_bash_dag() {
        let airflow_dag = r#"
from airflow import DAG
from airflow.operators.bash import BashOperator
from datetime import datetime

dag = DAG(
    'simple_bash_dag',
    description='A simple bash DAG',
    schedule_interval='@daily',
    start_date=datetime(2023, 1, 1),
    catchup=False,
)

task1 = BashOperator(
    task_id='print_hello',
    bash_command='echo "Hello World"',
    dag=dag,
)

task2 = BashOperator(
    task_id='print_date',
    bash_command='date',
    dag=dag,
)

task1 >> task2
        "#;

        let mission = AirflowParser::parse_string(airflow_dag).await.unwrap();

        assert_eq!(mission.name, "simple_bash_dag");
        assert_eq!(mission.description, Some("A simple bash DAG".to_string()));
        assert_eq!(mission.steps.len(), 2);

        let task1 = &mission.steps[0];
        assert_eq!(task1.id, "print_hello");
        assert!(matches!(task1.step_type, StepType::Command));
        assert_eq!(task1.depends_on, None);

        let task2 = &mission.steps[1];
        assert_eq!(task2.id, "print_date");
        assert_eq!(task2.depends_on, Some(vec!["print_hello".to_string()]));
    }

    #[tokio::test]
    async fn test_parse_python_operator() {
        let airflow_dag = r#"
from airflow import DAG
from airflow.operators.python import PythonOperator

dag = DAG('python_dag', description='Python DAG')

python_task = PythonOperator(
    task_id='run_python',
    python_callable='my_function',
    op_args=['arg1', 'arg2'],
    dag=dag,
)
        "#;

        let mission = AirflowParser::parse_string(airflow_dag).await.unwrap();

        assert_eq!(mission.steps.len(), 1);
        let task = &mission.steps[0];
        assert_eq!(task.id, "run_python");
        assert!(matches!(task.step_type, StepType::Command));

        let params = &task.parameters;
        assert_eq!(params["command"], "python");
        assert!(!params["args"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_parse_http_sensor() {
        let airflow_dag = r#"
from airflow import DAG
from airflow.sensors.http_sensor import HttpSensor

dag = DAG('http_dag')

http_sensor = HttpSensor(
    task_id='check_api',
    endpoint='/api/health',
    method='GET',
    dag=dag,
)
        "#;

        let mission = AirflowParser::parse_string(airflow_dag).await.unwrap();

        assert_eq!(mission.steps.len(), 1);
        let task = &mission.steps[0];
        assert_eq!(task.id, "check_api");
        assert!(matches!(task.step_type, StepType::Http));

        let params = &task.parameters;
        assert_eq!(params["url"], "/api/health");
        assert_eq!(params["method"], "GET");
    }

    #[tokio::test]
    async fn test_parse_dummy_operator() {
        let airflow_dag = r#"
from airflow import DAG
from airflow.operators.dummy import DummyOperator

dag = DAG('dummy_dag')

dummy = DummyOperator(
    task_id='do_nothing',
    dag=dag,
)
        "#;

        let mission = AirflowParser::parse_string(airflow_dag).await.unwrap();

        assert_eq!(mission.steps.len(), 1);
        let task = &mission.steps[0];
        assert_eq!(task.id, "do_nothing");
        assert!(matches!(task.step_type, StepType::Noop));
    }

    #[tokio::test]
    async fn test_parse_complex_dependencies() {
        let airflow_dag = r#"
from airflow import DAG
from airflow.operators.bash import BashOperator

dag = DAG('complex_dag')

start = BashOperator(task_id='start', bash_command='echo start', dag=dag)
middle1 = BashOperator(task_id='middle1', bash_command='echo middle1', dag=dag)
middle2 = BashOperator(task_id='middle2', bash_command='echo middle2', dag=dag)
end = BashOperator(task_id='end', bash_command='echo end', dag=dag)

start >> [middle1, middle2] >> end
        "#;

        let mission = AirflowParser::parse_string(airflow_dag).await.unwrap();

        assert_eq!(mission.steps.len(), 4);

        // Find end task and check dependencies
        let end_task = mission.steps.iter().find(|s| s.id == "end").unwrap();
        assert_eq!(end_task.depends_on.as_ref().unwrap().len(), 2);
        assert!(end_task
            .depends_on
            .as_ref()
            .unwrap()
            .contains(&"middle1".to_string()));
        assert!(end_task
            .depends_on
            .as_ref()
            .unwrap()
            .contains(&"middle2".to_string()));
    }

    #[tokio::test]
    async fn test_parse_empty_dag() {
        let airflow_dag = r#"
from airflow import DAG
dag = DAG('empty_dag')
        "#;

        let mission = AirflowParser::parse_string(airflow_dag).await.unwrap();

        assert_eq!(mission.name, "empty_dag");
        assert_eq!(mission.steps.len(), 0);
    }

    #[tokio::test]
    async fn test_parse_dag_with_retries() {
        let airflow_dag = r#"
from airflow import DAG
from airflow.operators.bash import BashOperator

dag = DAG('retry_dag')

retry_task = BashOperator(
    task_id='retry_task',
    bash_command='echo "This might fail"',
    retries=3,
    retry_delay=timedelta(minutes=5),
    dag=dag,
)
        "#;

        let mission = AirflowParser::parse_string(airflow_dag).await.unwrap();

        assert_eq!(mission.steps.len(), 1);
        let task = &mission.steps[0];

        // Timeout should be calculated based on retries (300 * (3 + 1) = 1200 seconds)
        assert_eq!(task.timeout_seconds, Some(1200));
    }

    #[test]
    fn test_extract_dag_id() {
        let content = r#"dag = DAG('test_dag', description='Test')"#;
        let dag_id = AirflowParser::extract_dag_id(content);
        assert_eq!(dag_id, Some("test_dag".to_string()));
    }

    #[test]
    fn test_extract_dag_description() {
        let content = r#"dag = DAG('test', description='Test description')"#;
        let description = AirflowParser::extract_dag_description(content);
        assert_eq!(description, Some("Test description".to_string()));
    }

    #[test]
    fn test_extract_parameter() {
        let block = r#"bash_command='echo hello', retries=3"#;
        let bash_command = AirflowParser::extract_parameter(block, "bash_command");
        assert_eq!(bash_command, Some("echo hello".to_string()));
    }

    #[test]
    fn test_parse_task_list() {
        let single_task = AirflowParser::parse_task_list("task1");
        assert_eq!(single_task, vec!["task1".to_string()]);

        let multiple_tasks = AirflowParser::parse_task_list("[task1, task2, task3]");
        assert_eq!(
            multiple_tasks,
            vec![
                "task1".to_string(),
                "task2".to_string(),
                "task3".to_string()
            ]
        );
    }
}
