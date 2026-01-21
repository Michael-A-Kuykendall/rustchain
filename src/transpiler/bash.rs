//! Bash Script Parser for RustChain
//!
//! Converts Bash scripts to RustChain missions:
//! - Parse shell commands, conditionals, loops, functions
//! - Extract command sequences and control flow
//! - Convert to RustChain steps with proper dependencies
//! - Handle pipes, redirections, and environment variables

use crate::core::Result;
use crate::engine::{Mission, MissionConfig, MissionStep, StepType};
use crate::transpiler::common::TranspilationContext;
use serde_json::json;
use std::collections::HashMap;

/// Bash script parser for converting shell scripts to RustChain missions
pub struct BashParser;

/// Represents a parsed Bash command
#[derive(Debug, Clone)]
pub struct BashCommand {
    pub command: String,
    pub args: Vec<String>,
    pub environment: HashMap<String, String>,
    pub working_directory: Option<String>,
    pub input_redirect: Option<String>,
    pub output_redirect: Option<String>,
    pub pipes_to: Option<String>,
    pub conditional: Option<BashConditional>,
}

/// Represents Bash conditional logic
#[derive(Debug, Clone)]
pub struct BashConditional {
    pub condition_type: String, // if, while, for, case
    pub condition: String,
    pub then_commands: Vec<BashCommand>,
    pub else_commands: Vec<BashCommand>,
}

/// Represents a Bash function definition
#[derive(Debug, Clone)]
pub struct BashFunction {
    pub name: String,
    pub parameters: Vec<String>,
    pub commands: Vec<BashCommand>,
    pub description: Option<String>,
}

/// Represents a Bash variable assignment
#[derive(Debug, Clone)]
pub struct BashVariable {
    pub name: String,
    pub value: String,
    pub is_export: bool,
    pub is_readonly: bool,
}

impl BashParser {
    /// Parse a Bash script file and convert to RustChain mission
    pub async fn parse_file(file_path: &str) -> Result<Mission> {
        let content = tokio::fs::read_to_string(std::path::Path::new(file_path)).await?;
        Self::parse_string(&content).await
    }

    /// Parse Bash script content from string
    pub async fn parse_string(content: &str) -> Result<Mission> {
        let mut context = TranspilationContext::new("Bash Script Mission".to_string());

        // Parse Bash script elements
        let variables = Self::parse_variables(content)?;
        let functions = Self::parse_functions(content)?;
        let commands = Self::parse_commands(content)?;

        // Convert to RustChain steps
        let mut steps = Vec::new();
        let mut step_counter = 1;

        // Add variable initialization steps
        for variable in &variables {
            let step = Self::create_variable_step(variable, &format!("var_{}", step_counter))?;
            steps.push(step);
            step_counter += 1;
        }

        // Add function definition steps (as noop with metadata)
        for function in &functions {
            let step = Self::create_function_step(function, &format!("func_{}", step_counter))?;
            steps.push(step);
            step_counter += 1;
        }

        // Add command execution steps
        for command in &commands {
            let command_steps = Self::create_command_steps(command, &mut step_counter)?;
            steps.extend(command_steps);
        }

        context.add_variable("total_commands".to_string(), commands.len().to_string());
        context.add_variable("total_variables".to_string(), variables.len().to_string());
        context.add_variable("total_functions".to_string(), functions.len().to_string());

        Ok(Mission {
            version: "1.0".to_string(),
            name: "Bash Script Mission".to_string(),
            description: Some(format!(
                "Converted from Bash script with {} commands, {} variables, {} functions",
                commands.len(),
                variables.len(),
                functions.len()
            )),
            steps,
            config: Some(MissionConfig {
                max_parallel_steps: Some(1), // Bash scripts are typically sequential
                timeout_seconds: Some(3600), // 1 hour for script execution
                fail_fast: Some(true),       // Bash scripts should fail fast by default
            }),
        })
    }

    /// Parse variable assignments from Bash script
    fn parse_variables(content: &str) -> Result<Vec<BashVariable>> {
        let mut variables = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse export statements
            if let Some(stripped) = line.strip_prefix("export ") {
                if let Some(var) = Self::parse_variable_line(stripped, true)? {
                    variables.push(var);
                }
            }
            // Parse readonly statements
            else if let Some(stripped) = line.strip_prefix("readonly ") {
                if let Some(mut var) = Self::parse_variable_line(stripped, false)? {
                    var.is_readonly = true;
                    variables.push(var);
                }
            }
            // Parse regular variable assignments
            else if line.contains('=') && !line.starts_with("if ") && !line.starts_with("while ")
            {
                if let Some(var) = Self::parse_variable_line(line, false)? {
                    variables.push(var);
                }
            }
        }

        Ok(variables)
    }

    /// Parse a single variable assignment line
    fn parse_variable_line(line: &str, is_export: bool) -> Result<Option<BashVariable>> {
        if let Some(eq_pos) = line.find('=') {
            let name = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();

            // Skip if it looks like a command or function call
            if name.contains(' ') || name.contains('(') {
                return Ok(None);
            }

            Ok(Some(BashVariable {
                name,
                value,
                is_export,
                is_readonly: false,
            }))
        } else {
            Ok(None)
        }
    }

    /// Parse function definitions from Bash script
    fn parse_functions(content: &str) -> Result<Vec<BashFunction>> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();

            // Look for function definitions: function_name() { or function function_name {
            if (line.contains("()") && line.contains('{')) || line.starts_with("function ") {
                if let Some(function) = Self::parse_function_block(&lines, &mut i)? {
                    functions.push(function);
                }
            }
            i += 1;
        }

        Ok(functions)
    }

    /// Parse a single function block
    fn parse_function_block(lines: &[&str], start_idx: &mut usize) -> Result<Option<BashFunction>> {
        let line = lines[*start_idx].trim();

        // Extract function name
        let name = if line.starts_with("function ") {
            // function func_name {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                parts[1].trim_matches('{').to_string()
            } else {
                return Ok(None);
            }
        } else if line.contains("()") {
            // func_name() {
            line.split('(').next().unwrap_or("").trim().to_string()
        } else {
            return Ok(None);
        };

        // Skip function body for now (would need proper brace matching in production)
        let mut brace_count = 1;
        let mut commands = Vec::new();
        *start_idx += 1;

        while *start_idx < lines.len() && brace_count > 0 {
            let func_line = lines[*start_idx].trim();

            if func_line.contains('{') {
                brace_count += func_line.matches('{').count();
            }
            if func_line.contains('}') {
                brace_count -= func_line.matches('}').count();
            }

            // Parse commands within function (simplified)
            if brace_count > 0 && !func_line.is_empty() && !func_line.starts_with('#') {
                if let Some(command) = Self::parse_command_line(func_line)? {
                    commands.push(command);
                }
            }

            *start_idx += 1;
        }

        Ok(Some(BashFunction {
            name,
            parameters: Vec::new(), // Would parse from function signature in production
            commands,
            description: None,
        }))
    }

    /// Parse commands from Bash script
    fn parse_commands(content: &str) -> Result<Vec<BashCommand>> {
        let mut commands = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines, comments, variable assignments, and function definitions
            if line.is_empty()
                || line.starts_with('#')
                || line.contains('=')
                || line.contains("()")
                || line.starts_with("function ")
            {
                continue;
            }

            if let Some(command) = Self::parse_command_line(line)? {
                commands.push(command);
            }
        }

        Ok(commands)
    }

    /// Parse a single command line
    fn parse_command_line(line: &str) -> Result<Option<BashCommand>> {
        // Handle pipes
        if line.contains('|') {
            return Self::parse_piped_command(line);
        }

        // Handle redirections
        let (command_part, input_redirect, output_redirect) = Self::parse_redirections(line);

        // Split command and arguments
        let parts: Vec<&str> = command_part.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(None);
        }

        let command = parts[0].to_string();
        let args = parts[1..].iter().map(|s| s.to_string()).collect();

        // Parse conditional logic (simplified)
        let conditional = Self::parse_conditional_logic(line)?;

        Ok(Some(BashCommand {
            command,
            args,
            environment: HashMap::new(),
            working_directory: None,
            input_redirect,
            output_redirect,
            pipes_to: None,
            conditional,
        }))
    }

    /// Parse piped commands
    fn parse_piped_command(line: &str) -> Result<Option<BashCommand>> {
        let pipe_parts: Vec<&str> = line.split('|').collect();
        if pipe_parts.len() < 2 {
            return Ok(None);
        }

        let first_command = pipe_parts[0].trim();
        let remaining_pipe = pipe_parts[1..].join("|").trim().to_string();

        if let Some(mut command) = Self::parse_command_line(first_command)? {
            command.pipes_to = Some(remaining_pipe);
            Ok(Some(command))
        } else {
            Ok(None)
        }
    }

    /// Parse input/output redirections
    fn parse_redirections(line: &str) -> (String, Option<String>, Option<String>) {
        let mut command_part = line.to_string();
        let mut input_redirect = None;
        let mut output_redirect = None;

        // Parse output redirection (> or >>)
        if let Some(_pos) = line.find(" > ") {
            let parts: Vec<&str> = line.splitn(2, " > ").collect();
            command_part = parts[0].to_string();
            output_redirect = Some(parts[1].trim().to_string());
        } else if let Some(_pos) = line.find(" >> ") {
            let parts: Vec<&str> = line.splitn(2, " >> ").collect();
            command_part = parts[0].to_string();
            output_redirect = Some(format!("append:{}", parts[1].trim()));
        }

        // Parse input redirection (<)
        if let Some(_pos) = command_part.find(" < ") {
            let parts: Vec<&str> = command_part.splitn(2, " < ").collect();
            let temp_command = parts[0].to_string();
            input_redirect = Some(parts[1].trim().to_string());
            command_part = temp_command;
        }

        (command_part, input_redirect, output_redirect)
    }

    /// Parse conditional logic (simplified)
    fn parse_conditional_logic(line: &str) -> Result<Option<BashConditional>> {
        // Very basic conditional parsing - would need full parser for production
        if let Some(stripped) = line.strip_prefix("if ") {
            let condition = stripped.split(';').next().unwrap_or("").trim().to_string();
            Ok(Some(BashConditional {
                condition_type: "if".to_string(),
                condition,
                then_commands: Vec::new(),
                else_commands: Vec::new(),
            }))
        } else if let Some(stripped) = line.strip_prefix("while ") {
            let condition = stripped.split(';').next().unwrap_or("").trim().to_string();
            Ok(Some(BashConditional {
                condition_type: "while".to_string(),
                condition,
                then_commands: Vec::new(),
                else_commands: Vec::new(),
            }))
        } else if let Some(stripped) = line.strip_prefix("for ") {
            let condition = stripped.split(';').next().unwrap_or("").trim().to_string();
            Ok(Some(BashConditional {
                condition_type: "for".to_string(),
                condition,
                then_commands: Vec::new(),
                else_commands: Vec::new(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Convert variable to RustChain step
    fn create_variable_step(variable: &BashVariable, step_id: &str) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Set Variable: {}", variable.name),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: Some(10),
            continue_on_error: Some(false),
            parameters: json!({
                "variable_name": variable.name,
                "variable_value": variable.value,
                "is_export": variable.is_export,
                "is_readonly": variable.is_readonly,
                "bash_variable": true,
                "action": "set_variable"
            }),
        })
    }

    /// Convert function definition to RustChain step
    fn create_function_step(function: &BashFunction, step_id: &str) -> Result<MissionStep> {
        Ok(MissionStep {
            id: step_id.to_string(),
            name: format!("Define Function: {}", function.name),
            step_type: StepType::Noop,
            depends_on: None,
            timeout_seconds: Some(10),
            continue_on_error: Some(false),
            parameters: json!({
                "function_name": function.name,
                "parameter_count": function.parameters.len(),
                "command_count": function.commands.len(),
                "description": function.description,
                "bash_function": true,
                "action": "define_function"
            }),
        })
    }

    /// Convert command to RustChain steps
    fn create_command_steps(
        command: &BashCommand,
        step_counter: &mut usize,
    ) -> Result<Vec<MissionStep>> {
        let mut steps = Vec::new();

        // Main command step
        let main_step = MissionStep {
            id: format!("cmd_{}", step_counter),
            name: format!("Execute: {}", Self::format_command_name(command)),
            step_type: Self::step_type_for(&command.command),
            depends_on: None,
            timeout_seconds: Some(Self::get_command_timeout(&command.command)),
            continue_on_error: Some(Self::should_continue_on_error(&command.command)),
            parameters: json!({
                "command": command.command,
                "args": command.args,
                "working_directory": command.working_directory,
                "environment": command.environment,
                "input_redirect": command.input_redirect,
                "output_redirect": command.output_redirect,
                "pipes_to": command.pipes_to,
                "bash_command": true,
                "full_command": Self::reconstruct_full_command(command)
            }),
        };
        steps.push(main_step);
        *step_counter += 1;

        // Handle conditional logic
        if let Some(conditional) = &command.conditional {
            let conditional_step = MissionStep {
                id: format!("cond_{}", step_counter),
                name: format!(
                    "Conditional: {} {}",
                    conditional.condition_type, conditional.condition
                ),
                step_type: StepType::Noop,
                depends_on: Some(vec![format!("cmd_{}", *step_counter - 1)]),
                timeout_seconds: Some(60),
                continue_on_error: Some(true),
                parameters: json!({
                    "condition_type": conditional.condition_type,
                    "condition": conditional.condition,
                    "bash_conditional": true,
                    "action": "evaluate_condition"
                }),
            };
            steps.push(conditional_step);
            *step_counter += 1;
        }

        // Handle piped command
        if let Some(pipe_cmd) = &command.pipes_to {
            let pipe_step = MissionStep {
                id: format!("pipe_{}", step_counter),
                name: format!("Pipe to: {}", pipe_cmd),
                step_type: StepType::Command,
                depends_on: Some(vec![format!("cmd_{}", *step_counter - 2)]),
                timeout_seconds: Some(300),
                continue_on_error: Some(false),
                parameters: json!({
                    "command": pipe_cmd,
                    "bash_pipe": true,
                    "action": "pipe_command"
                }),
            };
            steps.push(pipe_step);
            *step_counter += 1;
        }

        Ok(steps)
    }

    /// Format command name for display
    fn format_command_name(command: &BashCommand) -> String {
        if command.args.is_empty() {
            command.command.clone()
        } else {
            format!("{} {}", command.command, command.args.join(" "))
        }
    }

    /// Map bash commands to RustChain step types
    fn step_type_for(command: &str) -> StepType {
        match command {
            // File operations
            "touch" | "mkdir" | "cp" | "mv" => StepType::CreateFile,
            "rm" | "rmdir" => StepType::DeleteFile,
            "echo" | "cat" | "tee" => StepType::CreateFile,

            // Network operations
            "curl" | "wget" | "ping" | "nc" | "telnet" => StepType::Http,

            // System commands
            "ps" | "top" | "kill" | "jobs" | "nohup" => StepType::Command,
            "cd" | "pwd" | "ls" | "find" | "grep" | "sed" | "awk" => StepType::Command,
            "chmod" | "chown" | "su" | "sudo" => StepType::Command,

            // Build/development commands
            "make" | "cmake" | "gcc" | "g++" | "cargo" | "npm" | "yarn" => StepType::Command,
            "git" | "svn" | "hg" => StepType::Command,

            // Package management
            "apt" | "yum" | "brew" | "pip" | "gem" => StepType::Command,

            // Docker/containers
            "docker" | "kubectl" | "helm" => StepType::Command,

            // Default to command for unknown
            _ => StepType::Command,
        }
    }

    /// Get appropriate timeout for command
    fn get_command_timeout(command: &str) -> u64 {
        match command {
            // Quick commands
            "echo" | "pwd" | "ls" | "cd" | "touch" | "mkdir" => 30,

            // Medium commands
            "cp" | "mv" | "rm" | "chmod" | "chown" => 120,
            "grep" | "sed" | "awk" | "find" => 300,

            // Long-running commands
            "make" | "cmake" | "gcc" | "g++" | "cargo" | "npm" => 1800,
            "curl" | "wget" | "ping" => 300,
            "docker" | "kubectl" => 600,
            "apt" | "yum" | "brew" | "pip" => 1200,

            // Default timeout
            _ => 300,
        }
    }

    /// Determine if command should continue on error
    fn should_continue_on_error(command: &str) -> bool {
        match command {
            // Critical commands that should stop on error
            "rm" | "rmdir" | "kill" | "shutdown" | "reboot" => false,
            "chmod" | "chown" | "su" | "sudo" => false,

            // Commands that can often continue on error
            "echo" | "cat" | "ls" | "pwd" => true,
            "mkdir" | "touch" => true, // Might already exist
            "cp" | "mv" => false,      // File operations should be successful

            // Network commands can be retried
            "ping" | "curl" | "wget" => true,

            // Default to fail-fast
            _ => false,
        }
    }

    /// Reconstruct full command string for execution
    fn reconstruct_full_command(command: &BashCommand) -> String {
        let mut cmd = format!("{} {}", command.command, command.args.join(" "));

        if let Some(input) = &command.input_redirect {
            cmd = format!("{} < {}", cmd, input);
        }

        if let Some(output) = &command.output_redirect {
            if let Some(stripped) = output.strip_prefix("append:") {
                cmd = format!("{} >> {}", cmd, stripped);
            } else {
                cmd = format!("{} > {}", cmd, output);
            }
        }

        if let Some(pipe) = &command.pipes_to {
            cmd = format!("{} | {}", cmd, pipe);
        }

        cmd.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_simple_bash_script() {
        let bash_script = r#"#!/bin/bash
# Simple backup script
BACKUP_DIR="/backup"
SOURCE_DIR="/home/user"

echo "Starting backup..."
mkdir -p $BACKUP_DIR
cp -r $SOURCE_DIR $BACKUP_DIR
echo "Backup complete!"
        "#;

        let result = BashParser::parse_string(bash_script).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert_eq!(mission.name, "Bash Script Mission");
        assert!(mission.steps.len() >= 4); // Variables + commands

        // Check that we have variable and command steps
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names.iter().any(|name| name.contains("Variable")));
        assert!(step_names.iter().any(|name| name.contains("Execute")));
    }

    #[test]
    fn test_parse_variables() {
        let script = r#"
export PATH="/usr/bin:$PATH"
readonly CONFIG_FILE="/etc/app.conf"
DEBUG=1
TEMP_DIR="/tmp/app"
        "#;

        let variables = BashParser::parse_variables(script).unwrap();
        assert_eq!(variables.len(), 4);

        // Check export variable
        assert!(variables.iter().any(|v| v.name == "PATH" && v.is_export));
        // Check readonly variable
        assert!(variables
            .iter()
            .any(|v| v.name == "CONFIG_FILE" && v.is_readonly));
        // Check regular variables
        assert!(variables
            .iter()
            .any(|v| v.name == "DEBUG" && v.value == "1"));
    }

    #[test]
    fn test_parse_commands() {
        let script = r#"
echo "Hello World"
ls -la /home
grep "error" /var/log/app.log > errors.txt
curl -X POST http://api.example.com/data
        "#;

        let commands = BashParser::parse_commands(script).unwrap();
        assert_eq!(commands.len(), 4);

        // Check command parsing
        assert_eq!(commands[0].command, "echo");
        assert_eq!(commands[0].args, vec!["\"Hello", "World\""]);

        assert_eq!(commands[1].command, "ls");
        assert_eq!(commands[1].args, vec!["-la", "/home"]);

        // Check redirection parsing
        assert_eq!(commands[2].command, "grep");
        assert!(commands[2].output_redirect.is_some());
    }

    #[test]
    fn test_parse_piped_commands() {
        let line = "ps aux | grep nginx | wc -l";
        let command = BashParser::parse_command_line(line).unwrap().unwrap();

        assert_eq!(command.command, "ps");
        assert_eq!(command.args, vec!["aux"]);
        assert!(command.pipes_to.is_some());
        assert_eq!(command.pipes_to.unwrap(), "grep nginx | wc -l");
    }

    #[test]
    fn test_parse_redirections() {
        let (cmd, input, output) = BashParser::parse_redirections("cat < input.txt > output.txt");
        assert_eq!(cmd, "cat");
        assert_eq!(input, Some("input.txt".to_string()));
        assert_eq!(output, Some("output.txt".to_string()));

        let (cmd2, _, output2) = BashParser::parse_redirections("echo 'test' >> log.txt");
        assert_eq!(cmd2, "echo 'test'");
        assert_eq!(output2, Some("append:log.txt".to_string()));
    }

    #[test]
    fn test_command_step_type_mapping() {
        assert!(matches!(
            BashParser::step_type_for("touch"),
            StepType::CreateFile
        ));
        assert!(matches!(
            BashParser::step_type_for("mkdir"),
            StepType::CreateFile
        ));
        assert!(matches!(
            BashParser::step_type_for("rm"),
            StepType::DeleteFile
        ));
        assert!(matches!(BashParser::step_type_for("curl"), StepType::Http));
        assert!(matches!(BashParser::step_type_for("ls"), StepType::Command));
    }

    #[test]
    fn test_command_timeout_mapping() {
        assert_eq!(BashParser::get_command_timeout("echo"), 30);
        assert_eq!(BashParser::get_command_timeout("cp"), 120);
        assert_eq!(BashParser::get_command_timeout("make"), 1800);
        assert_eq!(BashParser::get_command_timeout("curl"), 300);
    }

    #[test]
    fn test_continue_on_error_mapping() {
        assert!(!BashParser::should_continue_on_error("rm"));
        assert!(!BashParser::should_continue_on_error("kill"));
        assert!(BashParser::should_continue_on_error("echo"));
        assert!(BashParser::should_continue_on_error("mkdir"));
        assert!(BashParser::should_continue_on_error("ping"));
    }

    #[tokio::test]
    async fn test_conditional_parsing() {
        let bash_script = r#"
if [ -f "/etc/config" ]; then
    echo "Config exists"
fi

while read line; do
    echo $line
done < input.txt

for file in *.txt; do
    echo $file
done
        "#;

        let result = BashParser::parse_string(bash_script).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names.iter().any(|name| name.contains("Conditional")));
    }

    #[tokio::test]
    async fn test_function_parsing() {
        let bash_script = r#"
function backup_files() {
    cp -r /home/user /backup
    echo "Backup complete"
}

deploy() {
    git pull origin main
    npm install
    npm run build
}
        "#;

        let result = BashParser::parse_string(bash_script).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        let step_names: Vec<String> = mission.steps.iter().map(|s| s.name.clone()).collect();
        assert!(step_names
            .iter()
            .any(|name| name.contains("Define Function")));
    }

    #[tokio::test]
    async fn test_full_command_reconstruction() {
        let bash_script = r#"
grep "error" /var/log/app.log > errors.txt
ps aux | grep nginx | head -10
echo "test" >> output.log
        "#;

        let result = BashParser::parse_string(bash_script).await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert!(mission.steps.len() >= 3);

        // Check that full commands are properly reconstructed
        for step in &mission.steps {
            if step.name.contains("Execute") {
                assert!(step.parameters.get("full_command").is_some());
            }
        }
    }

    #[tokio::test]
    async fn test_empty_script() {
        let result = BashParser::parse_string("").await;
        assert!(result.is_ok());

        let mission = result.unwrap();
        assert_eq!(mission.steps.len(), 0);
        assert!(mission.description.unwrap().contains("0 commands"));
    }
}
