use crate::core::error::RustChainError;
use crate::engine::{DagExecutor, ExecutionContext, MissionStep, StepType};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, error, info};

/// Enhanced chain executor that supports nested sub-steps
#[derive(Debug, Clone)]
pub struct ChainExecutor {
    chain_id: String,
}

impl ChainExecutor {
    pub fn new(chain_id: String) -> Self {
        Self { chain_id }
    }

    /// Execute a chain with nested sub-steps
    pub async fn execute_chain_steps(
        &self,
        chain_steps: &[ChainSubStep],
        parent_context: &mut ExecutionContext,
    ) -> Result<String, RustChainError> {
        info!(
            "Executing chain '{}' with {} sub-steps",
            self.chain_id,
            chain_steps.len()
        );

        let mut chain_results = Vec::new();
        let mut chain_context = ExecutionContext::new();

        // Copy parent context variables to chain context (read-only access)
        for (key, value) in parent_context.get_all_variables() {
            chain_context.set_variable(key, value);
        }

        for (idx, sub_step) in chain_steps.iter().enumerate() {
            debug!(
                "Executing chain sub-step {}: {}",
                idx + 1,
                sub_step.step_name
            );

            // Create a MissionStep from the ChainSubStep
            let mission_step = self.to_mission_step(sub_step, &chain_context)?;

            // Execute the step using the main DAG executor (with boxing for recursion)
            let step_result =
                Box::pin(DagExecutor::execute_step(&mission_step, &mut chain_context)).await?;

            if step_result.status != crate::engine::StepStatus::Success {
                let error_msg = step_result
                    .error
                    .unwrap_or_else(|| format!("Chain sub-step {} failed", sub_step.step_name));
                error!("Chain sub-step failed: {}", error_msg);
                return Err(RustChainError::Execution(
                    crate::core::error::ExecutionError::StepFailed {
                        mission_id: self.chain_id.clone(),
                        step_id: sub_step.step_name.clone(),
                        reason: error_msg,
                    },
                ));
            }

            // Collect result for final chain output
            if let Some(output) = step_result.output.as_str() {
                chain_results.push(format!("Step {}: {}", sub_step.step_name, output));
            }

            info!(
                "Chain sub-step '{}' completed successfully",
                sub_step.step_name
            );
        }

        let final_result = chain_results.join("\n\n");

        // Copy only chain-specific results back to parent context (scoped variable management)
        for (key, value) in chain_context.get_all_variables() {
            // Only propagate variables that were created within this chain
            if key.starts_with(&format!("{}_", self.chain_id))
                || chain_steps
                    .iter()
                    .any(|step| key.starts_with(&format!("{}_", step.step_name)))
            {
                parent_context.set_variable(key, value);
            }
        }

        // Also propagate the main chain result
        let chain_result_key = format!("{}_result", self.chain_id);
        parent_context.set_variable(&chain_result_key, &final_result);

        Ok(final_result)
    }

    /// Convert ChainSubStep to MissionStep for execution
    fn to_mission_step(
        &self,
        sub_step: &ChainSubStep,
        context: &ExecutionContext,
    ) -> Result<MissionStep, RustChainError> {
        // Substitute variables in parameters
        let mut processed_parameters = sub_step.parameters.clone();

        // Process string values for variable substitution
        Self::substitute_variables_in_value(&mut processed_parameters, context);

        Ok(MissionStep {
            id: sub_step.step_name.clone(),
            name: sub_step.step_name.clone(),
            step_type: sub_step.step_type.clone(),
            parameters: processed_parameters,
            depends_on: None, // Chain handles dependencies internally
            timeout_seconds: sub_step.timeout_seconds,
            continue_on_error: None, // Chain handles error flow internally
        })
    }

    /// Recursively substitute variables in JSON values
    fn substitute_variables_in_value(value: &mut Value, context: &ExecutionContext) {
        match value {
            Value::String(s) => {
                *s = context.substitute_variables(s);
            }
            Value::Object(map) => {
                for (_, v) in map.iter_mut() {
                    Self::substitute_variables_in_value(v, context);
                }
            }
            Value::Array(arr) => {
                for v in arr.iter_mut() {
                    Self::substitute_variables_in_value(v, context);
                }
            }
            _ => {} // Numbers, booleans, null don't need substitution
        }
    }
}

/// Sub-step definition for chain execution
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ChainSubStep {
    pub step_name: String,
    pub step_type: StepType,
    pub parameters: Value,
    pub timeout_seconds: Option<u64>,
}

impl ExecutionContext {
    /// Get all variables for context copying
    pub fn get_all_variables(&self) -> &HashMap<String, String> {
        &self.variables
    }
}
