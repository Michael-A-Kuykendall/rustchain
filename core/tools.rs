use crate::engine::context::RuntimeContext;
use crate::core::telemetry::TelemetryEvent;

pub async fn call_tool_secure(
    ctx: &RuntimeContext,
    agent_id: &str,
    tool_name: &str,
    input: &str
) -> String {
    if !ctx.security.is_tool_allowed(tool_name) {
        return format!("Tool blocked by security policy: {}", tool_name);
    }

    if !ctx.rbac.is_allowed(agent_id, tool_name) {
        return format!("Access denied for agent {} to tool {}", agent_id, tool_name);
    }

    ctx.telemetry_sink.emit(TelemetryEvent::ToolInvoked {
        name: tool_name.to_string(),
        input: input.to_string(),
    });

    let result = match get_tool(tool_name).await {
        Some(tool) => tool.call(input).await,
        None => format!("Tool not found: {}", tool_name),
    };

    ctx.telemetry_sink.emit(TelemetryEvent::ToolResult {
        name: tool_name.to_string(),
        output: result.clone(),
    });

    // Record audit log
    if result.contains("denied") || result.contains("blocked") {
        ctx.audit_log.record(agent_id, "ToolAccessViolation", &result);
    }

    result
}
---
