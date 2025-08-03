# Copilot Mission Runner Instructions

## Mission
Automate the execution of all mission YAMLs from `mission-stacks/00-error-foundation.yaml` through `mission-stacks/52-secure-tool-wrapper.yaml` using the XO runtime flexible runner. For each mission:

- Run the mission using the runner.
- If the mission completes successfully, proceed to the next.
- If any mission fails or errors, STOP immediately and diagnose the issue.
- If you cannot resolve the problem or are unsure, STOP and request human assistance.
- Do not modify mission YAMLs unless absolutely necessary to fix a blocking error.
- Ensure all files are created in the correct locations as specified by each mission.
- Log and report all actions and errors for traceability.
- **After each mission, check that all outputs match the mission requirements and are of expected quality. If any output is missing, incorrect, or incomplete, STOP and diagnose before proceeding. You are the error checker.**

## Workflow
1. Start at mission 00 and proceed sequentially through mission 52.
2. For each mission:
   - Delete any files that may conflict with the mission's output before running.
   - Run the mission with the runner.
   - Check for errors or failed steps.
   - **After running, verify that all files and outputs match the mission YAML's requirements.**
   - If successful, continue. If not, stop and debug.
3. If a mission requires human input or cannot be resolved, stop and ask for help.

## Notes
- Do not update or reorganize missions unless required to fix a run-blocking error.
- Always prefer automation and minimal manual intervention.
- Document any changes or issues encountered.

---
This file governs Copilot's behavior for the RustChain mission automation process.
