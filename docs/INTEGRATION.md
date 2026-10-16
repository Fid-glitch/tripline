# Tripline Integration Contract & Governance Architecture

## 1. Executive Summary & Honest Scope

**Tripline** is a self-hosted B2B AI firewall and governance gateway. It intercepts agent actions and requests between enterprise client applications/agents and LLM/tool execution environments.

### Honest Scope & Threat Model
- **Boundary Control**: Tripline strictly controls and audits traffic passing through its enforcement boundary.
- **Provider-Side Boundary**: Tripline cannot guarantee provider-side data handling, vendor-side data retention, or upstream infrastructure security once an allowed request is forwarded to an external LLM provider.
- **Fail-Closed Architecture**: Any failure in usage limits, audit log persistence, or policy evaluation causes the request to be blocked before execution.

---

## 2. Enforcement Call Order

When integrating governance and enforcement into `agent/security.py` or agent runners, callers **MUST** follow this exact sequence:

```python
# 1. Pre-execution quota and rate-limit check (ALWAYS FIRST)
limit = usage_tracker.check_and_consume(
    kind="tool_call" if is_tool else "request",
    user_id=user_id,
    team_id=team_id,
    org_id=org_id,
    simulated=simulation_mode,
    tokens=estimated_tokens,
)

if not limit.allowed:
    # Fail-closed: record blocked attempt in audit log and halt immediately
    audit_log.record(
        action_type=action_name,
        decision="BLOCK",
        reason=f"Usage limit exceeded: {limit.reason}",
        tool_name=tool_name,
        user_id=user_id,
        team_id=team_id,
        org_id=org_id,
        session_id=session_id,
        request_id=request_id,
        attempted=True,
        executed=False,
        simulation_mode=simulation_mode,
        metadata={"limit_scope": limit.scope},
    )
    return {
        "decision": "BLOCK",
        "reason": limit.reason,
        "executed": False,
        "result": None,
    }

# 2. Policy Engine Evaluation (Teammate's policy engine)
# Note: Policy evaluation does NOT execute the tool
policy_eval = policy_engine.evaluate(
    tool_name=tool_name,
    arguments=sanitized_args,
    context=context,
)
decision = policy_eval["decision"]  # ALLOW, REDACT, ASK, or BLOCK
reason = policy_eval["reason"]

# 3. Execution Permission Check
# INVARIANT: Execute ONLY if decision is ALLOW or ASK with verified approval
can_execute = False
if decision == "ALLOW":
    can_execute = True
elif decision == "ASK" and approval_status == "approved":
    can_execute = True

# 4. Protected Execution (if permitted)
execution_result = None
execution_error = None
executed_actual = False

if can_execute:
    try:
        execution_result = execute_protected_tool(tool_name, arguments)
        executed_actual = True
    except Exception as exc:
        executed_actual = True
        execution_error = str(exc)

# 5. Post-Execution Audit Logging (Mandatory)
audit_log.record(
    action_type=action_name,
    decision=decision,
    reason=reason,
    tool_name=tool_name,
    user_id=user_id,
    team_id=team_id,
    org_id=org_id,
    session_id=session_id,
    request_id=request_id,
    signals=policy_eval.get("signals"),
    risk_score=policy_eval.get("risk_score"),
    policy_id=policy_eval.get("policy_id"),
    attempted=True,
    executed=executed_actual,
    approval_status=approval_status,
    simulation_mode=simulation_mode,
    metadata={
        "execution_error": execution_error,
        "result_status": "success" if (executed_actual and not execution_error) else "error",
    },
)
```

---

## 3. Shared Field Definitions & Decision Strings

### Decision Strings
- `ALLOW`: The action passes all security policies and pre-execution checks and is permitted to execute.
- `REDACT`: Sensitive information in arguments or prompts was sanitized or redacted prior to execution.
- `ASK`: The action is elevated for human-in-the-loop approval. **A pending approval is NEVER permission to execute.**
- `BLOCK`: The action is prohibited by policy or exhausted quotas and is immediately prevented from executing.

### Approval Status Values
- `None` or `not_required`: Standard evaluation where human approval was not requested.
- `pending`: Human review is pending. Execution is strictly blocked.
- `approved`: Human supervisor approved the action; execution may now proceed.
- `denied`: Human supervisor rejected the action; execution remains blocked.
- `expired`: Approval window lapsed without resolution.

### Crucial Invariant: Shared `request_id`
When an initial action results in `ASK` (decision: `ASK`, approval_status: `pending`), and is subsequently approved or denied by a supervisor:
- **Both the initial `ASK` event and the subsequent resolution event MUST share the exact same `request_id`**.
- This enables the governance metrics engine and Audit Explorer to resolve the lifecycle of the request without ambiguous state collisions.

---

## 4. Proposed Exact Diff for `agent/security.py`

Per hard constraints, teammates own `agent/security.py`. Below is the exact proposed patch to integrate `UsageTracker` and `AuditLog` without modifying the existing baseline file directly:

```diff
--- a/agent/security.py
+++ b/agent/security.py
@@ -1,7 +1,9 @@
 import json
 from datetime import datetime, timezone
 from pathlib import Path
 from urllib.parse import urlparse
+from agent.audit import AuditLog
+from agent.usage_limits import UsageTracker
 
 from agent import tools
 
@@ -10,6 +12,8 @@ ROOT = Path(__file__).resolve().parent.parent
 AUDIT_LOG = ROOT / "data" / "audit.jsonl"
+_governance_audit = AuditLog()
+_governance_usage = UsageTracker()
 
 ALLOWED_COMMANDS = {
@@ -120,6 +124,19 @@ def execute_tool(tool_name, args, *, user_id="default_user", team_id=None, org_id=None, request_id=None):
     """Evaluate policy first; execute only requests marked ALLOW."""
+    # Step 1: Pre-execution usage check
+    limit_res = _governance_usage.check_and_consume("tool_call", user_id=user_id, team_id=team_id, org_id=org_id)
+    if not limit_res.allowed:
+        _governance_audit.record(
+            action_type="tool_execution",
+            decision="BLOCK",
+            reason=f"Quota exceeded: {limit_res.reason}",
+            tool_name=tool_name,
+            user_id=user_id,
+            request_id=request_id,
+            executed=False,
+        )
+        return {"decision": "BLOCK", "reason": limit_res.reason, "executed": False, "result": None}
+
     decision, reason = evaluate_policy(tool_name, args)
```

---

## 5. Deployment Considerations & Known Limitations

1. **Storage Engine (Prototype vs. Production)**:
   - *Current Implementation*: Uses append-only JSONL files (`logs/audit.jsonl` and `logs/usage.jsonl`) with `os.fsync` and threading locks (`threading.Lock`).
   - *Limitation*: Thread-safe within a single process. Multi-worker or multi-container deployments (e.g. Gunicorn/Uvicorn workers) require a persistent relational database (SQLite in WAL mode for single-node, PostgreSQL/TimescaleDB for distributed clusters).
2. **Offline Local Operation**:
   - Runs fully offline without external cloud dependencies or paid APIs.
3. **Environment Variables**:
   - `TRIPLINE_AUDIT_LOG`: Path to write and read audit JSONL records (default: `logs/audit.jsonl`).
   - `TRIPLINE_USAGE_LOG`: Path to persist usage tracking records (default: `logs/usage.jsonl`).
