
import streamlit as st

from agent.runner import run_scenario, read_domain_audit
from agent.domain_policies import evaluate_domain_policy
from agent.audit import read_events, calculate_audit_metrics
from agent.usage_limits import (
    UsageLimiter,
    calculate_usage_metrics,
    enforce_limit_before_execution,
)


st.set_page_config(
    page_title="Tripline | AI Policy Gateway",
    page_icon="T",
    layout="wide",
)

st.title("Tripline")
st.subheader("Policy Enforcement for AI Agent Actions")

st.write(
    "A policy gateway that evaluates agent actions before execution "
    "and records why each decision was made."
)

st.info(
    "Prototype mode: permitted actions are simulated. No real images "
    "are edited, and no medical advice is generated. Consent and "
    "authorization are represented by mock scenario data."
)

SCENARIOS = {
    "Image - consent verified (mock)": (
        "image",
        "edit_image",
        {"consent_status": "verified", "subject_authorized": True},
        "ALLOW",
    ),
    "Image - consent missing": (
        "image",
        "edit_image",
        {"consent_status": "missing"},
        "REVIEW",
    ),
    "Image - consent denied": (
        "image",
        "edit_image",
        {"consent_status": "denied"},
        "BLOCK",
    ),
    "Medical - general education": (
        "medical",
        "general_education",
        {},
        "ALLOW",
    ),
    "Medical - personalized dosage": (
        "medical",
        "personalized_dosage",
        {},
        "BLOCK",
    ),
    "Medical - high-risk symptoms": (
        "medical",
        "high_risk_symptoms",
        {},
        "REVIEW",
    ),
    "Medical - personalized treatment": (
        "medical",
        "personalized_treatment",
        {},
        "REVIEW",
    ),
}

st.divider()
st.header("1. Decision Explorer")

selected = st.selectbox("Choose a scenario", list(SCENARIOS.keys()))
domain, action, context, expected = SCENARIOS[selected]

left, right = st.columns(2)

with left:
    st.write("**Domain:**", domain)
    st.write("**Requested action:**", action)

with right:
    st.write("**Scenario context**")
    st.json(context if context else {"context": "none"})

if st.button("Evaluate policy and run mock action", type="primary"):
    result = run_scenario(domain, action, context)
    st.session_state["last_result"] = result
    st.session_state["last_expected"] = expected

if "last_result" in st.session_state:
    result = st.session_state["last_result"]
    expected = st.session_state["last_expected"]
    trace = result.get("trace", result)
    decision = result["decision"]

    st.divider()
    st.header("2. Enforcement Decision")

    c1, c2, c3 = st.columns(3)
    c1.metric("Policy decision", decision)
    c2.metric(
        "Mock action executed",
        "Yes" if result["executed"] else "No",
    )
    c3.metric(
        "Expected outcome",
        "PASS" if decision == expected else "FAIL",
    )

    if decision == "ALLOW":
        st.success(trace["reason"])
    elif decision == "BLOCK":
        st.error(trace["reason"])
    else:
        st.warning(trace["reason"])

    detail1, detail2, detail3 = st.columns(3)

    with detail1:
        st.write("**Policy rule**")
        st.code(trace.get("rule_id", "Not provided"))

    with detail2:
        st.write("**Risk level**")
        st.write(trace.get("risk_level", "Not provided"))

    with detail3:
        st.write("**Next step**")
        st.write(trace.get("next_step", "Not provided"))

    st.subheader("Decision Trace")
    st.write("**Why this decision was made**")
    st.write(trace["reason"])

    checks = trace.get("checks", [])
    if checks:
        st.write("**Policy checks**")
        st.dataframe(
            [
                {
                    "Check": check["name"],
                    "Passed": check["passed"],
                    "Details": check["detail"],
                }
                for check in checks
            ],
            use_container_width=True,
            hide_index=True,
        )

    missing = trace.get("missing_requirements", [])
    st.write("**Missing requirements**")
    if missing:
        for requirement in missing:
            st.write(f"- {requirement}")
    else:
        st.write("No missing requirements reported.")

    st.subheader("Execution Outcome")
    if result["executed"]:
        st.success("The policy permitted the mock action to run.")
        if result.get("result") is not None:
            st.json(result["result"])
    else:
        st.warning(
            "The action was not executed because the policy did not "
            "return ALLOW."
        )

    if result.get("execution_error"):
        st.error(f"Execution error: {result['execution_error']}")

    st.caption(
        "The trace is a structured explanation of policy checks, "
        "not a model's private chain-of-thought. REVIEW does not "
        "execute the action; human approval is not implemented."
    )

st.divider()
st.header("3. Policy Evaluation")

evaluation_cases = [
    ("image", "edit_image",
     {"consent_status": "verified", "subject_authorized": True},
     "ALLOW"),
    ("image", "edit_image", {"consent_status": "missing"}, "REVIEW"),
    ("image", "edit_image", {"consent_status": "denied"}, "BLOCK"),
    ("medical", "general_education", {}, "ALLOW"),
    ("medical", "personalized_dosage", {}, "BLOCK"),
    ("medical", "high_risk_symptoms", {}, "REVIEW"),
    ("medical", "personalized_treatment", {}, "REVIEW"),
]

evaluation_results = []
for case_domain, case_action, case_context, case_expected in evaluation_cases:
    decision, reason = evaluate_domain_policy(
        case_domain, case_action, case_context
    )
    evaluation_results.append({
        "Domain": case_domain,
        "Action": case_action,
        "Expected": case_expected,
        "Actual": decision,
        "Pass": decision == case_expected,
        "Reason": reason,
    })

passed = sum(row["Pass"] for row in evaluation_results)
blocked = sum(row["Actual"] == "BLOCK" for row in evaluation_results)
reviewed = sum(row["Actual"] == "REVIEW" for row in evaluation_results)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Policy cases", len(evaluation_results))
m2.metric("Expected decisions matched", f"{passed}/{len(evaluation_results)}")
m3.metric("BLOCK decisions", blocked)
m4.metric("REVIEW decisions", reviewed)

with st.expander("View all evaluation cases"):
    st.dataframe(
        evaluation_results,
        use_container_width=True,
        hide_index=True,
    )

st.caption(
    "These deterministic checks verify expected policy outcomes. "
    "They are not an independent benchmark of real-world AI safety."
)

st.divider()
st.header("4. Security Audit Events & Governance Monitoring")

col_btn1, col_btn2 = st.columns([1, 4])
with col_btn1:
    if st.button("Refresh audit logs"):
        st.rerun()

audit_events = read_events()
domain_events = read_domain_audit()

# Combined view of all logged events for metrics
combined_events = audit_events + domain_events
audit_metrics = calculate_audit_metrics(combined_events)

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Events", audit_metrics["total_events"])
col2.metric("Blocked Attempts", audit_metrics["blocked"])
col3.metric("Pending Approvals", audit_metrics["pending_approvals"])
col4.metric("Real vs Simulated", f"{audit_metrics['real']} Real / {audit_metrics['simulated']} Sim")
col5.metric("Block Rate", f"{audit_metrics['block_rate_pct']}%")

audit_tab1, audit_tab2 = st.tabs(["Structured Security Events", "Domain Scenario Events"])

with audit_tab1:
    if audit_events:
        st.write(f"Showing **{len(audit_events)}** structured security events from `data/audit.jsonl`.")
        formatted_security_events = []
        for event in audit_events:
            sim_badge = "SIMULATED" if str(event.get("simulation_status", "")).upper() == "SIMULATED" else "REAL"
            formatted_security_events.append({
                "Timestamp": event.get("timestamp"),
                "Action / Tool": event.get("tool") or event.get("action"),
                "Decision": event.get("decision"),
                "Approval": event.get("approval_status", "NOT_REQUIRED"),
                "Activity Type": sim_badge,
                "Executed": "Yes" if event.get("executed") else "No",
                "Reason": event.get("reason"),
            })
        st.dataframe(formatted_security_events, use_container_width=True, hide_index=True)

        with st.expander("Inspect Raw Sanitized Events (JSON)"):
            st.json(audit_events[:10])
    else:
        st.write("No structured security events recorded yet in `data/audit.jsonl`.")

with audit_tab2:
    if domain_events:
        st.write(f"Showing **{len(domain_events)}** domain scenario events from `data/domain_audit.jsonl`.")
        formatted_domain_events = []
        for event in domain_events:
            is_sim = (
                isinstance(event.get("result"), dict)
                and event.get("result", {}).get("status") == "simulated"
            )
            formatted_domain_events.append({
                "Timestamp": event.get("timestamp"),
                "Domain": event.get("domain"),
                "Action": event.get("action"),
                "Decision": event.get("decision"),
                "Activity Type": "SIMULATED" if is_sim else "REAL",
                "Executed": "Yes" if event.get("executed") else "No",
                "Reason": event.get("reason"),
            })
        st.dataframe(formatted_domain_events, use_container_width=True, hide_index=True)
    else:
        st.write("No domain scenario events recorded yet.")

st.caption(
    "Audit records are sanitized before persistence. Sensitive credentials, "
    "tokens, and private keys are never stored unredacted in audit logs."
)

st.divider()
st.header("5. Usage Limits & Budget Governance")

st.write(
    "Enforce per-user, team, and organization request and tool-call limits "
    "before protected operations execute."
)

# Initialize in-memory limiter in session state for live governance demonstration
if "limiter" not in st.session_state:
    limiter = UsageLimiter()
    limiter.configure_limit(scope_type="organization", scope_id="org-enterprise", limit=100, limit_type="request")
    limiter.configure_limit(scope_type="team", scope_id="team-ai-safety", limit=20, limit_type="tool_call")
    limiter.configure_limit(scope_type="team", scope_id="team-ai-safety", limit=50, limit_type="request")
    limiter.configure_limit(scope_type="user", scope_id="user-analyst", limit=5, limit_type="request")
    limiter.configure_limit(scope_type="user", scope_id="user-analyst", limit=2, limit_type="tool_call")
    limiter.configure_limit(scope_type="application", scope_id="app-customer-agent", limit=200, limit_type="request")
    st.session_state["limiter"] = limiter

active_limiter: UsageLimiter = st.session_state["limiter"]
all_usages = active_limiter.get_all_usage()
usage_metrics = calculate_usage_metrics(all_usages)

u1, u2, u3, u4 = st.columns(4)
u1.metric("Configured Scopes", usage_metrics["total_configured_scopes"])
u2.metric("Total Requests & Tool Calls", usage_metrics["total_used"])
u3.metric("Scopes at Limit", usage_metrics["scopes_at_limit"])
u4.metric("Scopes with Capacity", usage_metrics["scopes_with_capacity"])

st.subheader("Active Limits and Budgets")
if all_usages:
    display_rows = []
    for row in all_usages:
        limit_val = row["limit"]
        used_val = row["used"]
        rem_val = row["remaining"]
        status = "EXCEEDED / BLOCKED" if (limit_val is not None and used_val >= limit_val) else "ACTIVE"
        display_rows.append({
            "Scope Type": row["scope_type"],
            "Scope ID": row["scope_id"],
            "Limit Type": row["limit_type"],
            "Used": used_val,
            "Limit": limit_val if limit_val is not None else "Unlimited",
            "Remaining": rem_val if rem_val is not None else "Unlimited",
            "Status": status,
        })
    st.dataframe(display_rows, use_container_width=True, hide_index=True)

st.subheader("Test Pre-Execution Limit Enforcement")
st.write(
    "Verify that limits are checked and enforced before the protected action executes. "
    "If the limit check fails or quota is exhausted, execution is prevented."
)

t_col1, t_col2, t_col3 = st.columns(3)
with t_col1:
    test_scope_type = st.selectbox(
        "Scope Type",
        ["user", "team", "organization", "application"],
        index=0,
    )
with t_col2:
    test_scope_id = st.text_input("Scope ID", value="user-analyst")
with t_col3:
    test_limit_type = st.selectbox(
        "Limit Type",
        ["request", "tool_call"],
        index=0,
    )

if st.button("Enforce Limit Before Execution"):
    def mock_protected_operation():
        return {"status": "success", "message": f"Protected {test_limit_type} executed for {test_scope_id}"}

    exec_result = enforce_limit_before_execution(
        active_limiter,
        scope_type=test_scope_type,
        scope_id=test_scope_id,
        operation_fn=mock_protected_operation,
        limit_type=test_limit_type,
    )

    if exec_result["allowed"] and exec_result["executed"]:
        st.success(f"ALLOWED & EXECUTED: {exec_result['reason']}. Remaining quota: {exec_result['usage']['remaining']}")
        st.json(exec_result["result"])
    else:
        st.error(f"BLOCKED: {exec_result['reason']}. Protected operation was NOT executed.")
        st.write(f"Current usage: {exec_result['usage']['used']}/{exec_result['usage']['limit']}")

st.caption(
    "Governance Note: Usage metrics and limit decisions reflect real in-memory counters "
    "and stored usage records. No synthetic or estimated monetary savings are claimed."
)

