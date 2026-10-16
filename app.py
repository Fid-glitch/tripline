
import streamlit as st

from agent.runner import run_scenario, read_domain_audit
from agent.domain_policies import evaluate_domain_policy


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
st.header("4. Audit Trail")

if st.button("Refresh audit trail"):
    st.rerun()

events = read_domain_audit()
if events:
    st.dataframe(events, use_container_width=True, hide_index=True)
else:
    st.write("No scenario executions recorded yet.")

st.caption(
    "Audit records are stored locally in data/domain_audit.jsonl. "
    "This prototype does not provide tamper-proof or externally "
    "verified audit storage."
)
