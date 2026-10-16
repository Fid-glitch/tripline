import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from agent.audit import (
    AuditLog,
    compute_metrics,
    read_events as fallback_read_events,
)
from agent.domain_policies import evaluate_domain_policy
from agent.runner import read_domain_audit, run_scenario
from agent.usage_limits import (
    LimitConfig,
    UsageTracker,
    enforce_limit_before_execution,
)

st.set_page_config(
    page_title="Tripline | AI Governance & Audit Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Enterprise CSS Styling (dark/light friendly, clean typography, badge pills)
st.markdown(
    """
    <style>
    .metric-card {
        background-color: rgba(127, 127, 127, 0.08);
        border: 1px solid rgba(127, 127, 127, 0.2);
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
    }
    .badge-simulated {
        background-color: #854d0e;
        color: #fef08a;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-real {
        background-color: #166534;
        color: #bbf7d0;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-block {
        background-color: #991b1b;
        color: #fecaca;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-allow {
        background-color: #1e3a8a;
        color: #bfdbfe;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-ask {
        background-color: #7c2d12;
        color: #fed7aa;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Top Header
st.title("🛡️ Tripline AI Governance & Audit Platform")
st.caption(
    "Self-hosted B2B AI firewall and audit backend. Evaluates agent operations, enforces policies "
    "before execution, and maintains tamper-resistant audit logs."
)

# Shared Session State for Tracker
if "tracker" not in st.session_state:
    tracker = UsageTracker(
        default_user_limit=LimitConfig(max_requests=100, max_tool_calls=50, max_tokens=50000),
    )
    tracker.set_scope_limit("org", "acme_corp", LimitConfig(max_requests=500, max_tool_calls=250))
    tracker.set_scope_limit("team", "team_sec_research", LimitConfig(max_requests=200, max_tool_calls=100))
    tracker.set_scope_limit("user", "analyst_clara", LimitConfig(max_requests=50, max_tool_calls=20))
    st.session_state["tracker"] = tracker

active_tracker: UsageTracker = st.session_state["tracker"]

# Load Audit Events
logger = AuditLog()
stored_events = logger.read_events()

# Also load domain audit events if available and merge
domain_events = read_domain_audit()
normalized_domain_events = []
for de in domain_events:
    is_sim = (
        isinstance(de.get("result"), dict)
        and de.get("result", {}).get("status") == "simulated"
    )
    normalized_domain_events.append({
        "event_id": de.get("event_id", f"dom-{hash(de.get('timestamp', ''))}"),
        "timestamp": de.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "organization_id": "acme_corp",
        "team_id": "domain_policy_team",
        "user_id": "scenario_runner",
        "session_id": "scenario_session",
        "request_id": f"req-domain-{de.get('rule_id', 'unknown')}",
        "action_type": f"{de.get('domain')}:{de.get('action')}",
        "tool_name": de.get("action", "domain_action"),
        "decision": de.get("decision", "BLOCK"),
        "reason": de.get("reason", "Domain policy trace"),
        "risk_score": 0.8 if de.get("risk_level") == "HIGH" else (0.2 if de.get("risk_level") == "LOW" else 0.5),
        "policy_id": de.get("rule_id"),
        "signals": de.get("missing_requirements", []),
        "attempted": True,
        "executed": de.get("executed", False),
        "approval_status": "not_required" if de.get("decision") != "REVIEW" else "pending",
        "simulation_mode": is_sim,
        "simulation_status": "SIMULATED" if is_sim else "REAL",
        "metadata": de.get("context", {}),
    })

all_events = stored_events + normalized_domain_events

# Sidebar Controls
st.sidebar.header("Data & Governance Scope")
view_mode = st.sidebar.radio(
    "Data Source Mode",
    ["All Events", "Real Traffic Only", "Simulated Demonstrations Only"],
    index=0,
)
mode_key = "all" if view_mode == "All Events" else ("real" if view_mode == "Real Traffic Only" else "simulated")

if st.sidebar.button("🔄 Refresh Data Sources"):
    st.rerun()

st.sidebar.divider()
st.sidebar.markdown(
    "**Boundary Notice**\n"
    "Tripline controls traffic passing through its enforcement boundary. "
    "It cannot guarantee provider-side data retention or external model handling."
)

# Compute Metrics
metrics = compute_metrics(all_events, mode=mode_key)

# Global Banners
if metrics["simulated_events"] > 0 and mode_key != "real":
    st.warning(
        "⚠️ **SIMULATED DATA IN VIEW**: Some or all of the records below were generated in simulation/demo mode "
        "and do not consume real production budgets."
    )

if metrics["integrity_violations"] > 0:
    st.error(
        f"🚨 **INTEGRITY VIOLATION DETECTED**: {metrics['integrity_violations']} event(s) in audit logs show "
        "executed operations that had decision=BLOCK or unapproved ASK! Investigate immediately."
    )

# Primary Navigation Tabs
tabs = st.tabs([
    "📊 Overview",
    "⚡ Live Activity",
    "✋ Human Approvals",
    "📈 Usage & Budgets",
    "🔍 Audit Explorer & Export",
    "🧪 Scenario Sandbox",
])

# ==============================================================================
# TAB 1: OVERVIEW
# ==============================================================================
with tabs[0]:
    st.subheader("Governance & Firewall Overview")

    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    with m_col1:
        st.metric("Total Events", metrics["total_events"])
    with m_col2:
        st.metric("Blocked Attempts", metrics["blocked_attempts"])
    with m_col3:
        st.metric("Blocks Enforced", metrics["blocks_enforced"])
    with m_col4:
        st.metric("Pending Approvals", metrics["pending_approvals"])
    with m_col5:
        st.metric("Executed Operations", metrics["executed"])

    st.divider()

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.markdown("**Decision Distribution**")
        by_dec = metrics["by_decision"]
        if sum(by_dec.values()) > 0:
            dec_df = pd.DataFrame(
                list(by_dec.items()),
                columns=["Decision", "Count"],
            ).set_index("Decision")
            st.bar_chart(dec_df)
        else:
            st.info("No data yet to plot decision distribution.")

    with chart_col2:
        st.markdown("**Events Timeline**")
        if all_events:
            time_series = []
            for ev in all_events:
                ts = ev.get("timestamp", "")
                if ts:
                    # Truncate to minute
                    clean_ts = ts[:16].replace("T", " ")
                    time_series.append({"time": clean_ts, "count": 1})
            if time_series:
                ts_df = pd.DataFrame(time_series).groupby("time").count()
                st.line_chart(ts_df)
            else:
                st.info("No data yet for events timeline.")
        else:
            st.info("No data yet for events timeline.")

    st.divider()
    st.markdown("**Top Policy Rules Triggered**")
    if metrics["top_policies"]:
        pol_df = pd.DataFrame(
            list(metrics["top_policies"].items()),
            columns=["Policy ID", "Occurrences"],
        ).sort_values(by="Occurrences", ascending=False)
        st.dataframe(pol_df, use_container_width=True, hide_index=True)
    else:
        st.write("No policy occurrences recorded yet.")


# ==============================================================================
# TAB 2: LIVE ACTIVITY
# ==============================================================================
with tabs[1]:
    st.subheader("Live Security Audit Activity")
    st.caption("Detailed stream of all intercepted operations and policy enforcement events.")

    # Filter Controls
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        f_decision = st.selectbox(
            "Filter by Decision",
            ["All", "ALLOW", "BLOCK", "ASK", "REDACT"],
            index=0,
        )
    with f_col2:
        users = sorted(list({e.get("user_id") for e in all_events if e.get("user_id")}))
        f_user = st.selectbox("Filter by User", ["All"] + users, index=0)
    with f_col3:
        tools = sorted(list({e.get("tool_name") or e.get("tool") for e in all_events if e.get("tool_name") or e.get("tool")}))
        f_tool = st.selectbox("Filter by Tool", ["All"] + tools, index=0)
    with f_col4:
        f_type = st.selectbox("Activity Classification", ["All", "Real Only", "Simulated Only"], index=0)

    # Apply Filters
    filtered_events = []
    for ev in all_events:
        is_sim = bool(ev.get("simulation_mode")) or str(ev.get("simulation_status", "")).upper() == "SIMULATED"
        if f_type == "Real Only" and is_sim:
            continue
        if f_type == "Simulated Only" and not is_sim:
            continue

        dec = str(ev.get("decision", "")).upper()
        if dec == "REVIEW":
            dec = "ASK"
        if f_decision != "All" and dec != f_decision:
            continue

        u = ev.get("user_id")
        if f_user != "All" and u != f_user:
            continue

        t = ev.get("tool_name") or ev.get("tool")
        if f_tool != "All" and t != f_tool:
            continue

        filtered_events.append(ev)

    if filtered_events:
        table_rows = []
        for ev in filtered_events:
            is_sim = bool(ev.get("simulation_mode")) or str(ev.get("simulation_status", "")).upper() == "SIMULATED"
            table_rows.append({
                "Timestamp": ev.get("timestamp", "")[:19].replace("T", " "),
                "Type": "SIMULATED" if is_sim else "REAL",
                "User": ev.get("user_id", "anonymous"),
                "Action / Tool": ev.get("tool_name") or ev.get("tool") or ev.get("action_type"),
                "Decision": ev.get("decision"),
                "Risk Score": f"{ev.get('risk_score', 0.0):.2f}" if ev.get("risk_score") is not None else "0.00",
                "Approval": ev.get("approval_status", "not_required"),
                "Executed": "Yes" if ev.get("executed") else "No",
                "Reason": ev.get("reason"),
            })
        st.dataframe(table_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No data yet matching the specified filter criteria.")


# ==============================================================================
# TAB 3: HUMAN APPROVALS
# ==============================================================================
with tabs[2]:
    st.subheader("Human-in-the-Loop Approval Queue")
    st.info(
        "ℹ️ **Safety Rule**: Pending status means the operation is **NOT EXECUTED**. "
        "A pending approval is never permission to execute."
    )

    app_col1, app_col2, app_col3 = st.columns(3)
    with app_col1:
        st.metric("Pending Approvals", metrics["pending_approvals"])
    with app_col2:
        st.metric("Approved Requests", metrics["approved"])
    with app_col3:
        st.metric("Denied Requests", metrics["denied"])

    approval_events = [
        e for e in all_events
        if str(e.get("decision", "")).upper() in {"ASK", "REVIEW"}
        or str(e.get("approval_status", "")).lower() in {"pending", "approved", "denied"}
    ]

    if approval_events:
        st.markdown("### Active & Historic Approval Requests")
        app_rows = []
        for e in approval_events:
            app_rows.append({
                "Request ID": e.get("request_id", "unspecified"),
                "Timestamp": e.get("timestamp", "")[:19].replace("T", " "),
                "User": e.get("user_id", "anonymous"),
                "Tool / Action": e.get("tool_name") or e.get("action_type"),
                "Approval Status": e.get("approval_status", "pending"),
                "Executed": "Yes" if e.get("executed") else "No (Blocked)",
                "Risk Score": e.get("risk_score", "N/A"),
                "Reason / Justification": e.get("reason"),
            })
        st.dataframe(app_rows, use_container_width=True, hide_index=True)
    else:
        st.write("No approval events recorded yet.")


# ==============================================================================
# TAB 4: USAGE & BUDGETS
# ==============================================================================
with tabs[3]:
    st.subheader("Usage Governance & Budget Quotas")
    st.caption("Track and enforce token, request, and tool-call limits across organizations, teams, and users.")

    usage_summary = active_tracker.summary(mode=mode_key)

    u_col1, u_col2, u_col3, u_col4 = st.columns(4)
    with u_col1:
        st.metric("Measured Requests", usage_summary["request_count"])
    with u_col2:
        st.metric("Measured Tool Calls", usage_summary["tool_call_count"])
    with u_col3:
        st.metric("Measured Tokens", usage_summary["measured_tokens"])
    with u_col4:
        # Cost line reads "no real cost data recorded" unless real cost data exists
        cost_val = usage_summary.get("reported_cost_usd")
        if cost_val is not None:
            st.metric("Reported Cost", f"${cost_val:.4f}")
        else:
            st.metric("Reported Cost", "No real cost data recorded")

    st.caption("Tripline records only measured consumption. Monetary savings and unmeasured costs are never estimated or fabricated.")

    st.divider()

    st.markdown("### Per-User Consumption")
    per_user = usage_summary.get("per_user", {})
    if per_user:
        pu_rows = []
        for u, data in per_user.items():
            pu_rows.append({
                "User ID": u,
                "Requests": data.get("requests", 0),
                "Tool Calls": data.get("tool_calls", 0),
                "Tokens": data.get("tokens", 0),
            })
        st.dataframe(pu_rows, use_container_width=True, hide_index=True)
    else:
        st.write("No per-user usage records found yet.")

    st.markdown("### Configured Limit Capacity by Scope")
    limit_remaining = usage_summary.get("limit_remaining", {})
    if limit_remaining:
        lim_rows = []
        for scope, data in limit_remaining.items():
            lim_rows.append({
                "Scope": scope,
                "Used Requests": data.get("used_requests", 0),
                "Max Requests": data.get("max_requests", "Unlimited"),
                "Remaining Requests": data.get("remaining_requests", "Unlimited"),
                "Used Tool Calls": data.get("used_tool_calls", 0),
                "Max Tool Calls": data.get("max_tool_calls", "Unlimited"),
                "Remaining Tool Calls": data.get("remaining_tool_calls", "Unlimited"),
            })
        st.dataframe(lim_rows, use_container_width=True, hide_index=True)
    else:
        st.write("No custom scope limits configured yet.")

    st.divider()
    st.markdown("### Pre-Execution Limit Enforcement Sandbox")
    st.write(
        "Verify that requests or tool calls are verified against configured budgets BEFORE "
        "any protected execution begins. If quota is exhausted, execution is halted."
    )

    t_c1, t_c2, t_c3 = st.columns(3)
    with t_c1:
        sim_user = st.text_input("User ID", value="analyst_clara")
    with t_c2:
        sim_kind = st.selectbox("Quota Type", ["request", "tool_call"])
    with t_c3:
        sim_tokens = st.number_input("Tokens", min_value=0, value=250, step=50)

    if st.button("Consume Quota & Execute Action"):
        def mock_tool_call():
            return {"status": "success", "message": f"Tool call executed for {sim_user}"}

        res = active_tracker.check_and_consume(
            sim_kind,
            user_id=sim_user,
            tokens=int(sim_tokens),
        )

        if res.allowed:
            st.success(f"ALLOWED: {res.reason}. Remaining capacity: {res.remaining}")
            out = mock_tool_call()
            st.json(out)
        else:
            st.error(f"BLOCKED: {res.reason}. Action was NOT executed.")


# ==============================================================================
# TAB 5: AUDIT EXPLORER & EXPORT
# ==============================================================================
with tabs[4]:
    st.subheader("Audit Event Explorer & Compliance Export")
    st.caption("Inspect individual sanitized audit events, trace correlated request lifecycles, and export records.")

    if all_events:
        event_options = [
            f"{e.get('event_id')} | {e.get('timestamp', '')[:19]} | {e.get('decision')} | {e.get('user_id')}"
            for e in all_events
        ]
        selected_option = st.selectbox("Select Event to Inspect", event_options, index=0)
        selected_id = selected_option.split(" | ")[0]
        selected_event = next((e for e in all_events if e.get("event_id") == selected_id), None)

        if selected_event:
            st.markdown("#### Selected Event Details (Sanitized)")
            st.json(selected_event)

            # Correlated Trace Explorer
            req_id = selected_event.get("request_id")
            sess_id = selected_event.get("session_id")

            st.markdown("#### Correlated Execution Trace")
            if req_id or sess_id:
                correlated = [
                    e for e in all_events
                    if (req_id and e.get("request_id") == req_id)
                    or (sess_id and e.get("session_id") == sess_id)
                ]
                correlated.sort(key=lambda x: str(x.get("timestamp", "")))

                st.write(
                    f"Found **{len(correlated)}** event(s) correlated by Request ID `{req_id}` "
                    f"or Session ID `{sess_id}`."
                )
                corr_rows = []
                for ce in correlated:
                    corr_rows.append({
                        "Time": ce.get("timestamp", "")[:19].replace("T", " "),
                        "Event ID": ce.get("event_id"),
                        "Decision": ce.get("decision"),
                        "Tool / Action": ce.get("tool_name") or ce.get("action_type"),
                        "Executed": "Yes" if ce.get("executed") else "No",
                        "Approval": ce.get("approval_status"),
                        "Reason": ce.get("reason"),
                    })
                st.dataframe(corr_rows, use_container_width=True, hide_index=True)
            else:
                st.write("No request_id or session_id associated with this event.")

        st.divider()
        st.markdown("### Export Sanitized Audit Records")
        exp_col1, exp_col2 = st.columns(2)

        # JSON Export
        json_export_data = json.dumps(all_events, indent=2, ensure_ascii=False)
        with exp_col1:
            st.download_button(
                label="📥 Download Sanitized JSON",
                data=json_export_data,
                file_name="tripline_audit_export.json",
                mime="application/json",
            )

        # CSV Export
        csv_buffer = io.StringIO()
        csv_fields = [
            "event_id", "timestamp", "organization_id", "team_id", "user_id",
            "session_id", "request_id", "action_type", "tool_name", "decision",
            "reason", "risk_score", "policy_id", "executed", "approval_status", "simulation_mode"
        ]
        writer = csv.DictWriter(csv_buffer, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for ev in all_events:
            writer.writerow(ev)
        csv_export_data = csv_buffer.getvalue()

        with exp_col2:
            st.download_button(
                label="📥 Download Sanitized CSV",
                data=csv_export_data,
                file_name="tripline_audit_export.csv",
                mime="text/csv",
            )
    else:
        st.info("No data yet to explore or export.")


# ==============================================================================
# TAB 6: SCENARIO SANDBOX (Original Policy Enforcement Scenarios)
# ==============================================================================
with tabs[5]:
    st.subheader("Deterministic Policy Sandbox & Evaluation")
    st.caption("Test pre-configured scenarios and verify explainable policy rules.")

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

    selected = st.selectbox("Choose a scenario to evaluate", list(SCENARIOS.keys()))
    domain, action, context, expected = SCENARIOS[selected]

    s_left, s_right = st.columns(2)
    with s_left:
        st.write("**Domain:**", domain)
        st.write("**Action:**", action)
    with s_right:
        st.write("**Context:**")
        st.json(context if context else {"context": "none"})

    if st.button("Evaluate Scenario Policy"):
        res = run_scenario(domain, action, context)
        trace = res.get("trace", res)
        decision = res["decision"]

        c1, c2, c3 = st.columns(3)
        c1.metric("Decision", decision)
        c2.metric("Executed", "Yes" if res["executed"] else "No")
        c3.metric("Expected", "PASS" if decision == expected else "FAIL")

        if decision == "ALLOW":
            st.success(trace["reason"])
        elif decision == "BLOCK":
            st.error(trace["reason"])
        else:
            st.warning(trace["reason"])

        st.json(trace)
