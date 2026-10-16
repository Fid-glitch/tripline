#!/usr/bin/env python3
"""
Seed helper script for Tripline Governance Dashboard.
Writes clearly marked simulation_mode=True events through the real AuditLog.record() path.

CRITICAL CONSTRAINTS:
- Must NEVER run automatically on import.
- Must NEVER mark simulated events as real (simulation_mode=True on ALL events).
- Enables rich dashboard demonstration offline without fabrication.
"""

import sys
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.audit import AuditLog


def seed_demo_events() -> None:
    """Populate demo audit events strictly flagged as simulation_mode=True."""
    logger = AuditLog()
    print(f"[*] Seeding demo simulation events into: {logger.log_path}")

    # 1. Benign allows (safe read and info queries)
    logger.record(
        action_type="tool_execution",
        decision="ALLOW",
        reason="File read inside designated sandbox environment",
        tool_name="read_file",
        user_id="analyst_clara",
        team_id="team_sec_research",
        org_id="acme_corp",
        session_id="sess_sim_001",
        request_id="req_sim_101",
        signals=["sandbox_path_verified"],
        risk_score=0.05,
        policy_id="POL-SANDBOX-ALLOW",
        attempted=True,
        executed=True,
        approval_status="not_required",
        simulation_mode=True,
        metadata={"path": "sandbox/report.txt", "bytes": 1024},
    )

    logger.record(
        action_type="llm_query",
        decision="ALLOW",
        reason="General domain knowledge request within safe parameters",
        tool_name="chat_completion",
        user_id="engineer_bob",
        team_id="team_engineering",
        org_id="acme_corp",
        session_id="sess_sim_002",
        request_id="req_sim_102",
        signals=["benign_content"],
        risk_score=0.10,
        policy_id="POL-LLM-CHAT",
        attempted=True,
        executed=True,
        approval_status="not_required",
        simulation_mode=True,
        metadata={"model": "claude-3-haiku", "tokens": 420},
    )

    # 2. Blocked Exfiltration Chain
    chain_req_id = "req_sim_exfil_201"
    logger.record(
        action_type="tool_execution",
        decision="BLOCK",
        reason="Access to sensitive environment credentials file (.env) denied",
        tool_name="read_file",
        user_id="compromised_agent_01",
        team_id="team_data_ops",
        org_id="acme_corp",
        session_id="sess_sim_exfil",
        request_id=chain_req_id,
        signals=["sensitive_file_target", "credentials_pattern"],
        risk_score=0.92,
        policy_id="POL-CREDENTIALS-PROTECTION",
        attempted=True,
        executed=False,
        approval_status="not_required",
        simulation_mode=True,
        metadata={"target_file": ".env", "rule": "SENSITIVE_FILES"},
    )

    logger.record(
        action_type="tool_execution",
        decision="BLOCK",
        reason="External HTTP POST exfiltration blocked by firewall egress rule",
        tool_name="http_request",
        user_id="compromised_agent_01",
        team_id="team_data_ops",
        org_id="acme_corp",
        session_id="sess_sim_exfil",
        request_id=chain_req_id,
        signals=["untrusted_destination", "suspected_exfil"],
        risk_score=0.98,
        policy_id="POL-EGRESS-FIREWALL",
        attempted=True,
        executed=False,
        approval_status="not_required",
        simulation_mode=True,
        metadata={"destination": "https://attacker-c2.xyz/collect"},
    )

    # 3. Pending Human Approval (ASK)
    # Notice: executed=False, approval_status="pending"
    logger.record(
        action_type="tool_execution",
        decision="ASK",
        reason="Bulk customer record export requires secondary supervisor authorization",
        tool_name="db_bulk_export",
        user_id="analyst_clara",
        team_id="team_analytics",
        org_id="acme_corp",
        session_id="sess_sim_003",
        request_id="req_sim_ask_301",
        signals=["large_dataset_export", "pii_columns_detected"],
        risk_score=0.75,
        policy_id="POL-HUMAN-APPROVAL-REQUIRED",
        attempted=True,
        executed=False,
        approval_status="pending",
        simulation_mode=True,
        metadata={"record_count": 15000, "table": "customers"},
    )

    # 4. Limit Block (Usage quota exhaustion)
    logger.record(
        action_type="request_limit",
        decision="BLOCK",
        reason="Hourly tool-call budget exhausted for user (10/10 consumed)",
        tool_name="tool_call_limiter",
        user_id="automated_crawler",
        team_id="team_data_ops",
        org_id="acme_corp",
        session_id="sess_sim_004",
        request_id="req_sim_limit_401",
        signals=["rate_limit_exceeded"],
        risk_score=0.50,
        policy_id="POL-RATE-LIMIT-USER",
        attempted=True,
        executed=False,
        approval_status="not_required",
        simulation_mode=True,
        metadata={"quota_type": "max_tool_calls", "limit": 10, "used": 10},
    )

    print("[+] Successfully seeded 6 simulation demo events.")


if __name__ == "__main__":
    seed_demo_events()
