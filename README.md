# Tripline

Self-hosted B2B AI firewall, governance gateway, and audit monitoring platform.

Tripline sits between enterprise applications/agents and LLM providers or tool environments, enforcing access policy (`ALLOW`, `REDACT`, `ASK`, `BLOCK`) before execution, tracking token/tool/request usage budgets, and recording sanitized audit events.

---

## Architecture & Governance Layer

- **Audit Logging (`agent/audit.py`)**:
  - Thread-safe, append-only JSONL event storage with `os.fsync` disk flushes.
  - Fail-closed write guarantees via `AuditWriteError`.
  - Comprehensive pre-write data sanitization: regex redaction for API keys (`sk-`, `AKIA`, `ghp_`, `xox`), bearer tokens, private keys, credential assignments, emails, and dropped sensitive payload fields.
  - Strict security invariant enforcement: operations marked `BLOCK` or unapproved `ASK` can never be recorded as executed.

- **Usage Quotas & Rate Limits (`agent/usage_limits.py`)**:
  - Atomic scoped limit enforcement (`user`, `team`, `organization`).
  - Pre-execution checks that fail closed on unknown kinds, missing user IDs, or persistence errors.
  - Strict isolation: simulated requests never consume real user or organizational budgets.
  - Window resets for rate-limiting windows.

- **Governance Dashboard (`app.py`)**:
  - Streamlit dashboard providing:
    - **Overview**: Real-time event totals, block rates, pending approvals, decision distributions, and events timeline.
    - **Live Activity**: Filterable stream by decision, user, tool, and traffic classification (Real vs. Simulated).
    - **Human Approvals**: Dedicated queue for requests requiring secondary human elevation.
    - **Usage & Budgets**: Per-user consumption metrics, quota capacity remaining, and strict honesty reporting ("No real cost data recorded" when unmeasured).
    - **Audit Explorer & Export**: Deep trace explorer correlated by `request_id` or `session_id` with sanitized JSON and CSV exports.
    - **Policy Sandbox**: Deterministic policy evaluation testbed.

---

## Setup & Running Locally

### 1. Requirements & Installation
Tripline runs locally and offline without external paid services.

```bash
# Install dependencies
pip install -r requirements.txt   # or: pip install streamlit pandas pytest
```

### 2. Environment Variables
- `TRIPLINE_AUDIT_LOG`: Path to write and read audit JSONL records (default: `logs/audit.jsonl`).
- `TRIPLINE_USAGE_LOG`: Path to persist usage tracking records (default: `logs/usage.jsonl`).

### 3. Run the Dashboard
```bash
streamlit run app.py
```

### 4. Run the Test Suite
```bash
python -m pytest
```

### 5. Seed Demo Simulation Events
To seed sample demonstration events (clearly tagged with `simulation_mode=True`):
```bash
python scripts/seed_demo_events.py
```

---

## Honest Scope & Limitations

### Honest Scope
- **Boundary Control**: Tripline strictly controls and audits traffic passing through its enforcement boundary.
- **Provider-Side Boundary**: Tripline cannot guarantee provider-side data handling, vendor-side data retention, or upstream infrastructure security once an allowed request is forwarded to an external LLM provider.

### Limitations
- **Storage Engine**: The current append-only JSONL files with in-process threading locks are prototype-grade, designed for single-node development and evaluation.
- **Production Migration**: For multi-process or horizontally scaled production deployments (e.g. multi-worker Uvicorn/Gunicorn), replace the JSONL logger with a persistent relational database such as SQLite in WAL mode or PostgreSQL/TimescaleDB.
