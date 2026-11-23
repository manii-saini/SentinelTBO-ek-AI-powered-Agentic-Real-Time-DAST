# SentinelTBO - Streamlit Edition

Agentic DAST + continuous change monitoring demo for travel/e-commerce staging APIs, refactored to run as a **single Streamlit app** (no Node/npm, no separate localhost services).

## Features

- 9-stage workflow: `detect -> recon/learn -> inventory -> plan -> execute -> verify -> triage -> report -> retest`
- 7 specialist agents: Access Control, Business Logic, Authentication, Injection, Hygiene, Data Exposure, SSRF
- In-process synthetic vulnerable travel platform (safe default target: `synthetic.travel.internal`)
- Real-time pipeline/events, findings dashboard, severity classification, evidence, PoC replay
- False-positive verification, dedup, retest lifecycle
- Safety controls: explicit allowlist, synthetic marker/credential enforcement, destructive approvals, rate limits, kill switch, health pause/backoff
- SHA-256 hash-chained audit logs with PII redaction
- SQLite persistence across Streamlit reruns
- Mock Jira/Teams/webhook integrations, JSONL/CSV/OpenAPI export
- Deterministic offline demo mode

## Run Locally

```bash
pip install -r requirements.txt
streamlit run main.py
```

Run from repository root. No `npm install`, no ports `3001/4000/5173`.

## Tests

```bash
python3 -m pytest -q
```

## Streamlit Community Cloud

1. Push this repo to GitHub.
2. In Streamlit Community Cloud, create an app with main file `main.py`.
3. Dependencies install from `requirements.txt`.
4. **No secrets required** for default demo mode. Optional secrets: see `.streamlit/secrets.toml.example`.
5. Deploy/reboot. If you previously had `packages.txt`, remove it (no system packages required).

## Safety Notes

- Default target is the in-process synthetic platform only.
- Out-of-scope hosts are blocked and audit-logged.
- Destructive/high-risk operations require approval in the UI.
- Kill switch blocks all outbound test traffic.
- Do not point this demo at production systems.
