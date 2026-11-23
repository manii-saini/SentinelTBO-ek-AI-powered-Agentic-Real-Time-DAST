from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DB_PATH = Path(os.getenv("SENTINEL_DB", str(DATA_DIR / "sentinel.db")))
TARGET_BASE_URL = os.getenv("SENTINEL_TARGET", "http://synthetic.travel.internal")
TARGET_HOST = "synthetic.travel.internal"

DEFAULT_ALLOWLIST = [h.strip() for h in os.getenv("SENTINEL_ALLOWLIST", TARGET_HOST).split(",") if h.strip()]
DEFAULT_SAFETY = {
    "allowlist": DEFAULT_ALLOWLIST,
    "rateLimit": int(os.getenv("SENTINEL_RATE_LIMIT", "12")),
    "burst": int(os.getenv("SENTINEL_BURST", "20")),
    "healthPauseThreshold": float(os.getenv("SENTINEL_HEALTH_PAUSE", "0.5")),
    "healthBackoffThreshold": float(os.getenv("SENTINEL_HEALTH_BACKOFF", "0.25")),
    "killSwitch": False,
    "requireApprovalForDestructive": True,
    "testCredentials": {
        "agent-a": {"agency": "A", "role": "agent", "token": "test-agent-a"},
        "subagent-a": {"agency": "A", "role": "sub-agent", "token": "test-subagent-a"},
        "admin-a": {"agency": "A", "role": "admin", "token": "test-admin-a"},
        "agent-b": {"agency": "B", "role": "agent", "token": "test-agent-b"},
        "subagent-b": {"agency": "B", "role": "sub-agent", "token": "test-subagent-b"},
        "admin-b": {"agency": "B", "role": "admin", "token": "test-admin-b"},
    },
}

DISCOVERY_TECHNIQUES = [
    {"name": "JS bundle route extraction", "detail": "Parse quoted route literals from production front-end bundles"},
    {"name": "HAR ingestion", "detail": "Import recorded browser sessions from QA and staging"},
    {"name": "Hidden path guessing", "detail": "Probe /v1 /old /internal /test /beta /debug prefixes"},
    {"name": "Gateway log diff", "detail": "Compare inferred map against 30/90-day gateway traffic"},
    {"name": "CT-log subdomains", "detail": "Correlate certificate transparency entries with staging hosts"},
    {"name": "In-process synthetic crawl", "detail": "Authenticated crawl of synthetic staging routes without external browser/server dependencies"},
]

TRIGGER_ENDPOINTS = {
    "deploy": {"title": "CI/CD deploy webhook", "detail": "Staging deploy finished; changed booking, payment and search handlers queued for retest.", "endpoints": ["/api/search", "/api/hold", "/api/book", "/api/pay", "/api/cancel", "/api/bookings/:id", "/api/invoices/:id"]},
    "bundle-diff": {"title": "New front-end JS bundle diff", "detail": "Bundle hash changed; 2 new API routes extracted from route manifest.", "endpoints": ["/api/book", "/api/pay"]},
    "subdomain": {"title": "New staging subdomain observed", "detail": "CT log emitted a certificate for a staging host; hidden-path probe queued.", "endpoints": ["/internal/debug"]},
    "traffic-anomaly": {"title": "Gateway traffic-log anomaly", "detail": "Unusual request volume on a legacy path with no recent inventory hits.", "endpoints": ["/v1/bookings"]},
}

ENDPOINT_META = {
    "/api/search": {"roles": ["agent", "sub-agent"], "params": [{"name": "origin", "location": "body", "type": "string"}, {"name": "destination", "location": "body", "type": "string"}], "data": ["fares"], "context": ["bookings"], "flow": "search"},
    "/api/hold": {"roles": ["agent", "sub-agent"], "params": [{"name": "holdId", "location": "body", "type": "string"}], "data": ["pnr", "fares"], "context": ["bookings"], "flow": "hold"},
    "/api/book": {"roles": ["agent", "sub-agent", "admin"], "params": [{"name": "holdId", "location": "body", "type": "string"}, {"name": "fare", "location": "body", "type": "number", "controllable": True}, {"name": "role", "location": "body", "type": "string", "controllable": True, "sensitive": True}, {"name": "quantity", "location": "body", "type": "number", "controllable": True}], "data": ["pnr", "passenger"], "context": ["bookings", "payments"], "flow": "book"},
    "/api/bookings/mine": {"roles": ["agent", "sub-agent", "admin"], "params": [], "data": ["pnr", "bookings"], "context": ["bookings"], "flow": "book"},
    "/api/bookings/:id": {"roles": ["agent", "sub-agent", "admin"], "params": [{"name": "id", "location": "path", "type": "string", "controllable": True}], "data": ["pnr", "passenger", "bookings"], "context": ["bookings", "pii"], "flow": "book"},
    "/api/pay": {"roles": ["agent", "admin"], "params": [{"name": "amount", "location": "body", "type": "number", "controllable": True}, {"name": "coupon", "location": "body", "type": "string", "controllable": True}], "data": ["payments"], "context": ["payments", "coupons"], "flow": "pay"},
    "/api/cancel": {"roles": ["agent", "admin"], "params": [{"name": "holdId", "location": "body", "type": "string", "controllable": True}], "data": ["payments"], "context": ["payments", "credit"], "flow": "cancel"},
    "/api/invoices/:id": {"roles": ["agent", "admin"], "params": [{"name": "id", "location": "path", "type": "string"}], "data": ["pnr", "invoices"], "context": ["invoices"], "flow": "pay"},
    "/api/supplier/webhook": {"roles": ["agent", "admin"], "params": [{"name": "url", "location": "body", "type": "url", "controllable": True, "sensitive": True}], "data": ["supplier config"], "context": ["supplier-access"], "flow": "cancel"},
    "/v1/bookings": {"roles": ["agent", "admin"], "params": [], "data": ["bookings", "passenger"], "context": ["bookings", "pii"], "flow": "legacy"},
    "/internal/debug": {"roles": [], "params": [], "data": ["passport", "pnr", "email"], "context": ["pii", "supplier-access"], "flow": "internal"},
    "/api/v2/coupons/stack": {"roles": [], "params": [{"name": "count", "location": "query", "type": "number", "controllable": True}], "data": ["coupons", "payments"], "context": ["payments", "coupons", "credit"], "flow": "pay"},
}


def load_ownership() -> list[dict[str, Any]]:
    p = ROOT / "packages" / "shared" / "assets.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return [{"pathPrefix": "/", "owner": "Unassigned", "team": "Triage", "slack": "#security-triage"}]


def owner_for_path(path: str) -> dict[str, Any]:
    entries = load_ownership()
    for e in entries:
        if path.startswith(e.get("pathPrefix", "/")):
            return e
    return entries[-1]


def meta_for_path(path: str) -> dict[str, Any]:
    return ENDPOINT_META.get(path, {"roles": ["agent"], "params": [], "data": ["unknown"], "context": ["bookings"], "flow": "unknown"})
