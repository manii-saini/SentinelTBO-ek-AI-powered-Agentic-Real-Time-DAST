from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Agency = Literal["A", "B"]
Role = Literal["agent", "sub-agent", "admin"]
StageId = Literal["detect", "recon", "inventory", "plan", "execute", "verify", "triage", "report", "retest"]
StageStatus = Literal["idle", "running", "done", "blocked", "error"]
TriggerKind = Literal["deploy", "bundle-diff", "subdomain", "traffic-anomaly"]
InventoryStatus = Literal["active", "zombie", "shadow"]
TestClass = Literal["access-control", "business-logic", "auth-session", "injection", "api-hygiene", "data-exposure", "ssrf-open-redirect"]
Severity = Literal["critical", "high", "medium", "low", "info"]
EventLevel = Literal["info", "success", "warn", "error"]

STAGE_ORDER: list[StageId] = ["detect", "recon", "inventory", "plan", "execute", "verify", "triage", "report", "retest"]
STAGE_META = {
    "detect": {"label": "Detect change", "agent": "ChangeWatcher"},
    "recon": {"label": "Learn app", "agent": "ReconAgent"},
    "inventory": {"label": "Build inventory", "agent": "InventoryAgent"},
    "plan": {"label": "Plan attacks", "agent": "PlannerAgent"},
    "execute": {"label": "Execute safely", "agent": "SpecialistExecutors"},
    "verify": {"label": "Verify", "agent": "VerifierAgent"},
    "triage": {"label": "Triage", "agent": "TriageAgent"},
    "report": {"label": "Report", "agent": "ReporterAgent"},
    "retest": {"label": "Retest", "agent": "RetestAgent"},
}


def now_id(prefix: str) -> str:
    import random, time
    return f"{prefix}_{int(time.time()*1000):x}{random.randint(0, 0xffff):04x}"


def redact(value: str) -> str:
    import re
    v = re.sub(r"([A-Z]{1,2}\d{6,8})", "[PASSPORT_REDACTED]", value)
    v = re.sub(r"\b(\d{4}[ -]?){3}\d{4}\b", "[CARD_REDACTED]", v)
    v = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b", "[EMAIL_REDACTED]", v)
    v = re.sub(r'"(token|authorization|api[_-]?key)"\s*:\s*"[^"]*"', r'"\\1":"[REDACTED]"', v, flags=re.I)
    return v


@dataclass
class StageState:
    id: StageId
    label: str
    agent: str
    status: StageStatus = "idle"
    detail: str = ""
    startedAt: int | None = None
    finishedAt: int | None = None
    count: int | None = None


@dataclass
class ChangeEvent:
    id: str
    kind: TriggerKind
    title: str
    detail: str
    source: str
    createdAt: int
    endpoints: list[str] = field(default_factory=list)
    status: Literal["queued", "testing", "tested"] = "queued"


@dataclass
class Endpoint:
    id: str
    method: str
    path: str
    host: str
    source: str
    status: InventoryStatus
    roles: list[Role]
    params: list[dict[str, Any]]
    authRequired: bool
    dataExposed: list[str]
    businessContext: list[str]
    flow: str
    lastRealTraffic: int | None
    hits30d: int
    hits90d: int
    windowHits: int | None
    vulnerableToVersion: str | None
    owner: str
    recommendation: Literal["decommission", "restrict", "update", "monitor"]
    discoveredAt: int


@dataclass
class PlannedTest:
    id: str
    endpointId: str
    endpoint: str
    method: str
    testClass: TestClass
    name: str
    reasoning: str
    params: list[str]
    roles: list[Role]
    risk: Literal["low", "medium", "high"]
    needsApproval: bool
    executor: str
    status: Literal["planned", "approved", "running", "done", "rejected", "skipped"] = "planned"


@dataclass
class ProofExchange:
    label: str
    request: dict[str, Any]
    response: dict[str, Any]


@dataclass
class Finding:
    id: str
    key: str
    title: str
    endpointId: str
    endpoint: str
    testClass: TestClass
    severity: Severity
    score: int
    scoreExplanation: str
    cwe: str
    owasp: str
    owner: str
    status: Literal["open", "approved", "still-vulnerable", "closed", "false-positive"]
    createdAt: int
    evidence: list[dict[str, Any]]
    impact: str
    fix: str
    requestsSent: int
    rootCause: str
    retest: dict[str, Any] | None = None
    ticketId: str | None = None


@dataclass
class ApprovalRequest:
    id: str
    kind: Literal["test", "finding"]
    refId: str
    title: str
    reason: str
    risk: Literal["medium", "high"]
    createdAt: int
    status: Literal["pending", "approved", "rejected", "modified"] = "pending"
    modifiedPlan: dict[str, Any] | None = None


@dataclass
class AuditRecord:
    id: str
    seq: int
    at: int
    runId: str
    method: str
    url: str
    host: str
    role: str
    agency: str
    status: int
    timingMs: int
    bytes: int
    blocked: bool
    blockReason: str | None
    testId: str | None
    findingId: str | None
    bodyHash: str
    prevHash: str
    hash: str
    replay: dict[str, Any]


@dataclass
class Ticket:
    id: str
    findingId: str
    title: str
    markdown: str
    createdAt: int
    destination: Literal["mock-jira", "mock-teams", "webhook"]
    sent: bool = False
    sentAt: int | None = None


@dataclass
class AgentEvent:
    id: str
    at: int
    runId: str
    stage: StageId | Literal["system"]
    level: EventLevel
    message: str
    data: dict[str, Any] = field(default_factory=dict)


def asdict_clean(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: asdict_clean(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [asdict_clean(v) for v in obj]
    if isinstance(obj, dict):
        return {k: asdict_clean(v) for k, v in obj.items()}
    return obj
