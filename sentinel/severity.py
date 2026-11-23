from __future__ import annotations

from typing import Any

BUSINESS_CONTEXT_WEIGHT = {"bookings": 8, "payments": 10, "credit": 12, "pii": 10, "supplier-access": 8, "coupons": 4, "invoices": 4}
TEST_CLASS_LABEL = {
    "access-control": "Access control",
    "business-logic": "Business logic",
    "auth-session": "Auth / session",
    "injection": "Injection",
    "api-hygiene": "API hygiene",
    "data-exposure": "Data exposure",
    "ssrf-open-redirect": "SSRF / open redirect",
}
CWE_OWASP = {
    "access-control": {"cwe": "CWE-639: Insecure Direct Object Reference", "owasp": "API1:2023 BOLA / API5:2023 BFLA"},
    "business-logic": {"cwe": "CWE-840: Business Logic Errors", "owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows"},
    "auth-session": {"cwe": "CWE-287: Improper Authentication", "owasp": "API2:2023 Broken Authentication"},
    "injection": {"cwe": "CWE-89: Injection", "owasp": "API8:2023 Security Misconfiguration"},
    "api-hygiene": {"cwe": "CWE-915: Improperly Controlled Modification of Object Properties", "owasp": "API3:2023 Broken Object Property Level Authorization"},
    "data-exposure": {"cwe": "CWE-200: Exposure of Sensitive Information", "owasp": "API3:2023 Broken Object Property Level Authorization"},
    "ssrf-open-redirect": {"cwe": "CWE-918: Server-Side Request Forgery", "owasp": "API7:2023 Server Side Request Forgery"},
}


def score_severity(inp: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    score = 18
    for ctx in inp.get("businessContext", []):
        w = BUSINESS_CONTEXT_WEIGHT.get(ctx, 1)
        score += w
        reasons.append(f"{ctx} +{w}")

    def add(cond: bool, pts: int, label: str) -> None:
        nonlocal score
        if cond:
            score += pts
            reasons.append(f"{label} +{pts}")

    add(bool(inp.get("crossAgency")), 22, "cross-agency boundary crossed")
    add(bool(inp.get("authBypass")), 20, "authorization bypass")
    add(bool(inp.get("unauthenticated")), 18, "no authentication required")
    add(bool(inp.get("destructive")), 12, "financial state mutation")
    add(bool(inp.get("bulkExtraction")), 8, "bulk data exposure")
    add(inp.get("testClass") == "ssrf-open-redirect", 15, "server-side request forgery primitive")
    add(inp.get("testClass") == "data-exposure", 8, "direct sensitive-data disclosure")
    if inp.get("reproducible") is False:
        score -= 25
        reasons.append("not reproducible -25")
    else:
        score += 5
        reasons.append("verified twice +5")
    data_exposed = inp.get("dataExposed") or []
    if any(any(k in str(d).lower() for k in ["passport", "pnr", "card", "email"]) for d in data_exposed):
        score += 8
        reasons.append("sensitive PNR/PII fields +8")
    score = max(0, min(100, score))
    severity = "critical" if score >= 80 else "high" if score >= 62 else "medium" if score >= 42 else "low" if score >= 22 else "info"
    return {"score": score, "severity": severity, "explanation": f"Business impact rubric: {', '.join(reasons) or 'baseline'} = {score}/100 ({severity})."}
