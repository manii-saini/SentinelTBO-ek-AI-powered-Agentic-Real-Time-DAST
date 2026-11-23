from __future__ import annotations

import time
from typing import Any

from ..config import owner_for_path
from ..models import now_id
from ..severity import CWE_OWASP, score_severity
from .base import AgentContext
from .verifier import deterministic_finding_id, dropped_finding, finding_key


def create_approval(ctx: AgentContext, kind: str, ref_id: str, title: str, reason: str, risk: str) -> dict[str, Any]:
    approval = {"id": now_id("apr"), "kind": kind, "refId": ref_id, "title": title, "reason": reason, "risk": risk, "createdAt": int(time.time()*1000), "status": "pending", "modifiedPlan": None}
    ctx.store.add_approval(approval)
    ctx.emit("system", "warn", f"Approval required: {approval['title']}", {"approvalId": approval["id"], "risk": approval["risk"]})
    if ctx.auto_approve:
        ctx.store.update_approval(approval["id"], "approved")
        approval["status"] = "approved"
        ctx.emit("system", "info", f"Demo policy auto-approved {approval['id']} (synthetic staging target, reversible test)", {"approvalId": approval["id"]})
    return approval


class TriageAgent:
    id = "triage"
    name = "TriageAgent"

    def run(self, verified: list[dict[str, Any]], dropped: list[dict[str, Any]], ctx: AgentContext) -> list[dict[str, Any]]:
        ctx.emit("triage", "info", "Deduplicating by endpoint + class + root cause and applying business-impact rubric")
        for d in dropped:
            ctx.store.upsert_finding(dropped_finding(d))

        findings = []
        for item in verified:
            meta = item["result"]["meta"]
            scoring = score_severity({"testClass": item["test"]["testClass"], "businessContext": meta.get("businessContext", []), "crossAgency": meta.get("crossAgency"), "authBypass": meta.get("authBypass"), "unauthenticated": meta.get("unauthenticated"), "destructive": meta.get("destructive"), "dataExposed": meta.get("dataExposed"), "reproducible": True})
            tags = CWE_OWASP[item["test"]["testClass"]]
            owner = owner_for_path(item["test"]["endpoint"])
            key = finding_key(item)
            finding = {
                "id": deterministic_finding_id(key), "key": key, "title": item["test"]["name"], "endpointId": item["test"]["endpointId"], "endpoint": item["test"]["endpoint"],
                "testClass": item["test"]["testClass"], "severity": scoring["severity"], "score": scoring["score"], "scoreExplanation": scoring["explanation"],
                "cwe": tags["cwe"], "owasp": tags["owasp"], "owner": owner.get("owner", "Unassigned"), "status": "open", "createdAt": int(time.time()*1000),
                "evidence": item.get("evidence", []), "impact": meta.get("impact", ""), "fix": meta.get("fix", ""), "requestsSent": item.get("requestsSent", 0), "rootCause": meta.get("rootCause", ""),
            }
            ctx.store.upsert_finding(finding)
            findings.append(finding)
            if finding["severity"] in ("critical", "high"):
                a = create_approval(ctx, "finding", finding["id"], f"Publish {finding['severity']} finding: {finding['title']}", f"Business-impact score {finding['score']}/100 for {finding['endpoint']}. Owner {finding['owner']}.", "high")
                if a["status"] == "approved":
                    ctx.store.update_approval(a["id"], "approved")
            ctx.emit("triage", "success", f"{finding['severity'].upper()} {finding['title']} → {finding['owner']} ({finding['score']}/100)", {"findingId": finding["id"], "cwe": finding["cwe"], "owasp": finding["owasp"]})
        ctx.emit("triage", "info", f"Triage complete: {len(findings)} verified finding(s), {len(dropped)} false positive(s) dropped")
        return findings
