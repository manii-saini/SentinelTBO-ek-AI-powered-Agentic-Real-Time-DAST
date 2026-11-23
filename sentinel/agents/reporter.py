from __future__ import annotations

import json
import time
from typing import Any

from ..models import now_id
from .base import AgentContext


def ticket_markdown(finding: dict[str, Any]) -> str:
    ev = []
    for i, e in enumerate(finding.get("evidence", []), 1):
        body = e.get("request", {}).get("body")
        ev.append("\n".join(filter(None, [
            f"### {i}. {e.get('label','evidence')}",
            f"**Request:** `{e.get('request',{}).get('method')} {e.get('request',{}).get('url')}`",
            f"**Body:** `{body}`" if body else None,
            f"**Response:** {e.get('response',{}).get('status')} in {e.get('response',{}).get('timingMs')}ms",
            "```json",
            str(e.get("response",{}).get("body",""))[:900],
            "```",
        ])))
    return f"""# [SEC] {finding['title']}

**Severity:** {finding['severity'].upper()} ({finding['score']}/100)  
**Endpoint:** {finding['endpoint']}  
**Owner:** {finding['owner']}  
**Class:** {finding['testClass']}  
**Tags:** {finding['cwe']} · {finding['owasp']}  
**Finding ID:** {finding['id']} · **Dedupe key:** {finding['key']}

## Impact
{finding['impact']}

## Severity rationale
{finding['scoreExplanation']}

## Minimal proof (redacted, synthetic accounts only)
{chr(10).join(ev)}

## Suggested fix
{finding['fix']}

## Verification
Proof replayed 2× against a control request by VerifierAgent; {finding.get('requestsSent',0)} synthetic requests total. No production data or real accounts used.
"""


class ReporterAgent:
    id = "report"
    name = "ReporterAgent"

    def run(self, findings: list[dict[str, Any]], ctx: AgentContext) -> list[dict[str, Any]]:
        open_findings = [f for f in findings if f["status"] in ("open", "approved")]
        tickets = []
        for f in open_findings:
            t = {"id": now_id("SEC"), "findingId": f["id"], "title": f"[SEC][{f['severity'].upper()}] {f['title']}", "markdown": ticket_markdown(f), "createdAt": int(time.time()*1000), "destination": "mock-jira", "sent": False, "sentAt": None}
            ctx.store.add_ticket(t)
            f["ticketId"] = t["id"]
            ctx.store.upsert_finding(f)
            tickets.append(t)
            ctx.emit("report", "success", f"Ticket {t['id']} drafted for {f['owner']}", {"ticketId": t["id"], "findingId": f["id"]})
        ctx.emit("report", "info", f"{len(tickets)} ticket(s) generated (not sent automatically)")
        return tickets


def send_ticket(ctx: AgentContext, ticket_id: str, destination: str):
    tickets = ctx.store.list_tickets()
    ticket = next((t for t in tickets if t["id"] == ticket_id), None)
    if not ticket:
        return None
    if destination == "webhook":
        cfg = ctx.store.get_setting("webhookConfig", {})
        url = cfg.get("url")
        if url:
            res = ctx.http.send({"method":"POST","url":url,"headers":{"x-sentinel-synthetic":"true","content-type":"application/json"},"body":json.dumps({"ticket":ticket["id"],"title":ticket["title"],"markdown":ticket["markdown"]}),"runId":ctx.run_id})
            ctx.emit("report", "error" if res.get("blocked") else "success", f"Webhook delivery {'blocked by safety layer' if res.get('blocked') else 'accepted'}", {"reason": res.get("blockReason"), "status": res.get("status")})
    ctx.store.update_ticket(ticket_id, destination)
    ctx.emit("report", "success", f"{ticket_id} delivered via {destination} adapter", {"destination": destination})
    return next((t for t in ctx.store.list_tickets() if t["id"] == ticket_id), None)
