from __future__ import annotations

from typing import Any

from ..models import now_id
from .base import AgentContext

RULES = [
    {"path": "/api/bookings/:id", "proofKey": "bola", "testClass": "access-control", "name": "Swap booking ID across agency A → B", "risk": "high", "approval": False, "roles": ["agent"], "params": ["id"]},
    {"path": "/v1/bookings", "proofKey": "cross-agency-enum", "testClass": "access-control", "name": "Cross-agency legacy enumeration", "risk": "medium", "approval": False, "roles": ["agent"], "params": []},
    {"path": "/v1/bookings", "proofKey": "unauth-legacy", "testClass": "auth-session", "name": "Unauthenticated legacy read", "risk": "medium", "approval": False, "roles": [], "params": []},
    {"path": "/api/book", "proofKey": "fare-tamper", "testClass": "business-logic", "name": "Client-controlled fare tampering", "risk": "high", "approval": True, "roles": ["agent"], "params": ["holdId", "fare"]},
    {"path": "/api/book", "proofKey": "mass-assignment", "testClass": "api-hygiene", "name": "Sub-agent → admin via mass assignment", "risk": "high", "approval": True, "roles": ["sub-agent"], "params": ["role"]},
    {"path": "/api/book", "proofKey": "negative-qty", "testClass": "business-logic", "name": "Negative quantity validation", "risk": "medium", "approval": True, "roles": ["agent"], "params": ["quantity"]},
    {"path": "/api/book", "proofKey": "skip-payment", "testClass": "business-logic", "name": "Skipped payment state transition", "risk": "high", "approval": True, "roles": ["agent"], "params": ["holdId"]},
    {"path": "/api/pay", "proofKey": "coupon-reuse", "testClass": "business-logic", "name": "Replay coupon twice", "risk": "high", "approval": True, "roles": ["agent"], "params": ["coupon"]},
    {"path": "/api/cancel", "proofKey": "double-refund", "testClass": "business-logic", "name": "Cancel → rebook double refund", "risk": "high", "approval": True, "roles": ["agent"], "params": ["holdId"]},
    {"path": "/internal/debug", "proofKey": "debug-exposure", "testClass": "data-exposure", "name": "Shadow route PII exposure", "risk": "high", "approval": False, "roles": [], "params": []},
    {"path": "/api/supplier/webhook", "proofKey": "ssrf-supplier", "testClass": "ssrf-open-redirect", "name": "Supplier webhook SSRF to internal route", "risk": "high", "approval": False, "roles": ["agent"], "params": ["url"]},
    {"path": "/api/v2/coupons/stack", "proofKey": "coupon-stack", "testClass": "business-logic", "name": "Unauthenticated coupon stacking", "risk": "high", "approval": False, "roles": [], "params": ["count"]},
    {"path": "/api/search", "proofKey": "injection-probe", "testClass": "injection", "name": "Benign SQLi marker probe", "risk": "low", "approval": False, "roles": ["agent"], "params": ["origin"]},
    {"path": "/api/invoices/:id", "proofKey": "excess-data", "testClass": "data-exposure", "name": "Excess data in invoice response", "risk": "low", "approval": False, "roles": ["agent"], "params": ["id"]},
]


class PlannerAgent:
    id = "plan"
    name = "PlannerAgent"

    def run(self, endpoints: list[dict[str, Any]], ctx: AgentContext) -> list[dict[str, Any]]:
        ctx.emit("plan", "info", "Selecting targeted tests from endpoint parameters, roles and business context")
        planned = []
        for rule in RULES:
            ep = next((e for e in endpoints if e["path"] == rule["path"]), None)
            if not ep:
                continue
            llm = ctx.llm.complete("You are a conservative DAST planner. Justify one targeted test, never broad spraying.", f"Endpoint: {ep['method']} {ep['path']}\nRoles: {','.join(ep.get('roles',[]))}\nBusiness context: {','.join(ep.get('businessContext',[]))}\nTest: {rule['name']}\nParams: {','.join(rule['params'])}")
            t = {"id": now_id("test"), "endpointId": ep["id"], "endpoint": ep["path"], "method": ep["method"], "testClass": rule["testClass"], "name": rule["name"], "reasoning": llm["text"], "params": rule["params"], "roles": rule["roles"], "risk": rule["risk"], "needsApproval": rule["approval"], "executor": rule["proofKey"], "status": "planned"}
            planned.append(t)
            ctx.store.add_planned_test(t, ctx.run_id)
        groups = sorted(set(t["testClass"] for t in planned))
        ctx.emit("plan", "success", f"Planned {len(planned)} targeted tests across {len(groups)} classes ({sum(1 for t in planned if t['needsApproval'])} require approval)", {"classes": groups, "approvals": sum(1 for t in planned if t['needsApproval']), "llm": ctx.llm.provider})
        return planned
