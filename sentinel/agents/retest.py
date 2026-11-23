from __future__ import annotations

import time
from typing import Any

from ..proofs import PROOFS
from .base import AgentContext

FIX_TO_PROOF = {
    "booking-idor": {"patch":"bola","proof":"bola"},
    "legacy-cross-tenant-list": {"patch":"zombie","proof":"cross-agency-enum"},
    "legacy-missing-auth": {"patch":"zombie","proof":"unauth-legacy"},
    "client-controlled-fare": {"patch":"fare-tamper","proof":"fare-tamper"},
    "mass-assignment-role": {"patch":"mass-assignment","proof":"mass-assignment"},
    "coupon-replay": {"patch":"coupon-reuse","proof":"coupon-reuse"},
    "cancel-rebook-double-refund": {"patch":"double-refund","proof":"double-refund"},
    "v21-coupon-stack": {"patch":"coupon-stack","proof":"coupon-stack"},
    "shadow-debug-pii": {"patch":"shadow","proof":"debug-exposure"},
    "supplier-webhook-ssrf": {"patch":"ssrf","proof":"ssrf-supplier"},
}


def deploy_fix(ctx: AgentContext, finding: dict[str, Any]) -> bool:
    mapping = FIX_TO_PROOF.get(finding.get("rootCause"))
    if not mapping:
        return False
    res = ctx.http.send({"method":"POST","url":f"{ctx.target}/__admin/patch","headers":{"x-sentinel-synthetic":"true","content-type":"application/json"},"body":__import__("json").dumps({"keys":[mapping["patch"]]}),"runId":ctx.run_id})
    ctx.emit("retest","error" if res.get("blocked") else "info", f"Fix deployed for {finding['title']} (patch: {mapping['patch']})", {"status":res.get("status"),"blocked":res.get("blocked")})
    return not res.get("blocked")


class RetestAgent:
    id = "retest"
    name = "RetestAgent"

    def run(self, finding: dict[str, Any], ctx: AgentContext, deploy_fix_first: bool = True) -> dict[str, Any]:
        mapping = FIX_TO_PROOF.get(finding.get("rootCause"))
        proof = PROOFS.get(mapping["proof"]) if mapping else None
        if not mapping or not proof:
            return finding
        if deploy_fix_first:
            deploy_fix(ctx, finding)
        before = finding.get("evidence", [])
        replay = proof["run"](ctx)
        retest = {"at": int(time.time()*1000), "result": "still-vulnerable" if replay.get("reproduced") else "closed", "before": before, "after": replay.get("evidence", [])}
        updated = {**finding, "status": "still-vulnerable" if replay.get("reproduced") else "closed", "retest": retest}
        ctx.store.upsert_finding(updated)
        ctx.emit("retest", "error" if replay.get("reproduced") else "success", f"{finding['title']}: {updated['status'].upper()}", {"findingId": finding["id"], "before": len(before), "after": len(replay.get("evidence", []))})
        return updated
