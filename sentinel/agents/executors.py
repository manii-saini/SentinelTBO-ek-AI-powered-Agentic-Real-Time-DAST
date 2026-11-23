from __future__ import annotations

from typing import Any

from ..proofs import PROOFS
from .base import AgentContext

EXECUTORS = [
    ("AccessControl", ["access-control"]),
    ("BusinessLogic", ["business-logic"]),
    ("Auth", ["auth-session"]),
    ("Injection", ["injection"]),
    ("Hygiene", ["api-hygiene"]),
    ("DataExposure", ["data-exposure"]),
    ("SSRF", ["ssrf-open-redirect"]),
]


def run_proofs(tests: list[dict[str, Any]], ctx: AgentContext, executor_id: str) -> list[dict[str, Any]]:
    candidates = []
    for test in tests:
        proof = PROOFS.get(test["executor"])
        if not proof:
            continue
        ctx.store.update_planned_test(test["id"], "running")
        result = proof["run"](ctx)
        ctx.store.update_planned_test(test["id"], "done")
        ctx.emit("execute", "warn" if result.get("reproduced") else "info", f"{executor_id}: {test['name']} → {'signal observed' if result.get('reproduced') else 'no signal'}", {"testId": test["id"], "proofKey": test["executor"], "requests": result.get("meta", {}).get("requests", 0), "endpoint": test["endpoint"]})
        if result.get("reproduced"):
            candidates.append({"test": test, "proofKey": test["executor"], "result": result})
    return candidates


def execute_all(tests: list[dict[str, Any]], ctx: AgentContext) -> list[dict[str, Any]]:
    all_candidates = []
    for name, classes in EXECUTORS:
        mine = [t for t in tests if t["testClass"] in classes]
        if not mine:
            continue
        ctx.emit("execute", "info", f"{name} executing {len(mine)} targeted test(s)", {"classes": classes})
        all_candidates.extend(run_proofs(mine, ctx, name))
    return all_candidates
