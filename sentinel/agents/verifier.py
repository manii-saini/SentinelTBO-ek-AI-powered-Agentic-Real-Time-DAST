from __future__ import annotations

import hashlib
import json
from typing import Any

from ..proofs import PROOFS
from .base import AgentContext


def finding_key(candidate: dict[str, Any]) -> str:
    t = candidate["test"]; m = candidate["result"]["meta"]
    return f"{t['endpoint']}|{t['testClass']}|{m.get('rootCause')}"


def deterministic_finding_id(key: str) -> str:
    return "fnd_" + hashlib.sha1(key.encode()).hexdigest()[:12]


def dropped_finding(dropped: dict[str, Any]) -> dict[str, Any]:
    c = dropped["candidate"]; key = finding_key(c)
    evidence = [c["result"]["evidence"][-1]] if c["result"].get("evidence") else []
    return {"id": deterministic_finding_id(key), "key": key, "title": c["test"]["name"], "endpointId": c["test"]["endpointId"], "endpoint": c["test"]["endpoint"], "testClass": c["test"]["testClass"], "severity": "info", "score": 0, "scoreExplanation": dropped["reason"], "cwe": "-", "owasp": "-", "owner": "VerifierAgent", "status": "false-positive", "createdAt": int(__import__("time").time()*1000), "evidence": evidence, "impact": "No reproducible business impact; not shown in confirmed findings.", "fix": "No action required.", "requestsSent": c["result"]["meta"].get("requests", 0), "rootCause": c["result"]["meta"].get("rootCause", "unknown")}


class VerifierAgent:
    id = "verify"
    name = "VerifierAgent"

    def run(self, candidates: list[dict[str, Any]], ctx: AgentContext) -> dict[str, Any]:
        ctx.emit("verify", "info", f"Re-running minimal proofs twice with control comparison for {len(candidates)} candidate(s)")
        verified, dropped = [], []
        for candidate in candidates:
            proof = PROOFS.get(candidate["proofKey"])
            if not proof:
                continue
            first = proof["run"](ctx)
            second = proof["run"](ctx)
            stable = bool(first.get("reproduced")) and bool(second.get("reproduced")) and first.get("meta", {}).get("rootCause") == second.get("meta", {}).get("rootCause")
            requests_sent = candidate["result"]["meta"].get("requests", 0) + first["meta"].get("requests", 0) + second["meta"].get("requests", 0)
            if stable:
                evidence = []
                for src in [candidate["result"].get("evidence", [None])[0], first.get("evidence", [None])[-1], second.get("evidence", [None])[-1]]:
                    if src:
                        e = json.loads(json.dumps(src))
                        e["response"]["body"] = str(e["response"].get("body", ""))[:900]
                        evidence.append(e)
                v = {**candidate, "evidence": evidence, "requestsSent": requests_sent}
                verified.append(v)
                ctx.emit("verify", "success", f"Verified: {candidate['test']['name']} (2/2 replays)", {"testId": candidate["test"]["id"], "requests": requests_sent})
            else:
                reason = f"Dropped: proof reproduced {int(bool(first.get('reproduced')))+int(bool(second.get('reproduced')))}/2 times; control or state comparison unstable"
                dropped.append({"candidate": candidate, "reason": reason})
                ctx.emit("verify", "warn", f"False positive dropped: {candidate['test']['name']}", {"reason": reason, "testId": candidate["test"]["id"]})

        # dedupe
        uniq = {}
        for v in verified:
            uniq[finding_key(v)] = v
        unique_verified = list(uniq.values())
        if len(unique_verified) != len(verified):
            ctx.emit("verify", "info", f"Deduplicated {len(verified)-len(unique_verified)} repeat hit(s)")
        return {"verified": unique_verified, "dropped": dropped}
