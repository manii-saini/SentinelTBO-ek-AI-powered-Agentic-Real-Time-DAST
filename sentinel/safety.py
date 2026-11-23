from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from .config import DEFAULT_SAFETY, TARGET_HOST
from .models import now_id, redact

DESTRUCTIVE_PATH = re.compile(r"/(pay|payment|charge|cancel|refund|book|booking|checkout|transfer)(/|\?|$)", re.I)
DESTRUCTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class SafetyResult:
    allowed: bool
    reason: str | None = None
    wait_ms: int = 0
    approval_id: str | None = None


class SafetyLayer:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = {**DEFAULT_SAFETY, **(config or {})}
        self._buckets: dict[str, dict[str, float]] = {}
        self._health: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self._last_hash = "0" * 32
        self._audit_sink: Callable[[dict[str, Any]], None] = lambda r: None
        self._health_sink: Callable[[dict[str, Any]], None] = lambda s: None
        self._approval_checker: Callable[[str], bool] = lambda _id: False

    def on_audit(self, fn): self._audit_sink = fn; return self
    def on_health(self, fn): self._health_sink = fn; return self
    def is_approved(self, fn): self._approval_checker = fn; return self
    def set_config(self, patch: dict[str, Any]): self.config.update(patch)

    def authorize(self, req: dict[str, Any]) -> SafetyResult:
        if self.config.get("killSwitch"):
            return SafetyResult(False, "KILL SWITCH ACTIVE — all outbound traffic stopped")
        try:
            u = urlparse(req["url"])
        except Exception:
            return SafetyResult(False, "Malformed URL")
        if u.scheme not in ("http", "https"):
            return SafetyResult(False, f"Protocol {u.scheme} not allowed")
        host = u.netloc.lower()
        allow = [h.lower() for h in self.config.get("allowlist", [TARGET_HOST])]
        if host not in allow:
            return SafetyResult(False, f"Out of scope: {host} is not in the scope allowlist")
        headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        if headers.get("x-sentinel-synthetic", "").lower() != "true":
            return SafetyResult(False, "Missing synthetic-traffic marker (x-sentinel-synthetic: true)")
        token = str(headers.get("authorization", "")).replace("Bearer ", "").strip()
        known = {c["token"] for c in self.config.get("testCredentials", {}).values()}
        if token and token not in known:
            return SafetyResult(False, "Credential is not an approved synthetic test account")
        method = str(req.get("method", "GET")).upper()
        if self.config.get("requireApprovalForDestructive", True) and method in DESTRUCTIVE_METHODS and DESTRUCTIVE_PATH.search(u.path):
            approval_id = headers.get("x-sentinel-approval")
            if not approval_id or not self._approval_checker(approval_id):
                return SafetyResult(False, f"Destructive test requires an approved request ({method} {u.path})", approval_id=approval_id)
        h = self._health.get(host)
        if h and time.time() * 1000 < h.get("pausedUntil", 0):
            return SafetyResult(False, f"Health monitor paused {host} after elevated error rate")
        wait_ms = self._take_token(host)
        return SafetyResult(True, wait_ms=wait_ms)

    def _take_token(self, host: str) -> int:
        now = time.time() * 1000
        bucket = self._buckets.get(host) or {"tokens": float(self.config.get("burst", 20)), "updated": now}
        refill = ((now - bucket["updated"]) / 1000) * float(self.config.get("rateLimit", 12))
        bucket["tokens"] = min(float(self.config.get("burst", 20)), bucket["tokens"] + refill)
        bucket["updated"] = now
        wait = 0
        if bucket["tokens"] < 1:
            wait = int(((1 - bucket["tokens"]) / float(self.config.get("rateLimit", 12))) * 1000)
        else:
            bucket["tokens"] -= 1
        self._buckets[host] = bucket
        return wait

    def record_response(self, req: dict[str, Any], status: int, timing_ms: int, bytes_count: int = 0, blocked: bool = False, block_reason: str | None = None) -> dict[str, Any]:
        host = urlparse(req.get("url", "")).netloc or "invalid"
        h = self._health.get(host) or {"samples": [], "errors": 0, "pausedUntil": 0}
        h["samples"].append(timing_ms)
        h["samples"] = h["samples"][-30:]
        # Blocked policy decisions should not degrade target health; transport failures/status 0 do.
        if (status >= 500 or status == 0) and not blocked:
            h["errors"] += 1
        error_rate = h["errors"] / max(1, len(h["samples"]))
        action = "normal"
        if error_rate >= float(self.config.get("healthPauseThreshold", 0.5)):
            h["pausedUntil"] = time.time() * 1000 + 4000
            action = "pause"
            h["errors"] = 0
        elif error_rate >= float(self.config.get("healthBackoffThreshold", 0.25)):
            action = "backoff"
        self._health[host] = h
        self._health_sink({"at": int(time.time() * 1000), "host": host, "latencyMs": timing_ms, "errorRate": error_rate, "action": action})

        self._seq += 1
        headers = {k: ("[REDACTED]" if re.search(r"authorization|token", k, re.I) else v) for k, v in (req.get("headers") or {}).items()}
        replay = {"method": req.get("method"), "url": req.get("url"), "headers": headers, "body": redact(req.get("body")) if req.get("body") else None}
        payload = json.dumps({"seq": self._seq, "at": int(time.time()*1000), "method": req.get("method"), "url": req.get("url"), "status": status, "role": req.get("role"), "timingMs": timing_ms, "blocked": blocked}, sort_keys=True)
        hsh = hashlib.sha256((self._last_hash + payload).encode()).hexdigest()[:32]
        record = {
            "id": now_id("aud"), "seq": self._seq, "at": int(time.time()*1000), "runId": req.get("runId", "manual"),
            "method": req.get("method"), "url": req.get("url"), "host": host, "role": req.get("role", "unknown"), "agency": req.get("agency", "-"),
            "status": status, "timingMs": timing_ms, "bytes": bytes_count, "blocked": blocked, "blockReason": block_reason,
            "testId": req.get("testId"), "findingId": req.get("findingId"),
            "bodyHash": hashlib.sha256((req.get("body") or "").encode()).hexdigest()[:16], "prevHash": self._last_hash, "hash": hsh, "replay": replay,
        }
        self._last_hash = hsh
        self._audit_sink(record)
        return record

    def get_health(self, host: str) -> dict[str, Any] | None:
        h = self._health.get(host)
        if not h:
            return None
        samples = h.get("samples") or [0]
        latency = sum(samples) / max(1, len(samples))
        err = h.get("errors", 0) / max(1, len(samples))
        action = "pause" if time.time() * 1000 < h.get("pausedUntil", 0) else "backoff" if latency > 450 or h.get("errors", 0) > 3 else "normal"
        return {"at": int(time.time()*1000), "host": host, "latencyMs": int(latency), "errorRate": err, "action": action}


class SafeHttpClient:
    def __init__(self, safety: SafetyLayer, transport: Callable[[dict[str, Any]], dict[str, Any]]):
        self.safety = safety
        self.transport = transport

    def send(self, req: dict[str, Any]) -> dict[str, Any]:
        auth = self.safety.authorize(req)
        if not auth.allowed:
            rec = self.safety.record_response(req, 0, 0, 0, True, auth.reason)
            return {"ok": False, "status": 0, "body": json.dumps({"blocked": True, "reason": auth.reason, "auditId": rec["id"]}), "timingMs": 0, "blocked": True, "blockReason": auth.reason}
        if auth.wait_ms:
            time.sleep(min(auth.wait_ms, 1500) / 1000)
        start = time.perf_counter()
        try:
            res = self.transport(req)
            timing = int((time.perf_counter() - start) * 1000)
            body = res.get("body", "")
            status = int(res.get("status", 200))
            self.safety.record_response(req, status, timing, len(body.encode("utf-8")), False)
            return {"ok": 200 <= status < 400, "status": status, "body": body, "timingMs": timing, "blocked": False, "approvalId": auth.approval_id}
        except Exception as e:
            timing = int((time.perf_counter() - start) * 1000)
            msg = str(e)
            self.safety.record_response(req, 0, timing, 0, True, msg)
            return {"ok": False, "status": 0, "body": json.dumps({"error": msg}), "timingMs": timing, "blocked": True, "blockReason": msg}
