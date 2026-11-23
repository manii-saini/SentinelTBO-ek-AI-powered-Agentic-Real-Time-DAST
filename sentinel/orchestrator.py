from __future__ import annotations

import json
import time
from typing import Any

from .agents.base import AgentContext
from .agents.executors import execute_all
from .agents.inventory import InventoryAgent
from .agents.planner import PlannerAgent
from .agents.recon import ReconAgent
from .agents.reporter import ReporterAgent, send_ticket
from .agents.retest import RetestAgent
from .agents.triage import TriageAgent, create_approval
from .agents.verifier import VerifierAgent
from .config import DEFAULT_SAFETY, DISCOVERY_TECHNIQUES, TARGET_BASE_URL, TRIGGER_ENDPOINTS
from .llm import LLM
from .mock_platform import SyntheticTravelPlatform
from .models import STAGE_META, STAGE_ORDER, now_id
from .openapi import generate_openapi
from .safety import SafeHttpClient, SafetyLayer
from .store import Store


def initial_stages():
    return [{"id": s, **STAGE_META[s], "status": "idle", "detail": ""} for s in STAGE_ORDER]


class Orchestrator:
    def __init__(self, store: Store | None = None, platform: SyntheticTravelPlatform | None = None):
        self.store = store or Store()
        self.platform = platform or SyntheticTravelPlatform()
        self.safety = SafetyLayer(self.store.get_setting("safetyConfig", DEFAULT_SAFETY))
        self.http = SafeHttpClient(self.safety, self.platform.handle)
        self.llm = LLM()
        self.target = TARGET_BASE_URL
        self.listeners = []
        self.stages = initial_stages()
        self.approval_map: dict[str, str] = {}
        self.current_run_id = "idle"
        self.deploy_at = self.store.get_setting("deployAt", None)
        self.running = False
        self.safety.on_audit(lambda r: self.store.append_audit(r))
        self.safety.on_health(lambda h: self.store.add_health(h))
        self.safety.is_approved(lambda aid: self.store.get_approval_status(aid) == "approved")

    def on_event(self, fn):
        self.listeners.append(fn)
        return lambda: self.listeners.remove(fn)

    def emit(self, stage: str, level: str, message: str, data: dict | None = None):
        event = {"id": now_id("evt"), "at": int(time.time()*1000), "runId": self.current_run_id, "stage": stage, "level": level, "message": message, "data": data or {}}
        self.store.add_event(event)
        for fn in list(self.listeners):
            try: fn(event)
            except Exception: pass
        return event

    def _ctx(self, mode: str, auto_approve: bool) -> AgentContext:
        return AgentContext(
            store=self.store, safety=self.safety, http=self.http, llm=self.llm, target=self.target, run_id=self.current_run_id,
            mode=mode, auto_approve=auto_approve,
            approval_for=lambda key: (aid := self.approval_map.get(key)) and self.store.get_approval_status(aid) == "approved" and aid or None,
            emit=lambda stage, level, message, data=None: self.emit(stage, level, message, data),
            platform=self.platform,
        )

    def _stage(self, sid: str, status: str, detail: str, count: int | None = None):
        for s in self.stages:
            if s["id"] == sid:
                s["status"] = status; s["detail"] = detail; s["count"] = count
                if status == "running": s["startedAt"] = int(time.time()*1000)
                if status in ("done", "error"): s["finishedAt"] = int(time.time()*1000)
                self.emit(sid, "error" if status == "error" else "success" if status == "done" else "info", f"{STAGE_META[sid]['label']}: {detail}")
                break

    def fire_trigger(self, kind: str, source: str = "operator-console") -> dict[str, Any]:
        meta = TRIGGER_ENDPOINTS[kind]
        change = {"id": now_id("chg"), "kind": kind, "title": meta["title"], "detail": meta["detail"], "source": source, "createdAt": int(time.time()*1000), "endpoints": meta["endpoints"], "status": "queued"}
        self.store.add_change(change)
        self.emit("detect", "success", f"Change detected: {change['title']}", {"changeId": change["id"], "endpoints": change["endpoints"]})
        return change

    def deploy_v21(self):
        res = self.http.send({"method":"POST","url":f"{self.target}/__admin/deploy","headers":{"x-sentinel-synthetic":"true"},"body":"{}","runId":self.current_run_id})
        self.emit("detect", "error" if res.get("blocked") else "warn", f"Deploy command blocked: {res.get('blockReason')}" if res.get("blocked") else "Deploy v2.1 shipped to staging mock", {"status": res.get("status")})
        self.deploy_at = int(time.time()*1000)
        self.store.set_setting("deployAt", self.deploy_at)
        return self.fire_trigger("deploy", "ci-cd-pipeline:v2.1")

    def run_loop(self, mode="full", auto_approve=False, change=None, focus_paths=None):
        if self.running:
            raise RuntimeError("A security run is already in progress")
        self.running = True
        self.current_run_id = now_id("run")
        self.approval_map.clear()
        self.stages = initial_stages()
        run = {"runId": self.current_run_id, "startedAt": int(time.time()*1000), "mode": mode, "changeId": (change or {}).get("id"), "stages": self.stages}
        self.store.create_run(run)
        self.store.set_setting("lastRunId", self.current_run_id)
        ctx = self._ctx(mode, auto_approve)
        self.emit("system", "info", f"SentinelTBO run started ({mode} mode, target {self.target})", {"runId": self.current_run_id})
        try:
            if not change:
                change = self.fire_trigger("deploy", "operator-console")
            changes = [change] if change else [c for c in self.store.list_changes() if c["status"] != "tested"]
            for c in changes: self.store.update_change_status(c["id"], "testing")
            self._stage("detect", "done", f"{len(changes)} change event(s) queued", len(changes))

            self._stage("recon", "running", "discovering endpoints via bundle, HAR and probes")
            endpoints = ReconAgent().run(changes, focus_paths, ctx)
            self._stage("recon", "done", f"{len(endpoints)} endpoints discovered", len(endpoints))

            self._stage("inventory", "running", "classifying active / zombie / shadow")
            inventoried = InventoryAgent().run(endpoints, ctx)
            self._stage("inventory", "done", "knowledge graph + OpenAPI map updated", len(inventoried))

            self._stage("plan", "running", "selecting targeted tests")
            tests = PlannerAgent().run(inventoried, ctx)
            for t in tests:
                if t["needsApproval"]:
                    a = create_approval(ctx, "test", t["id"], t["name"], f"Touches payment/refund/booking mutation on staging with synthetic accounts. {t['reasoning']}", "high" if t["risk"] == "high" else "medium")
                    self.approval_map[t["executor"]] = a["id"]
            self._stage("plan", "done", f"{len(tests)} tests planned, {len(self.approval_map)} gated by approval", len(tests))

            self._stage("execute", "running", "safety-layer enforced specialist execution")
            candidates = execute_all(tests, ctx)
            blocked = len([a for a in self.store.list_audit(blocked_only=True, limit=1000) if a["runId"] == self.current_run_id])
            self._stage("execute", "done", f"{len(candidates)} signal(s) from {len(tests)} tests; {blocked} blocked request(s) logged", len(candidates))

            self._stage("verify", "running", "minimal proof replay 2× against control")
            verified = VerifierAgent().run(candidates, ctx)
            elapsed = int(time.time()*1000) - self.deploy_at if self.deploy_at else None
            if elapsed is not None:
                self.store.set_setting("deployToVerifiedMs", elapsed)
            self._stage("verify", "done", f"{len(verified['verified'])} verified, {len(verified['dropped'])} dropped", len(verified["verified"]))

            self._stage("triage", "running", "dedupe, severity scoring, owner mapping")
            findings = TriageAgent().run(verified["verified"], verified["dropped"], ctx)
            self._stage("triage", "done", f"{len(findings)} finding(s) scored and assigned", len(findings))

            self._stage("report", "running", "drafting Jira-style tickets")
            tickets = ReporterAgent().run(findings, ctx)
            self._stage("report", "done", f"{len(tickets)} ticket(s) drafted", len(tickets))

            for c in changes: self.store.update_change_status(c["id"], "tested")
            self._stage("retest", "done", "awaiting fix deployment to replay stored proof")
            run["finishedAt"] = int(time.time()*1000)
            self.store.finish_run(self.current_run_id, self.stages)
            self.emit("system", "success", f"Run complete: {len(findings)} finding(s), {len(verified['dropped'])} false positive(s) dropped in {max(1,int((run['finishedAt']-run['startedAt'])/1000))}s", {"runId": self.current_run_id})
            return run
        except Exception as e:
            self._stage("execute", "error", f"Run failed: {e}")
            run["finishedAt"] = int(time.time()*1000)
            self.store.finish_run(self.current_run_id, self.stages)
            self.emit("system", "error", f"Run failed: {e}")
            raise
        finally:
            self.running = False

    def run_demo(self):
        self.reset()
        change = self.deploy_v21()
        return self.run_loop(mode="demo", auto_approve=True, change=change)

    def reset(self):
        self.store.reset_run_data()
        self.platform.reset()
        self.stages = initial_stages()
        self.approval_map.clear()
        self.deploy_at = None
        self.emit("system", "info", "Workspace reset: mock platform and findings restored to baseline")

    def approve(self, approval_id: str, decision: str, modified_plan=None):
        approval = next((a for a in self.store.list_approvals() if a["id"] == approval_id), None)
        if not approval or decision not in ("approved", "rejected", "modified"):
            return None
        status = "modified" if decision == "modified" else decision
        self.store.update_approval(approval_id, status, modified_plan)
        self.emit("system", "success" if status == "approved" else "warn", f"Approval {approval_id}: {status}", {"id": approval_id, "status": status})
        approval["status"] = status
        return approval

    def retest(self, finding_id: str, deploy_fix_first=True):
        finding = self.store.get_finding(finding_id)
        if not finding: return None
        ctx = self._ctx("full", False)
        return RetestAgent().run(finding, ctx, deploy_fix_first=deploy_fix_first)

    def set_safety(self, patch: dict[str, Any]):
        self.safety.set_config(patch)
        self.store.set_setting("safetyConfig", self.safety.config)
        self.emit("system", "warn", f"Safety configuration updated: {', '.join(patch.keys())}", patch)

    def set_webhook(self, url: str):
        self.store.set_setting("webhookConfig", {"url": url})
        self.emit("system", "info", "Ticket webhook configuration saved (must still pass allowlist)", {"url": url})

    def send_ticket(self, ticket_id: str, destination: str):
        return send_ticket(self._ctx("full", False), ticket_id, destination)

    def get_state(self, window: int = 30):
        counters = self.store.counters()
        counters["deployToVerifiedMs"] = self.store.get_setting("deployToVerifiedMs", None)
        return {
            "target": self.target,
            "mode": "offline-deterministic" if self.llm.provider == "mock" else "llm-backed",
            "llm": {"provider": self.llm.provider, "model": self.llm.model},
            "running": self.running,
            "stages": self.stages,
            "counters": counters,
            "events": self.store.list_events(200),
            "changes": self.store.list_changes(),
            "endpoints": self.store.list_endpoints(window),
            "graph": self.store.get_graph(),
            "tests": self.store.list_planned_tests(),
            "findings": self.store.list_findings(),
            "approvals": self.store.list_approvals(),
            "tickets": self.store.list_tickets(),
            "audit": self.store.list_audit(limit=400),
            "health": self.store.list_health(80),
            "runs": self.store.list_runs(),
            "safety": self.safety.config,
            "healthNow": self.safety.get_health(self.target.replace("http://", "")),
            "techniques": DISCOVERY_TECHNIQUES,
            "webhookConfig": self.store.get_setting("webhookConfig", {}),
        }

    def export_openapi(self):
        return generate_openapi(self.store.list_endpoints(90))
