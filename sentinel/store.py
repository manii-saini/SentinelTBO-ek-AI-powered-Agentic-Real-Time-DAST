from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .config import DB_PATH


def _j(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False)


def _p(v: str | None, default: Any) -> Any:
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self):
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, started_at INTEGER, finished_at INTEGER, mode TEXT, change_id TEXT, stages TEXT);
        CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, at INTEGER, run_id TEXT, stage TEXT, level TEXT, message TEXT, data TEXT);
        CREATE INDEX IF NOT EXISTS idx_events_at ON events(at DESC);
        CREATE TABLE IF NOT EXISTS changes (id TEXT PRIMARY KEY, at INTEGER, kind TEXT, title TEXT, detail TEXT, source TEXT, endpoints TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS endpoints (id TEXT PRIMARY KEY, method TEXT, path TEXT, host TEXT, source TEXT, status TEXT, roles TEXT, params TEXT, auth_required INTEGER, data_exposed TEXT, business_context TEXT, flow TEXT, last_real_traffic INTEGER, hits30d INTEGER, hits90d INTEGER, vulnerable_to_version TEXT, owner TEXT, recommendation TEXT, discovered_at INTEGER);
        CREATE TABLE IF NOT EXISTS graph_nodes (id TEXT PRIMARY KEY, kind TEXT, label TEXT, data TEXT);
        CREATE TABLE IF NOT EXISTS graph_edges (id TEXT PRIMARY KEY, source TEXT, target TEXT, label TEXT);
        CREATE TABLE IF NOT EXISTS planned_tests (id TEXT PRIMARY KEY, endpoint_id TEXT, method TEXT, path TEXT, test_class TEXT, name TEXT, reasoning TEXT, params TEXT, roles TEXT, risk TEXT, needs_approval INTEGER, executor TEXT, status TEXT, run_id TEXT);
        CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, id TEXT, at INTEGER, run_id TEXT, method TEXT, url TEXT, host TEXT, role TEXT, agency TEXT, status INTEGER, timing_ms INTEGER, bytes INTEGER, blocked INTEGER, block_reason TEXT, test_id TEXT, finding_id TEXT, body_hash TEXT, prev_hash TEXT, hash TEXT, replay TEXT);
        CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at DESC);
        CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, key TEXT, title TEXT, endpoint_id TEXT, endpoint TEXT, test_class TEXT, severity TEXT, score INTEGER, score_explanation TEXT, cwe TEXT, owasp TEXT, owner TEXT, status TEXT, created_at INTEGER, evidence TEXT, impact TEXT, fix TEXT, requests_sent INTEGER, root_cause TEXT, retest TEXT, ticket_id TEXT);
        CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, kind TEXT, ref_id TEXT, title TEXT, reason TEXT, risk TEXT, created_at INTEGER, status TEXT, modified_plan TEXT);
        CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, finding_id TEXT, title TEXT, markdown TEXT, created_at INTEGER, destination TEXT, sent INTEGER, sent_at INTEGER);
        CREATE TABLE IF NOT EXISTS health (at INTEGER, host TEXT, latency_ms INTEGER, error_rate REAL, action TEXT);
        """)
        self.db.commit()

    def set_setting(self, key: str, value: Any):
        self.db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, _j(value)))
        self.db.commit()

    def get_setting(self, key: str, default: Any = None):
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return _p(row["value"], default) if row else default

    def create_run(self, run: dict[str, Any]):
        self.db.execute("INSERT OR REPLACE INTO runs(run_id,started_at,finished_at,mode,change_id,stages) VALUES(?,?,?,?,?,?)",
                        (run["runId"], run["startedAt"], run.get("finishedAt"), run["mode"], run.get("changeId"), _j(run.get("stages", []))))
        self.db.commit()

    def finish_run(self, run_id: str, stages: list[dict[str, Any]]):
        import time
        self.db.execute("UPDATE runs SET finished_at=?, stages=? WHERE run_id=?", (int(time.time()*1000), _j(stages), run_id))
        self.db.commit()

    def list_runs(self, limit=20):
        rows = self.db.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [{"runId": r["run_id"], "startedAt": r["started_at"], "finishedAt": r["finished_at"], "mode": r["mode"], "changeId": r["change_id"], "stages": _p(r["stages"], [])} for r in rows]

    def add_event(self, event: dict[str, Any]):
        self.db.execute("INSERT OR REPLACE INTO events VALUES(?,?,?,?,?,?,?)", (event["id"], event["at"], event["runId"], event["stage"], event["level"], event["message"], _j(event.get("data", {}))))
        self.db.commit()

    def list_events(self, limit=200):
        rows = self.db.execute("SELECT * FROM events ORDER BY at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r["id"], "at": r["at"], "runId": r["run_id"], "stage": r["stage"], "level": r["level"], "message": r["message"], "data": _p(r["data"], {})} for r in rows]

    def add_change(self, c: dict[str, Any]):
        self.db.execute("INSERT OR REPLACE INTO changes VALUES(?,?,?,?,?,?,?,?)", (c["id"], c["createdAt"], c["kind"], c["title"], c["detail"], c["source"], _j(c.get("endpoints", [])), c.get("status", "queued")))
        self.db.commit()

    def list_changes(self):
        rows = self.db.execute("SELECT * FROM changes ORDER BY at DESC LIMIT 100").fetchall()
        return [{"id": r["id"], "kind": r["kind"], "title": r["title"], "detail": r["detail"], "source": r["source"], "createdAt": r["at"], "endpoints": _p(r["endpoints"], []), "status": r["status"]} for r in rows]

    def update_change_status(self, id_: str, status: str):
        self.db.execute("UPDATE changes SET status=? WHERE id=?", (status, id_)); self.db.commit()

    def upsert_endpoint(self, e: dict[str, Any]):
        self.db.execute("""INSERT INTO endpoints VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET method=excluded.method,path=excluded.path,status=excluded.status,roles=excluded.roles,params=excluded.params,auth_required=excluded.auth_required,data_exposed=excluded.data_exposed,business_context=excluded.business_context,flow=excluded.flow,last_real_traffic=excluded.last_real_traffic,hits30d=excluded.hits30d,hits90d=excluded.hits90d,vulnerable_to_version=excluded.vulnerable_to_version,owner=excluded.owner,recommendation=excluded.recommendation""",
            (e["id"], e["method"], e["path"], e.get("host"), e.get("source"), e.get("status"), _j(e.get("roles", [])), _j(e.get("params", [])), 1 if e.get("authRequired") else 0, _j(e.get("dataExposed", [])), _j(e.get("businessContext", [])), e.get("flow"), e.get("lastRealTraffic"), e.get("hits30d", 0), e.get("hits90d", 0), e.get("vulnerableToVersion"), e.get("owner"), e.get("recommendation"), e.get("discoveredAt")))
        self.db.commit()

    def list_endpoints(self, window: int = 30):
        rows = self.db.execute("SELECT * FROM endpoints ORDER BY path").fetchall()
        out = []
        for r in rows:
            e = {"id": r["id"], "method": r["method"], "path": r["path"], "host": r["host"], "source": r["source"], "status": r["status"], "roles": _p(r["roles"], []), "params": _p(r["params"], []), "authRequired": bool(r["auth_required"]), "dataExposed": _p(r["data_exposed"], []), "businessContext": _p(r["business_context"], []), "flow": r["flow"], "lastRealTraffic": r["last_real_traffic"], "hits30d": r["hits30d"], "hits90d": r["hits90d"], "windowHits": r["hits30d"] if window == 30 else r["hits90d"], "vulnerableToVersion": r["vulnerable_to_version"], "owner": r["owner"], "recommendation": r["recommendation"], "discoveredAt": r["discovered_at"]}
            out.append(e)
        return out

    def set_graph(self, nodes, edges):
        self.db.execute("DELETE FROM graph_nodes"); self.db.execute("DELETE FROM graph_edges")
        for n in nodes:
            self.db.execute("INSERT INTO graph_nodes VALUES(?,?,?,?)", (n["id"], n["kind"], n["label"], _j(n.get("data", {}))))
        for e in edges:
            self.db.execute("INSERT INTO graph_edges VALUES(?,?,?,?)", (e["id"], e["source"], e["target"], e.get("label", "")))
        self.db.commit()

    def get_graph(self):
        nodes = [dict(id=r["id"], kind=r["kind"], label=r["label"], data=_p(r["data"], {})) for r in self.db.execute("SELECT * FROM graph_nodes").fetchall()]
        edges = [dict(id=r["id"], source=r["source"], target=r["target"], label=r["label"]) for r in self.db.execute("SELECT * FROM graph_edges").fetchall()]
        return {"nodes": nodes, "edges": edges}

    def add_planned_test(self, t: dict[str, Any], run_id: str | None = None):
        self.db.execute("INSERT OR REPLACE INTO planned_tests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (t["id"], t["endpointId"], t["method"], t["endpoint"], t["testClass"], t["name"], t["reasoning"], _j(t.get("params", [])), _j(t.get("roles", [])), t["risk"], 1 if t.get("needsApproval") else 0, t["executor"], t.get("status", "planned"), run_id))
        self.db.commit()

    def list_planned_tests(self):
        rows = self.db.execute("SELECT * FROM planned_tests ORDER BY test_class, name").fetchall()
        return [dict(id=r["id"], endpointId=r["endpoint_id"], endpoint=r["path"], method=r["method"], testClass=r["test_class"], name=r["name"], reasoning=r["reasoning"], params=_p(r["params"], []), roles=_p(r["roles"], []), risk=r["risk"], needsApproval=bool(r["needs_approval"]), executor=r["executor"], status=r["status"]) for r in rows]

    def update_planned_test(self, id_: str, status: str):
        self.db.execute("UPDATE planned_tests SET status=? WHERE id=?", (status, id_)); self.db.commit()

    def append_audit(self, r: dict[str, Any]):
        self.db.execute("INSERT INTO audit(id,seq,at,run_id,method,url,host,role,agency,status,timing_ms,bytes,blocked,block_reason,test_id,finding_id,body_hash,prev_hash,hash,replay) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (r["id"], r["seq"], r["at"], r["runId"], r["method"], r["url"], r["host"], r["role"], r["agency"], r["status"], r["timingMs"], r["bytes"], 1 if r["blocked"] else 0, r.get("blockReason"), r.get("testId"), r.get("findingId"), r["bodyHash"], r["prevHash"], r["hash"], _j(r.get("replay", {}))))
        self.db.commit()

    def list_audit(self, search: str | None = None, blocked_only: bool = False, limit: int = 300):
        clauses, args = [], []
        if blocked_only: clauses.append("blocked=1")
        if search:
            clauses.append("(url LIKE ? OR method LIKE ? OR role LIKE ?)"); q=f"%{search}%"; args += [q,q,q]
        args.append(limit)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.execute(f"SELECT * FROM audit {where} ORDER BY seq DESC LIMIT ?", args).fetchall()
        return [dict(id=r["id"], seq=r["seq"], at=r["at"], runId=r["run_id"], method=r["method"], url=r["url"], host=r["host"], role=r["role"], agency=r["agency"], status=r["status"], timingMs=r["timing_ms"], bytes=r["bytes"], blocked=bool(r["blocked"]), blockReason=r["block_reason"], testId=r["test_id"], findingId=r["finding_id"], bodyHash=r["body_hash"], prevHash=r["prev_hash"], hash=r["hash"], replay=_p(r["replay"], {})) for r in rows]

    def add_health(self, s: dict[str, Any]):
        self.db.execute("INSERT INTO health VALUES(?,?,?,?,?)", (s["at"], s["host"], s["latencyMs"], s["errorRate"], s["action"])); self.db.commit()

    def list_health(self, limit=60):
        rows = self.db.execute("SELECT * FROM health ORDER BY at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(at=r["at"], host=r["host"], latencyMs=r["latency_ms"], errorRate=r["error_rate"], action=r["action"]) for r in reversed(rows)]

    def upsert_finding(self, f: dict[str, Any]):
        self.db.execute("""INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET severity=excluded.severity,score=excluded.score,score_explanation=excluded.score_explanation,status=excluded.status,evidence=excluded.evidence,retest=excluded.retest,ticket_id=excluded.ticket_id,impact=excluded.impact,fix=excluded.fix""",
            (f["id"], f["key"], f["title"], f["endpointId"], f["endpoint"], f["testClass"], f["severity"], f["score"], f["scoreExplanation"], f["cwe"], f["owasp"], f["owner"], f["status"], f["createdAt"], _j(f.get("evidence", [])), f["impact"], f["fix"], f.get("requestsSent", 0), f["rootCause"], _j(f.get("retest")) if f.get("retest") else None, f.get("ticketId")))
        self.db.commit()

    def list_findings(self):
        rows = self.db.execute("SELECT * FROM findings ORDER BY score DESC, created_at DESC").fetchall()
        return [dict(id=r["id"], key=r["key"], title=r["title"], endpointId=r["endpoint_id"], endpoint=r["endpoint"], testClass=r["test_class"], severity=r["severity"], score=r["score"], scoreExplanation=r["score_explanation"], cwe=r["cwe"], owasp=r["owasp"], owner=r["owner"], status=r["status"], createdAt=r["created_at"], evidence=_p(r["evidence"], []), impact=r["impact"], fix=r["fix"], requestsSent=r["requests_sent"], rootCause=r["root_cause"], retest=_p(r["retest"], None), ticketId=r["ticket_id"]) for r in rows]

    def get_finding(self, id_: str):
        for f in self.list_findings():
            if f["id"] == id_: return f
        return None

    def add_approval(self, a: dict[str, Any]):
        self.db.execute("INSERT OR REPLACE INTO approvals VALUES(?,?,?,?,?,?,?,?,?)", (a["id"], a["kind"], a["refId"], a["title"], a["reason"], a["risk"], a["createdAt"], a["status"], _j(a.get("modifiedPlan"))))
        self.db.commit()

    def list_approvals(self):
        rows = self.db.execute("SELECT * FROM approvals ORDER BY created_at DESC").fetchall()
        return [dict(id=r["id"], kind=r["kind"], refId=r["ref_id"], title=r["title"], reason=r["reason"], risk=r["risk"], createdAt=r["created_at"], status=r["status"], modifiedPlan=_p(r["modified_plan"], None)) for r in rows]

    def update_approval(self, id_: str, status: str, modified_plan=None):
        self.db.execute("UPDATE approvals SET status=?, modified_plan=? WHERE id=?", (status, _j(modified_plan), id_)); self.db.commit()

    def get_approval_status(self, id_: str):
        r = self.db.execute("SELECT status FROM approvals WHERE id=?", (id_,)).fetchone()
        return r["status"] if r else None

    def add_ticket(self, t: dict[str, Any]):
        self.db.execute("INSERT OR REPLACE INTO tickets VALUES(?,?,?,?,?,?,?,?)", (t["id"], t["findingId"], t["title"], t["markdown"], t["createdAt"], t["destination"], 1 if t.get("sent") else 0, t.get("sentAt")))
        self.db.commit()

    def list_tickets(self):
        rows = self.db.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
        return [dict(id=r["id"], findingId=r["finding_id"], title=r["title"], markdown=r["markdown"], createdAt=r["created_at"], destination=r["destination"], sent=bool(r["sent"]), sentAt=r["sent_at"]) for r in rows]

    def update_ticket(self, id_: str, destination: str):
        import time
        self.db.execute("UPDATE tickets SET destination=?, sent=1, sent_at=? WHERE id=?", (destination, int(time.time()*1000), id_)); self.db.commit()

    def counters(self):
        def s(q): return self.db.execute(q).fetchone()[0]
        return {
            "endpoints": s("SELECT COUNT(*) FROM endpoints"),
            "findings": s("SELECT COUNT(*) FROM findings WHERE status NOT IN ('false-positive','closed')"),
            "confirmed": s("SELECT COUNT(*) FROM findings WHERE status IN ('open','approved','still-vulnerable')"),
            "falsePositivesDropped": s("SELECT COUNT(*) FROM findings WHERE status='false-positive'"),
            "requestsSent": s("SELECT COUNT(*) FROM audit WHERE blocked=0"),
            "blocked": s("SELECT COUNT(*) FROM audit WHERE blocked=1"),
        }

    def reset_run_data(self):
        self.db.executescript("""
        DELETE FROM findings; DELETE FROM approvals; DELETE FROM tickets; DELETE FROM changes;
        DELETE FROM audit; DELETE FROM health; DELETE FROM events; DELETE FROM runs; DELETE FROM planned_tests;
        DELETE FROM endpoints; DELETE FROM graph_nodes; DELETE FROM graph_edges;
        DELETE FROM settings WHERE key IN ('deployToVerifiedMs','lastRunId','deployAt');
        """)
        self.db.commit()

    def close(self):
        self.db.close()
