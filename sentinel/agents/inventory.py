from __future__ import annotations

import json
import time
from typing import Any

from ..config import DISCOVERY_TECHNIQUES, owner_for_path
from .base import AgentContext


def parse_traffic_logs(raw: str) -> list[dict[str, Any]]:
    raw = (raw or "").strip()
    if not raw:
        return []
    if raw.startswith("[") or raw.startswith("{"):
        obj = json.loads(raw)
        return obj if isinstance(obj, list) else obj.get("logs", [])
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return []
    header = [c.strip().lower() for c in lines[0].split(",")]
    out = []
    for line in lines[1:]:
        cells = line.split(",")
        def get(name): 
            i = header.index(name) if name in header else -1
            return cells[i] if i >= 0 and i < len(cells) else ""
        out.append({"path": get("path"), "method": get("method") or "GET", "at": int(get("at") or get("timestamp") or 0)})
    return [r for r in out if r.get("path")]


class InventoryAgent:
    id = "inventory"
    name = "InventoryAgent"

    def run(self, endpoints: list[dict[str, Any]], ctx: AgentContext) -> list[dict[str, Any]]:
        ctx.emit("inventory", "info", "Comparing inferred map with 30/90-day gateway traffic", {"techniques": [t["name"] for t in DISCOVERY_TECHNIQUES]})
        windows = {}
        for w in ("30", "90"):
            r = ctx.http.send({"method":"GET","url":f"{ctx.target}/__admin/traffic?window={w}","headers":{"x-sentinel-synthetic":"true"},"runId":ctx.run_id})
            try:
                windows[w] = parse_traffic_logs(r.get("body", "[]"))
            except Exception:
                windows[w] = []

        enriched = []
        for endpoint in endpoints:
            path = endpoint["path"]
            def count(rows):
                c = 0
                for r in rows:
                    rp = r.get("path", "")
                    if rp == path or (":id" in path and rp.startswith(path.split(":id")[0])):
                        c += 1
                return c
            hits30 = count(windows["30"]); hits90 = count(windows["90"])
            last_real = max([r.get("at", 0) for r in windows["90"] if r.get("path") == path] or [0]) or None
            undocumented = path.startswith("/internal") or path.startswith("/debug") or path.startswith("/test") or path.startswith("/beta")
            legacy = path.startswith("/v1") or path.startswith("/old") or path.startswith("/legacy")
            status = "shadow" if undocumented else "zombie" if hits90 == 0 else "active"
            owner = owner_for_path(path)
            has_known = path in ["/api/bookings/:id","/api/book","/api/pay","/api/cancel","/api/supplier/webhook","/internal/debug","/v1/bookings","/api/v2/coupons/stack"]
            recommendation = "decommission" if status == "zombie" else "restrict" if status == "shadow" else "update" if has_known else "monitor"
            e = {**endpoint, "hits30d": hits30, "hits90d": hits90, "windowHits": hits30, "lastRealTraffic": last_real, "status": status, "owner": owner.get("owner","Unassigned"), "vulnerableToVersion": "v2.1 (new)" if path == "/api/v2/coupons/stack" else "v2.0 (known issues)" if has_known else None, "recommendation": recommendation}
            enriched.append(e)
            ctx.store.upsert_endpoint(e)

        # graph
        nodes, edges = [], []
        flows = ["search","hold","book","pay","cancel"]
        for f in flows:
            nodes.append({"id": f"flow:{f}", "kind":"flow", "label":f, "data":{"type":"business-flow"}})
        for i,f in enumerate(flows[:-1]):
            edges.append({"id":f"edge:flow:{f}:{flows[i+1]}", "source":f"flow:{f}", "target":f"flow:{flows[i+1]}", "label":"next"})
        for e in enriched:
            nodes.append({"id": e["id"], "kind":"endpoint", "label":f"{e['method']} {e['path']}", "data":{"status":e["status"],"owner":e["owner"],"hits30d":e["hits30d"],"hits90d":e["hits90d"],"source":e["source"]}})
            if e["flow"] in flows:
                edges.append({"id":f"edge:{e['id']}:flow:{e['flow']}", "source":e["id"], "target":f"flow:{e['flow']}", "label":"part of"})
            for role in e.get("roles", []):
                rid = f"role:{role}"
                if not any(n["id"] == rid for n in nodes):
                    nodes.append({"id":rid,"kind":"role","label":role,"data":{"type":"test-account role"}})
                edges.append({"id":f"edge:{e['id']}:{rid}", "source":e["id"], "target":rid, "label":"allows"})
            for p in e.get("params", []):
                pid = f"param:{e['path']}:{p['name']}"
                nodes.append({"id":pid,"kind":"param","label":p["name"],"data":{"location":p.get("location"),"type":p.get("type"),"controllable":bool(p.get("controllable")),"sensitive":bool(p.get("sensitive"))}})
                edges.append({"id":f"edge:{e['id']}:{pid}", "source":e["id"], "target":pid, "label":"accepts"})
        ctx.store.set_graph(nodes, edges)

        counts = {}
        for e in enriched: counts[e["status"]] = counts.get(e["status"], 0) + 1
        ctx.emit("inventory","success", f"Inventory built: {len(enriched)} endpoints ({counts.get('active',0)} active, {counts.get('zombie',0)} zombie, {counts.get('shadow',0)} shadow)", {"counts":counts, "nodes":len(nodes)})
        return enriched
