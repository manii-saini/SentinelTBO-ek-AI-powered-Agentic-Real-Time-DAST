from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from sentinel.config import ROOT
from sentinel.openapi import generate_openapi
from sentinel.orchestrator import Orchestrator
from sentinel.severity import TEST_CLASS_LABEL
from sentinel.store import Store

st.set_page_config(page_title="SentinelTBO", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

CUSTOM_CSS = """
<style>
:root { --bg:#070b10; --panel:#0f1720; --panel2:#0b1118; --line:#1d2a37; --text:#d5e0e8; --muted:#8aa0b2; --cyan:#22d3ee; --green:#34d399; --amber:#fbbf24; --red:#fb7185; }
.stApp { background: radial-gradient(circle at top, #102033 0, #070b10 45%, #05080c 100%); color: var(--text); }
[data-testid="stSidebar"] { background: linear-gradient(180deg,#0b1118 0%,#091018 100%); border-right: 1px solid #182635; }
.block-container { padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1600px; }
.panel { background: rgba(15,23,32,.92); border: 1px solid var(--line); border-radius: 12px; padding: 1rem 1rem; box-shadow: 0 10px 30px rgba(0,0,0,.25); }
.metric { background: rgba(11,17,24,.85); border: 1px solid #1a2735; border-radius: 10px; padding: .8rem 1rem; min-height: 92px; }
.metric .label { font-size:.72rem; text-transform:uppercase; letter-spacing:.12em; color: var(--muted); }
.metric .value { font-size:1.7rem; font-weight:700; margin-top:.2rem; font-variant-numeric: tabular-nums; }
.metric .hint { font-size:.72rem; color:#70879a; margin-top:.15rem; }
.badge { display:inline-block; padding:.15rem .5rem; border-radius:999px; font-size:.68rem; font-weight:700; letter-spacing:.04em; border:1px solid #294055; background:#112030; color:#bcd0de; margin-right:.25rem; }
.badge.critical,.badge.red { color:#fecdd3; background:rgba(251,113,133,.12); border-color:rgba(251,113,133,.35); }
.badge.high,.badge.amber { color:#fde68a; background:rgba(251,191,36,.12); border-color:rgba(251,191,36,.35); }
.badge.medium,.badge.violet { color:#ddd6fe; background:rgba(139,92,246,.12); border-color:rgba(139,92,246,.35); }
.badge.low,.badge.cyan,.badge.info { color:#a5f3fc; background:rgba(34,211,238,.12); border-color:rgba(34,211,238,.35); }
.badge.green,.badge.closed { color:#bbf7d0; background:rgba(52,211,153,.12); border-color:rgba(52,211,153,.35); }
.small-muted { color: var(--muted); font-size:.78rem; }
.pipeline { display:grid; grid-template-columns: repeat(9, minmax(0,1fr)); gap:.5rem; }
.stage { background:#0b1118; border:1px solid #1b2938; border-radius:10px; padding:.65rem; min-height:105px; }
.stage .name { font-size:.72rem; font-weight:700; color:#dce8f0; }
.stage .agent { font-size:.64rem; color:#7890a3; font-family: ui-monospace, SFMono-Regular, monospace; margin-top:.15rem; }
.stage .detail { font-size:.66rem; color:#9fb2c2; margin-top:.45rem; line-height:1.3; }
.stage.done { border-color: rgba(52,211,153,.35); } .stage.running { border-color: rgba(34,211,238,.55); box-shadow: inset 0 0 0 1px rgba(34,211,238,.15); } .stage.error { border-color: rgba(251,113,133,.45); }
div[data-testid="stDataFrame"] { border: 1px solid #1b2938; border-radius: 10px; overflow:hidden; }
.stButton>button { border-radius:8px; border:1px solid #284055; background:#122131; color:#e5eef5; }
.stButton>button:hover { border-color:#22d3ee; color:#cffafe; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

PAGES = [
    "Mission Control", "Change Detection", "Knowledge Graph", "API Inventory", "Attack Planner",
    "Execution & Safety", "Approval Queue", "Findings", "Reports & Tickets", "Retest", "Rules of Engagement",
]


def get_orchestrator() -> Orchestrator:
    if "orch" not in st.session_state:
        # Default local DB; allow optional Streamlit secret override when configured.
        db_path = ROOT / "data" / "sentinel_streamlit.db"
        try:
            secret_db = st.secrets.get("SENTINEL_DB", "")
            if secret_db:
                db_path = Path(str(secret_db))
        except Exception:
            pass
        st.session_state.orch = Orchestrator(Store(db_path))
        st.session_state.last_event_id = None
    return st.session_state.orch


def time_ago(ts: int | None) -> str:
    if not ts: return "never"
    diff = max(0, int(time.time() * 1000) - int(ts)) / 1000
    if diff < 60: return f"{int(diff)}s ago"
    if diff < 3600: return f"{int(diff//60)}m ago"
    if diff < 86400: return f"{int(diff//3600)}h ago"
    return f"{int(diff//86400)}d ago"


def fmt_ms(ms: int | None) -> str:
    if ms is None: return "—"
    return f"{ms/1000:.1f}s" if ms >= 1000 else f"{ms}ms"


def badge(text: str, tone: str | None = None) -> str:
    t = (tone or text).lower()
    return f"<span class='badge {t}'>{text}</span>"


def metric(label: str, value: Any, hint: str = "", tone: str = "cyan"):
    color = {"cyan":"#67e8f9","green":"#6ee7b7","amber":"#fcd34d","red":"#fda4af"}.get(tone, "#67e8f9")
    st.markdown(f"<div class='metric'><div class='label'>{label}</div><div class='value' style='color:{color}'>{value}</div><div class='hint'>{hint}</div></div>", unsafe_allow_html=True)


def df(records: list[dict], cols: list[str] | None = None) -> pd.DataFrame:
    if not records:
        return pd.DataFrame(columns=cols or [])
    d = pd.DataFrame(records)
    if cols:
        for c in cols:
            if c not in d.columns: d[c] = None
        d = d[cols]
    return d


def stage_pipeline(stages: list[dict]):
    items = []
    for s in stages:
        detail = (s.get("detail") or "waiting").replace("<", "&lt;").replace(">", "&gt;")
        items.append(f"<div class='stage {s.get('status','idle')}'><div class='name'>{s.get('label')}</div><div class='agent'>{s.get('agent')}</div><div class='detail'>{detail}</div></div>")
    st.markdown("<div class='pipeline'>" + "".join(items) + "</div>", unsafe_allow_html=True)


def run_action(orch: Orchestrator, fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
        st.session_state.last_action_ok = True
        return result
    except Exception as e:
        st.session_state.last_action_ok = False
        st.error(str(e))
        return None

def render_mission(orch: Orchestrator, state: dict):
    c = st.columns(6)
    with c[0]: metric("Endpoints mapped", state["counters"]["endpoints"], "inferred + probed")
    with c[1]: metric("Findings", state["counters"]["findings"], "deduplicated", "amber")
    with c[2]: metric("Confirmed", state["counters"]["confirmed"], "verified 2× + control", "red")
    with c[3]: metric("False positives dropped", state["counters"]["falsePositivesDropped"], "verifier rejections", "green")
    with c[4]: metric("Requests sent", state["counters"]["requestsSent"], f"{state['counters']['blocked']} blocked & logged")
    with c[5]: metric("Deploy → verified", fmt_ms(state["counters"].get("deployToVerifiedMs")), "last deploy-triggered run", "cyan")
    st.write("")
    running = next((s for s in state["stages"] if s["status"] == "running"), None)
    st.markdown(f"<div class='small-muted'>Autonomous agent loop — {running['label'] + ': ' + running.get('detail','') if running else 'idle, fire a change or run demo'}</div>", unsafe_allow_html=True)
    stage_pipeline(state["stages"])
    st.write("")
    left, right = st.columns([2, 1])
    with left:
        st.subheader("Live event feed")
        events = state.get("events", [])[:80]
        if events:
            ev_df = pd.DataFrame([{"time": datetime.fromtimestamp(e["at"]/1000).strftime("%H:%M:%S"), "stage": e["stage"], "level": e["level"], "message": e["message"]} for e in events])
            st.dataframe(ev_df, use_container_width=True, hide_index=True, height=420)
        else:
            st.info("No events yet. Run demo or trigger a scan.")
    with right:
        st.subheader("Safety & run status")
        hs = state.get("healthNow") or {}
        healthy = (hs.get("errorRate", 0) < 0.25) and not state["safety"].get("killSwitch")
        st.markdown(badge("OPERATIONAL" if healthy else "KILL SWITCH ON" if state["safety"].get("killSwitch") else "DEGRADED", "green" if healthy else "red"), unsafe_allow_html=True)
        st.write(f"Target: `{state['target']}`")
        st.write(f"Mode: `{state['mode']}` / `{state['llm']['provider']}`")
        st.write(f"Rate: `{state['safety']['rateLimit']} req/s`, burst `{state['safety']['burst']}`")
        st.write(f"Avg latency: `{hs.get('latencyMs',0)} ms`  |  Error rate: `{hs.get('errorRate',0)*100:.1f}%`")
        st.write(f"Approval gate: `{state['safety'].get('requireApprovalForDestructive', True)}`")
        runs = state.get("runs", [])
        if runs:
            r = runs[0]
            st.write(f"Last run: `{r['runId']}` ({r['mode']})")
            dur = (r.get("finishedAt") or int(time.time()*1000)) - r["startedAt"]
            st.write(f"Duration: `{fmt_ms(dur)}` | stages done: `{sum(1 for s in r.get('stages',[]) if s.get('status')=='done')}/9`")
        health = state.get("health", [])
        if health:
            hdf = pd.DataFrame(health)
            fig = px.area(hdf, x="at", y="latencyMs", labels={"at":"time","latencyMs":"latency ms"})
            fig.update_layout(height=180, margin=dict(l=0,r=0,t=10,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#9fb2c2")
            fig.update_traces(line_color="#22d3ee")
            fig.update_xaxes(showticklabels=False)
            st.plotly_chart(fig, use_container_width=True)


def render_changes(orch: Orchestrator, state: dict):
    left, right = st.columns([1,2])
    with left:
        st.subheader("Fire simulated trigger")
        for kind, label, detail in [
            ("deploy","CI/CD deploy webhook","POST trigger — stage build, changed handlers"),
            ("bundle-diff","Front-end JS bundle diff","New route literals extracted from shipped bundle"),
            ("subdomain","New subdomain / CT log","Certificate transparency emitted a staging host"),
            ("traffic-anomaly","Traffic-log anomaly","Gateway detects unusual legacy path activity"),
        ]:
            if st.button(f"{label}", key=f"trigger-{kind}", use_container_width=True):
                run_action(orch, orch.fire_trigger, kind)
                st.rerun()
            st.caption(detail)
        if st.button("Deploy v2.1 + run full loop (demo auto-approve)", type="primary", use_container_width=True):
            run_action(orch, orch.run_demo)
            st.rerun()
        st.code("Simulated in-process webhook: orchestrator.deploy_v21()", language="python")
    with right:
        st.subheader("Change events")
        changes = state.get("changes", [])
        if not changes:
            st.info("No changes detected yet.")
        for c in changes:
            st.markdown(f"**{c['title']}** {badge(c['status'],'green' if c['status']=='tested' else 'cyan' if c['status']=='testing' else 'amber')}", unsafe_allow_html=True)
            st.caption(f"{c['detail']} | {c['source']} | {time_ago(c['createdAt'])}")
            st.code(" ".join(c.get("endpoints", [])) or "(none)", language="text")

def render_graph(orch: Orchestrator, state: dict):
    st.subheader("App knowledge graph")
    graph = state.get("graph", {"nodes":[],"edges":[]})
    nodes, edges = graph.get("nodes", []), graph.get("edges", [])
    st.caption(f"{len(nodes)} nodes / {len(edges)} edges — endpoints, params, roles, business flows")
    if not nodes:
        st.info("Graph is empty. Run the agent loop to build inventory.")
        return
    # simple layered layout by kind
    kind_x = {"flow":0, "endpoint":1, "role":2, "param":3, "asset":4}
    counters = {}
    pos = {}
    for n in nodes:
        k = n.get("kind","asset")
        row = counters.get(k,0); counters[k]=row+1
        pos[n["id"]] = (kind_x.get(k,4)*2.2, -row*0.8)
    edge_x, edge_y = [], []
    for e in edges:
        s, t = pos.get(e["source"]), pos.get(e["target"])
        if not s or not t: continue
        edge_x += [s[0], t[0], None]; edge_y += [s[1], t[1], None]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines", line=dict(width=1,color="#294055"), hoverinfo="none", name="edges"))
    for kind, color in [("flow","#34d399"),("endpoint","#22d3ee"),("role","#a78bfa"),("param","#fbbf24"),("asset","#94a3b8")]:
        ks = [n for n in nodes if n.get("kind")==kind]
        if not ks: continue
        fig.add_trace(go.Scatter(
            x=[pos[n["id"]][0] for n in ks], y=[pos[n["id"]][1] for n in ks],
            mode="markers+text", text=[n.get("label","")[:28] for n in ks], textposition="top center",
            marker=dict(size=14 if kind!="param" else 10, color=color, line=dict(width=1,color="#0b1118")),
            customdata=[json.dumps(n.get("data",{}), ensure_ascii=False)[:300] for n in ks],
            hovertemplate="<b>%{text}</b><br>kind="+kind+"<br>%{customdata}<extra></extra>", name=kind
        ))
    fig.update_layout(height=620, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      xaxis=dict(showgrid=False,zeroline=False,visible=False), yaxis=dict(showgrid=False,zeroline=False,visible=False), legend=dict(orientation="h"))
    st.plotly_chart(fig, use_container_width=True)
    nid = st.selectbox("Node inspector", ["(select)"] + [f"{n['kind']}::{n['label']}::{n['id']}" for n in nodes[:400]])
    if nid != "(select)":
        sel_id = nid.split("::")[-1]
        node = next((n for n in nodes if n["id"]==sel_id), None)
        ep = next((e for e in state.get("endpoints",[]) if e["id"]==sel_id), None)
        if node:
            st.json(node.get("data", {}))
        if ep:
            st.write("**Parameters**")
            st.dataframe(df(ep.get("params",[])), use_container_width=True, hide_index=True)
            st.write(f"Roles: `{', '.join(ep.get('roles',[])) or 'unauthenticated'}` | {ep.get('hits30d',0)} hits/30d | last {time_ago(ep.get('lastRealTraffic'))}")


def render_inventory(orch: Orchestrator, state: dict):
    st.subheader("Inferred API inventory")
    c1,c2,c3,c4 = st.columns([2,1,1,1])
    with c1: q = st.text_input("Filter path or owner", "")
    with c2: tab = st.selectbox("Status", ["all","active","zombie","shadow"])
    with c3: window = st.selectbox("Traffic window", [30,90], index=0)
    with c4:
        st.download_button("Export OpenAPI 3", data=json.dumps(generate_openapi(state.get("endpoints",[])), indent=2), file_name="sentinel-inferred-openapi.json", mime="application/json", use_container_width=True)
    endpoints = state.get("endpoints", [])
    if window != 30:
        endpoints = orch.store.list_endpoints(window)
    rows = []
    for e in endpoints:
        if tab != "all" and e.get("status") != tab: continue
        hay = (e.get("path","") + " " + e.get("owner","")).lower()
        if q and q.lower() not in hay: continue
        rows.append({
            "Endpoint": f"{e.get('method')} {e.get('path')}",
            "State": e.get("status"), "Last real traffic": time_ago(e.get("lastRealTraffic")),
            "Auth": ",".join(e.get("roles",[])) if e.get("authRequired") else "none",
            "Data exposed": ", ".join(e.get("dataExposed",[])),
            "Vulns vs version": e.get("vulnerableToVersion") or "—",
            "Owner": e.get("owner"), "Recommendation": e.get("recommendation"),
            f"Hits/{window}d": e.get("windowHits", e.get("hits30d")),
        })
    st.dataframe(df(rows), use_container_width=True, hide_index=True, height=520)
    st.subheader("Discovery techniques")
    st.dataframe(df(state.get("techniques", [])), use_container_width=True, hide_index=True)

def render_planner(orch: Orchestrator, state: dict):
    st.subheader("Targeted attack plan")
    st.caption(f"{len(state.get('tests',[]))} tests selected from parameters, roles and business context — no broad spraying. Reasoning: {state.get('llm',{}).get('provider')}")
    tests = state.get("tests", [])
    if not tests:
        st.info("No tests planned yet. Run the agent loop.")
        return
    classes = sorted(set(t["testClass"] for t in tests))
    for tc in classes:
        st.markdown(f"### {TEST_CLASS_LABEL.get(tc, tc)}")
        tc_tests = [t for t in tests if t["testClass"] == tc]
        for t in tc_tests:
            with st.expander(f"{t['name']} — {t['method']} {t['endpoint']} [{t['status']}]"):
                st.markdown(f"{badge(t['risk'],'red' if t['risk']=='high' else 'amber' if t['risk']=='medium' else 'cyan')} {badge(t['status'],'green' if t['status']=='done' else 'amber' if t.get('needsApproval') else 'cyan')} {' '+badge('approval gate','amber') if t.get('needsApproval') else ''}", unsafe_allow_html=True)
                st.write(t.get("reasoning",""))
                st.write(f"Params: `{', '.join(t.get('params',[])) or 'none'}` | Roles: `{', '.join(t.get('roles',[])) or 'anonymous'}` | Executor: `{t.get('executor')}`")


def render_execution(orch: Orchestrator, state: dict):
    st.subheader("Execution & Safety")
    top = st.columns(3)
    with top[0]:
        st.markdown("**Scope allowlist**")
        allow = st.text_area("One host per line", "\n".join(state["safety"].get("allowlist",[])), height=110)
        if st.button("Save scope", use_container_width=True):
            vals = [v.strip() for v in allow.replace(",","\n").splitlines() if v.strip()]
            run_action(orch, orch.set_safety, {"allowlist": vals}); st.rerun()
    with top[1]:
        st.markdown("**Rate limit & health response**")
        rate = st.slider("Requests / second", 1, 60, int(state["safety"].get("rateLimit",12)))
        cA,cB = st.columns(2)
        if cA.button("Apply rate", use_container_width=True): run_action(orch, orch.set_safety, {"rateLimit": rate}); st.rerun()
        ks = state["safety"].get("killSwitch", False)
        if cB.button("Resume traffic" if ks else "Kill all traffic", use_container_width=True): run_action(orch, orch.set_safety, {"killSwitch": not ks}); st.rerun()
        st.caption(f"Backoff: {state['safety'].get('healthBackoffThreshold',0.25)*100:.0f}% | Pause: {state['safety'].get('healthPauseThreshold',0.5)*100:.0f}%")
    with top[2]:
        st.markdown("**Test credential vault (synthetic only)**")
        creds = [{"Account":k,"Agency":v["agency"],"Role":v["role"],"Token":"test-•••••"+v["token"][-3:]} for k,v in state["safety"].get("testCredentials",{}).items()]
        st.dataframe(df(creds), use_container_width=True, hide_index=True, height=180)

    health = state.get("health", [])
    if health:
        hdf = pd.DataFrame(health)
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=hdf["at"], y=hdf["latencyMs"], name="latency ms", line=dict(color="#22d3ee")))
        fig.add_trace(go.Scatter(x=hdf["at"], y=hdf["errorRate"]*100, name="error %", line=dict(color="#fb7185"), yaxis="y2"))
        fig.update_layout(height=260, margin=dict(l=0,r=0,t=20,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#9fb2c2",
                          yaxis=dict(title="ms"), yaxis2=dict(title="%", overlaying="y", side="right"), legend=dict(orientation="h"))
        fig.update_xaxes(showticklabels=False)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("**Replayable audit log**")
    f1,f2,f3 = st.columns([2,1,1])
    with f1: search = st.text_input("Search URL/method/role", "")
    with f2: blocked_only = st.checkbox("Blocked only", False)
    with f3:
        audit_export = "\n".join(json.dumps(r) for r in orch.store.list_audit(limit=10000))
        st.download_button("Export JSONL", data=audit_export, file_name="sentinel-audit.jsonl", mime="application/jsonl", use_container_width=True)
    audit = orch.store.list_audit(search=search or None, blocked_only=blocked_only, limit=400)
    adf = pd.DataFrame([{"seq":a["seq"],"time":time_ago(a["at"]),"method":a["method"],"url":a["url"],"role":a["role"],"status":a["status"] or "—","timingMs":a["timingMs"],"result":"BLOCKED" if a["blocked"] else "allowed","reason":a.get("blockReason") or ""} for a in audit])
    st.dataframe(adf, use_container_width=True, hide_index=True, height=320)
    sel = st.selectbox("Replay record", ["(none)"] + [f"{a['seq']}::{a['method']} {a['url']}" for a in audit[:200]])
    if sel != "(none)":
        seq = int(sel.split("::")[0])
        rec = next((a for a in audit if a["seq"]==seq), None)
        if rec:
            st.caption(f"hash {rec['hash']} | prev {rec['prevHash']} | {rec.get('blockReason') or 'allowed by safety layer'}")
            st.json(rec.get("replay", {}))

def render_approvals(orch: Orchestrator, state: dict):
    st.subheader("Human approval queue")
    tab = st.radio("View", ["pending","all"], horizontal=True)
    approvals = [a for a in state.get("approvals",[]) if tab=="all" or a.get("status")=="pending"]
    if not approvals:
        st.info("Queue clear." if tab=="pending" else "No approvals yet.")
        return
    for a in approvals:
        with st.container(border=True):
            st.markdown(f"{badge(a['kind'],'cyan' if a['kind']=='test' else 'violet')} {badge(a['risk'],'red' if a['risk']=='high' else 'amber')} {badge(a['status'],'green' if a['status']=='approved' else 'red' if a['status']=='rejected' else 'violet' if a['status']=='modified' else 'amber')}", unsafe_allow_html=True)
            st.markdown(f"**{a['title']}**")
            st.caption(a.get("reason",""))
            st.caption(f"{a['id']} · {a['refId']} · {time_ago(a.get('createdAt'))}")
            if a.get("status") == "pending":
                note = st.text_input("Modification note (optional)", key=f"note-{a['id']}")
                b1,b2,b3 = st.columns(3)
                if b1.button("Approve", key=f"ap-{a['id']}", use_container_width=True): run_action(orch, orch.approve, a['id'], 'approved', {"note":note} if note else None); st.rerun()
                if b2.button("Reject", key=f"rj-{a['id']}", use_container_width=True): run_action(orch, orch.approve, a['id'], 'rejected', {"note":note} if note else None); st.rerun()
                if b3.button("Modify & approve", key=f"md-{a['id']}", use_container_width=True): run_action(orch, orch.approve, a['id'], 'modified', {"note":note} if note else None); st.rerun()


def render_findings(orch: Orchestrator, state: dict):
    st.subheader("Verified findings")
    tab = st.radio("View", ["confirmed","dropped","retsted/closed"], horizontal=True)
    findings = state.get("findings", [])
    def include(f):
        if tab=="dropped": return f.get("status")=="false-positive"
        if tab=="retsted/closed": return f.get("status") in ("closed","still-vulnerable")
        return f.get("status") not in ("false-positive","closed","still-vulnerable")
    items = [f for f in findings if include(f)]
    if not items:
        st.info("Nothing here yet. Run the agent loop.")
        return
    for f in items:
        with st.expander(f"[{f.get('severity','').upper()} {f.get('score',0)}] {f.get('title')} — {f.get('endpoint')}"):
            st.markdown(f"{badge(f.get('severity','info'))} {badge(TEST_CLASS_LABEL.get(f.get('testClass'),'test'),'cyan')} {badge(f.get('status','open'),'green' if f.get('status')=='closed' else 'red' if f.get('status')=='still-vulnerable' else 'amber')}", unsafe_allow_html=True)
            st.write(f"Owner: **{f.get('owner')}** | Requests: `{f.get('requestsSent',0)}` | {time_ago(f.get('createdAt'))}")
            st.caption(f"CWE: {f.get('cwe')} | OWASP: {f.get('owasp')}")
            st.write("**Impact**"); st.write(f.get("impact",""))
            st.write("**Severity rationale**"); st.write(f.get("scoreExplanation",""))
            st.write("**Suggested fix**"); st.write(f.get("fix",""))
            st.write("**Minimal proof (redacted, synthetic only)**")
            for i, e in enumerate(f.get("evidence",[]),1):
                st.markdown(f"**{i}. {e.get('label','evidence')}** — `{e.get('response',{}).get('status')}` in `{e.get('response',{}).get('timingMs')}ms`")
                st.code(f"{e.get('request',{}).get('method')} {e.get('request',{}).get('url')}\n{e.get('request',{}).get('body') or ''}", language="http")
                st.code(str(e.get("response",{}).get("body",""))[:900], language="json")
            if f.get("retest"):
                rt = f["retest"]
                st.markdown(f"**Retest:** {badge(rt.get('result',''), 'green' if rt.get('result')=='closed' else 'red')} at {time_ago(rt.get('at'))}")


def render_reports(orch: Orchestrator, state: dict):
    st.subheader("Reports & Tickets")
    tickets = state.get("tickets", [])
    findings = {f["id"]: f for f in state.get("findings", [])}
    left, right = st.columns([1,2])
    with left:
        if not tickets:
            st.info("No tickets yet.")
        for t in tickets:
            f = findings.get(t.get("findingId"), {})
            label = f"{t['id']} [{f.get('severity','').upper()}] {t['title'][:60]}"
            if st.button(label, key=f"sel-{t['id']}", use_container_width=True):
                st.session_state.selected_ticket = t["id"]
    with right:
        tid = st.session_state.get("selected_ticket") or (tickets[0]["id"] if tickets else None)
        t = next((x for x in tickets if x["id"]==tid), None)
        if not t:
            st.info("Select a ticket.")
        else:
            st.markdown(f"### {t['title']}")
            st.caption(f"{t['id']} · {t['destination']} · {'sent' if t.get('sent') else 'draft'} · {time_ago(t.get('createdAt'))}")
            b1,b2,b3 = st.columns(3)
            if b1.button("Send to Jira (mock)", use_container_width=True): run_action(orch, orch.send_ticket, t['id'], 'mock-jira'); st.rerun()
            if b2.button("Send to Teams (mock)", use_container_width=True): run_action(orch, orch.send_ticket, t['id'], 'mock-teams'); st.rerun()
            if b3.button("Send webhook", use_container_width=True): run_action(orch, orch.send_ticket, t['id'], 'webhook'); st.rerun()
            st.markdown(t.get("markdown",""))
    st.markdown("**Webhook adapter**")
    url = st.text_input("Webhook URL (must pass allowlist)", value=state.get("webhookConfig",{}).get("url",""))
    if st.button("Save webhook"):
        run_action(orch, orch.set_webhook, url); st.rerun()
    st.caption("Out-of-scope webhook destinations are blocked and written to audit log.")

def render_retest(orch: Orchestrator, state: dict):
    st.subheader("Fix verification & retest")
    st.caption("Deploys a patch to the synthetic staging mock, then replays the stored minimal proof.")
    candidates = [f for f in state.get("findings", []) if f.get("status") != "false-positive"]
    if not candidates:
        st.info("No findings to retest yet.")
        return
    for f in candidates:
        with st.container(border=True):
            cols = st.columns([4,1,1,1])
            with cols[0]:
                st.markdown(f"**{f['title']}**  {badge(f['severity'])} {badge(f['status'],'green' if f['status']=='closed' else 'red' if f['status']=='still-vulnerable' else 'amber')}")
                st.caption(f"{f['endpoint']} · {TEST_CLASS_LABEL.get(f.get('testClass'),'')} · owner {f.get('owner')} · {time_ago(f.get('retest',{}).get('at') if f.get('retest') else None)}")
            if cols[1].button("Fix deployed → retest", key=f"fix-{f['id']}", use_container_width=True):
                run_action(orch, orch.retest, f['id'], True); st.rerun()
            if cols[2].button("Replay proof", key=f"rep-{f['id']}", use_container_width=True):
                run_action(orch, orch.retest, f['id'], False); st.rerun()
            if cols[3].button("Evidence", key=f"ev-{f['id']}", use_container_width=True):
                st.session_state[f"showev-{f['id']}"] = not st.session_state.get(f"showev-{f['id']}", False)
            if st.session_state.get(f"showev-{f['id']}"):
                e1,e2 = st.columns(2)
                with e1:
                    st.write("**Before**")
                    if f.get("evidence"): st.code(str(f["evidence"][-1].get("response",{}).get("body",""))[:900], language="json")
                with e2:
                    st.write("**After**")
                    if f.get("retest") and f["retest"].get("after"):
                        st.code(str(f["retest"]["after"][-1].get("response",{}).get("body",""))[:900], language="json")
                    else:
                        st.info("Not retested yet.")


def render_rules(state: dict):
    st.subheader("Rules of Engagement — active")
    st.markdown("Enforced in code by the safety layer, not only displayed in UI.")
    rules = [
        ("Scope", "Targets are restricted to an explicit host allowlist. Any request outside scope is stopped before execution and written to audit log."),
        ("Synthetic identities", "Only bundled test accounts for agencies A and B. Real credentials are rejected."),
        ("No destructive testing", "Destructive payment/refund/booking/cancel tests require approved request id. No DoS, no persistence, no bulk extraction."),
        ("Minimal, redacted evidence", "Verifier replays minimal proof twice against control and redacts passport/card/email/token fields."),
        ("Full replayability", "Every allowed or blocked request is append-only hash-chained in audit log with replay payload."),
        ("Staging only", "Bundled target is an in-process synthetic travel platform. No production systems."),
    ]
    cols = st.columns(3)
    for i,(title,text) in enumerate(rules):
        with cols[i%3]:
            st.markdown(f"<div class='panel'><h4>{title}</h4><div class='small-muted'>{text}</div></div>", unsafe_allow_html=True)
            st.write("")
    st.markdown("**Enforcement points**")
    st.dataframe(df([
        {"File":"sentinel/safety.py","Responsibility":"allowlist, token bucket, approval gate, health pause/backoff, hash-chained audit, redaction"},
        {"File":"sentinel/proofs.py","Responsibility":"synthetic headers/credentials, minimal evidence, scoped proof execution"},
        {"File":"sentinel/agents/verifier.py","Responsibility":"2x replay + control, false-positive rejection"},
        {"File":"sentinel/mock_platform.py","Responsibility":"in-process synthetic staging target with vulnerable/fixable fixtures"},
    ]), use_container_width=True, hide_index=True)
    st.json(state.get("safety", {}))


def main():
    orch = get_orchestrator()
    state = orch.get_state(st.session_state.get("window", 30))

    with st.sidebar:
        st.markdown("## 🛡️ SentinelTBO")
        st.caption("Agentic Real-Time DAST Control Plane")
        st.markdown(badge("SYNTHETIC STAGING ONLY","green"), unsafe_allow_html=True)
        page = st.radio("Navigation", PAGES, label_visibility="collapsed")
        st.divider()
        st.write(f"Target: `{state['target']}`")
        st.write(f"Running: `{state['running']}`")
        st.write(f"SSE replacement: Streamlit state refresh")
        pending = len([a for a in state.get("approvals",[]) if a.get("status")=="pending"])
        st.write(f"Pending approvals: `{pending}`")
        st.divider()
        c1,c2 = st.columns(2)
        if c1.button("Run loop", use_container_width=True, disabled=state["running"]):
            run_action(orch, orch.run_loop, "full", False); st.rerun()
        if c2.button("Demo", use_container_width=True, disabled=state["running"]):
            run_action(orch, orch.run_demo); st.rerun()
        if st.button("Reset workspace", use_container_width=True):
            run_action(orch, orch.reset); st.rerun()
        st.divider()
        auto = st.toggle("Auto-refresh (2s)", value=st.session_state.get("auto_refresh", False))
        st.session_state.auto_refresh = auto
        st.caption("No Node/npm/runtime servers required. All execution is in-process Python.")

    st.markdown(f"# {page}")
    st.caption("SentinelTBO — detect → learn → inventory → plan → execute → verify → triage → report → retest")

    if page == "Mission Control": render_mission(orch, state)
    elif page == "Change Detection": render_changes(orch, state)
    elif page == "Knowledge Graph": render_graph(orch, state)
    elif page == "API Inventory": render_inventory(orch, state)
    elif page == "Attack Planner": render_planner(orch, state)
    elif page == "Execution & Safety": render_execution(orch, state)
    elif page == "Approval Queue": render_approvals(orch, state)
    elif page == "Findings": render_findings(orch, state)
    elif page == "Reports & Tickets": render_reports(orch, state)
    elif page == "Retest": render_retest(orch, state)
    elif page == "Rules of Engagement": render_rules(state)

    if st.session_state.get("auto_refresh"):
        time.sleep(2)
        st.rerun()


if __name__ == "__main__":
    main()
