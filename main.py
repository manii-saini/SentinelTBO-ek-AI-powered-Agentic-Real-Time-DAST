import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent

st.set_page_config(page_title="SentinelTBO Host", page_icon="🛡️", layout="wide")

SERVICES = {
    "mock": {"cmd": ["npm", "run", "dev:mock"], "port": 4000, "url": "http://127.0.0.1:4000"},
    "api": {"cmd": ["npm", "run", "dev:api"], "port": 3001, "url": "http://127.0.0.1:3001"},
    "web": {"cmd": ["npm", "run", "dev:web"], "port": 5173, "url": "http://127.0.0.1:5173"},
}


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex((host, port)) == 0


def ensure_state():
    st.session_state.setdefault("procs", {})  # name -> pid
    st.session_state.setdefault("logs", {})   # name -> list[str]


def is_running(name: str) -> bool:
    pid = st.session_state.procs.get(name)
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        st.session_state.procs[name] = None
        return False


def start_service(name: str):
    if is_running(name):
        return
    log_path = ROOT / f".streamlit-{name}.log"
    log_file = open(log_path, "ab", buffering=0)
    proc = subprocess.Popen(
        SERVICES[name]["cmd"],
        cwd=ROOT,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    st.session_state.procs[name] = proc.pid
    st.session_state.logs[name] = str(log_path)


def stop_service(name: str):
    pid = st.session_state.procs.get(name)
    if not pid:
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except Exception:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    st.session_state.procs[name] = None


def read_log(name: str, lines: int = 80) -> str:
    path = st.session_state.logs.get(name) or str(ROOT / f".streamlit-{name}.log")
    p = Path(path)
    if not p.exists():
        return ""
    try:
        data = p.read_text(errors="replace").splitlines()
        return "\n".join(data[-lines:])
    except Exception as e:
        return f"(unable to read log: {e})"


def run_command(cmd, title: str):
    st.subheader(title)
    with st.spinner(f"Running: {' '.join(cmd)}"):
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        output = st.empty()
        lines = []
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line.rstrip())
            output.code("\n".join(lines[-200:]), language="text")
        code = proc.wait()
    if code == 0:
        st.success(f"Completed: {' '.join(cmd)}")
    else:
        st.error(f"Failed ({code}): {' '.join(cmd)}")


ensure_state()

st.title("SentinelTBO — Streamlit Host")
st.caption("Agentic Real-Time DAST control plane for a B2B travel platform (staging only).")

with st.sidebar:
    st.header("Environment")
    st.write(f"Python: `{sys.version.split()[0]}`")
    st.write(f"Root: `{ROOT}`")
    node_ok = subprocess.call(["bash", "-lc", "command -v node >/dev/null 2>&1"]) == 0
    npm_ok = subprocess.call(["bash", "-lc", "command -v npm >/dev/null 2>&1"]) == 0
    st.write(f"Node available: {'yes' if node_ok else 'no'}")
    st.write(f"npm available: {'yes' if npm_ok else 'no'}")
    st.markdown("---")
    if st.button("Install dependencies (npm install)", use_container_width=True):
        run_command(["npm", "install"], "npm install")
    if st.button("Run scripted demo (npm run demo)", use_container_width=True):
        run_command(["npm", "run", "demo"], "npm run demo")

st.markdown(
    """
**Services**
- Web UI: `http://127.0.0.1:5173`
- Control plane API + SSE: `http://127.0.0.1:3001`
- Synthetic travel platform (mock): `http://127.0.0.1:4000`
"""
)

cols = st.columns(3)
for col, name in zip(cols, ["mock", "api", "web"]):
    svc = SERVICES[name]
    with col:
        st.subheader(name.upper())
        running = is_running(name)
        listening = port_open(svc["port"])
        st.write(f"Process: {'running' if running else 'stopped'}")
        st.write(f"Port {svc['port']}: {'listening' if listening else 'closed'}")
        st.code(svc["url"], language="text")
        b1, b2 = st.columns(2)
        if b1.button(f"Start {name}", key=f"start-{name}", use_container_width=True):
            start_service(name)
            time.sleep(0.5)
            st.rerun()
        if b2.button(f"Stop {name}", key=f"stop-{name}", use_container_width=True):
            stop_service(name)
            time.sleep(0.2)
            st.rerun()

c1, c2 = st.columns(2)
with c1:
    if st.button("Start all services", use_container_width=True):
        for n in ["mock", "api", "web"]:
            start_service(n)
        time.sleep(1.0)
        st.rerun()
with c2:
    if st.button("Stop all services", use_container_width=True):
        for n in ["web", "api", "mock"]:
            stop_service(n)
        time.sleep(0.2)
        st.rerun()

if port_open(5173):
    st.markdown("### Web UI")
    st.link_button("Open SentinelTBO UI", "http://127.0.0.1:5173")
    try:
        st.components.v1.iframe("http://127.0.0.1:5173", height=900, scrolling=True)
    except Exception:
        pass

tabs = st.tabs(["Mock log", "API log", "Web log", "About"])
for tab, name in zip(tabs[:3], ["mock", "api", "web"]):
    with tab:
        st.code(read_log(name) or "(no log yet)", language="text")
        if st.button(f"Refresh {name} log", key=f"refresh-{name}"):
            st.rerun()

with tabs[3]:
    readme = ROOT / "README.md"
    if readme.exists():
        st.markdown(readme.read_text(errors="replace"))
    else:
        st.info("README.md not found.")
