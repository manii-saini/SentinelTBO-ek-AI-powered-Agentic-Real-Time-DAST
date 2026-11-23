from sentinel.orchestrator import Orchestrator
from sentinel.store import Store


def test_full_agent_loop_demo(tmp_path):
    orch = Orchestrator(Store(tmp_path / "e2e.db"))
    run = orch.run_demo()
    state = orch.get_state()

    assert run["mode"] == "demo"
    assert len(run["stages"]) == 9
    assert all(s["status"] == "done" for s in run["stages"])
    assert len(state["endpoints"]) >= 12
    assert any(e["path"] == "/v1/bookings" and e["status"] == "zombie" for e in state["endpoints"])
    assert any(e["path"] == "/internal/debug" and e["status"] == "shadow" for e in state["endpoints"])

    confirmed = [f for f in state["findings"] if f["status"] not in ("false-positive", "closed")]
    roots = {f["rootCause"] for f in confirmed}
    for expected in [
        "booking-idor", "client-controlled-fare", "mass-assignment-role", "cancel-rebook-double-refund",
        "coupon-replay", "shadow-debug-pii", "supplier-webhook-ssrf", "v21-coupon-stack",
    ]:
        assert expected in roots

    assert any(f["status"] == "false-positive" for f in state["findings"])
    assert len(state["tickets"]) == len(confirmed)
    assert len(state["approvals"]) > 0
    assert state["counters"]["requestsSent"] > 40
    assert state["counters"]["deployToVerifiedMs"] is not None
    assert len(state["graph"]["nodes"]) > 20

    blocked = orch.http.send({"method":"GET","url":"https://production.travel.example/api/bookings","headers":{"x-sentinel-synthetic":"true","authorization":"Bearer test-agent-a"},"runId":"x"})
    assert blocked["blocked"] is True
    assert any(a["blocked"] for a in orch.store.list_audit(blocked_only=True, limit=10))

    idor = next(f for f in confirmed if f["rootCause"] == "booking-idor")
    retested = orch.retest(idor["id"], True)
    assert retested["status"] == "closed"
    assert retested["retest"]["result"] == "closed"
    orch.store.close()


def test_kill_switch_and_allowlist_enforced(tmp_path):
    orch = Orchestrator(Store(tmp_path / "s.db"))
    orch.set_safety({"killSwitch": True})
    r = orch.http.send({"method":"GET","url":"http://synthetic.travel.internal/api/search","headers":{"x-sentinel-synthetic":"true","authorization":"Bearer test-agent-a"},"runId":"x"})
    assert r["blocked"] is True
    assert "KILL SWITCH" in (r["blockReason"] or "")
    orch.set_safety({"killSwitch": False, "allowlist": ["synthetic.travel.internal"]})
    r2 = orch.http.send({"method":"GET","url":"http://evil.example/api/search","headers":{"x-sentinel-synthetic":"true","authorization":"Bearer test-agent-a"},"runId":"x"})
    assert r2["blocked"] is True
    assert "Out of scope" in (r2["blockReason"] or "")
    orch.store.close()
