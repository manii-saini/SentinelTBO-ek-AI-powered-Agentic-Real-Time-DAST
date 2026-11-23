from sentinel.safety import SafeHttpClient, SafetyLayer


def transport_ok(req):
    return {"status": 200, "body": '{"ok":true}'}


def base_headers():
    return {"x-sentinel-synthetic": "true", "authorization": "Bearer test-agent-a"}


def test_out_of_scope_blocked_and_audited():
    safety = SafetyLayer({"allowlist": ["synthetic.travel.internal"]})
    audits = []
    safety.on_audit(audits.append)
    client = SafeHttpClient(safety, transport_ok)
    res = client.send({"method": "GET", "url": "https://production.travel.example/api/bookings", "headers": base_headers(), "runId": "t"})
    assert res["blocked"] is True
    assert "Out of scope" in (res["blockReason"] or "")
    assert audits and audits[0]["blocked"] is True


def test_missing_marker_and_bad_token_blocked():
    safety = SafetyLayer({"allowlist": ["synthetic.travel.internal"]})
    client = SafeHttpClient(safety, transport_ok)
    bad_marker = client.send({"method": "GET", "url": "http://synthetic.travel.internal/api/search", "headers": {"authorization": "Bearer test-agent-a"}})
    assert "synthetic-traffic marker" in (bad_marker["blockReason"] or "")
    bad_token = client.send({"method": "GET", "url": "http://synthetic.travel.internal/api/search", "headers": {"x-sentinel-synthetic": "true", "authorization": "Bearer real-token"}})
    assert "approved synthetic test account" in (bad_token["blockReason"] or "")


def test_destructive_requires_approval():
    safety = SafetyLayer({"allowlist": ["synthetic.travel.internal"]})
    approved = {"ok": False}
    safety.is_approved(lambda aid: approved["ok"] and aid == "apr_1")
    client = SafeHttpClient(safety, transport_ok)
    blocked = client.send({"method": "POST", "url": "http://synthetic.travel.internal/api/refund", "headers": {**base_headers(), "x-sentinel-approval": "apr_1"}, "body": "{}"})
    assert "approved request" in (blocked["blockReason"] or "")
    approved["ok"] = True
    allowed = client.send({"method": "POST", "url": "http://synthetic.travel.internal/api/refund", "headers": {**base_headers(), "x-sentinel-approval": "apr_1"}, "body": "{}"})
    assert allowed["blocked"] is False
    assert allowed["status"] == 200


def test_kill_switch_blocks():
    safety = SafetyLayer({"allowlist": ["synthetic.travel.internal"], "killSwitch": True})
    r = safety.authorize({"method": "GET", "url": "http://synthetic.travel.internal/api/search", "headers": base_headers()})
    assert r.allowed is False
    assert "KILL SWITCH" in (r.reason or "")


def test_audit_hash_chain_and_redaction():
    safety = SafetyLayer({"allowlist": ["synthetic.travel.internal"]})
    seen = []
    safety.on_audit(seen.append)
    safety.record_response({"method": "POST", "url": "http://synthetic.travel.internal/api/book", "headers": base_headers(), "body": '{"passport":"A1234567","email":"a@b.com"}', "runId": "r"}, 200, 12, 10, False)
    safety.record_response({"method": "GET", "url": "http://synthetic.travel.internal/api/search", "headers": base_headers(), "runId": "r"}, 200, 8, 0, False)
    assert seen[1]["prevHash"] == seen[0]["hash"]
    assert seen[0]["hash"] != seen[1]["hash"]
    assert "A1234567" not in (seen[0]["replay"].get("body") or "")
    assert "a@b.com" not in (seen[0]["replay"].get("body") or "")
    assert "REDACTED" in (seen[0]["replay"].get("body") or "")
