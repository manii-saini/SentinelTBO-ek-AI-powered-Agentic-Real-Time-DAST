from sentinel.store import Store


def test_store_settings_runs_events(tmp_path):
    s = Store(tmp_path / "t.db")
    s.set_setting("k", {"v": 1})
    assert s.get_setting("k") == {"v": 1}
    s.create_run({"runId": "r1", "startedAt": 1, "mode": "demo", "stages": []})
    s.finish_run("r1", [{"id": "detect", "status": "done"}])
    runs = s.list_runs()
    assert runs[0]["runId"] == "r1"
    assert runs[0]["stages"][0]["status"] == "done"
    s.add_event({"id": "e1", "at": 2, "runId": "r1", "stage": "detect", "level": "info", "message": "hello", "data": {}})
    assert s.list_events()[0]["message"] == "hello"
    s.close()


def test_store_audit_counters(tmp_path):
    s = Store(tmp_path / "t.db")
    s.append_audit({"id":"a1","seq":1,"at":1,"runId":"r","method":"GET","url":"http://synthetic.travel.internal/api/search","host":"synthetic.travel.internal","role":"agent","agency":"A","status":200,"timingMs":3,"bytes":10,"blocked":False,"blockReason":None,"testId":None,"findingId":None,"bodyHash":"x","prevHash":"0","hash":"h","replay":{}})
    s.append_audit({"id":"a2","seq":2,"at":2,"runId":"r","method":"POST","url":"https://evil.example/x","host":"evil.example","role":"agent","agency":"A","status":0,"timingMs":0,"bytes":0,"blocked":True,"blockReason":"Out of scope","testId":None,"findingId":None,"bodyHash":"x","prevHash":"h","hash":"h2","replay":{}})
    c = s.counters()
    assert c["requestsSent"] == 1
    assert c["blocked"] == 1
    assert len(s.list_audit(blocked_only=True)) == 1
    assert "Out of scope" in s.list_audit(search="evil.example")[0]["blockReason"]
    s.close()
