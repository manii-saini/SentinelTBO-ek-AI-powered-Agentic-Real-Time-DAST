from __future__ import annotations

import json
from typing import Any, Callable

from .models import redact


def _send(ctx, method: str, path: str, *, role=None, agency="A", body=None, approval_key=None, label=None):
    headers = {"x-sentinel-synthetic": "true", "content-type": "application/json"}
    role_label = "anonymous"
    if role:
        cred_key = f"{'subagent' if role == 'sub-agent' else role}-{agency.lower()}"
        cred = ctx.safety.config.get("testCredentials", {}).get(cred_key)
        if cred:
            headers["authorization"] = f"Bearer {cred['token']}"
            role_label = f"{cred['role']}@agency-{cred['agency']}"
    approval_id = ctx.approval_for(approval_key) if approval_key else None
    if approval_id:
        headers["x-sentinel-approval"] = approval_id
    url = path if path.startswith("http") else f"{ctx.target}{path}"
    body_s = json.dumps(body) if body is not None else None
    res = ctx.http.send({"method": method, "url": url, "headers": headers, "body": body_s, "role": role, "agency": agency, "runId": ctx.run_id})
    try:
        parsed = json.loads(res.get("body", "{}"))
    except Exception:
        parsed = {"raw": res.get("body", "")[:200]}
    exchange = {
        "label": label or f"{method} {path} ({role_label})",
        "request": {"method": method, "url": url, "headers": {**headers, "authorization": "[MASKED TEST TOKEN]" if headers.get("authorization") else "(none)"}, "body": redact(body_s) if body_s else None},
        "response": {"status": res.get("status", 0), "body": redact(res.get("body", ""))[:900], "timingMs": res.get("timingMs", 0)},
    }
    return {"status": res.get("status", 0), "json": parsed, "exchange": exchange, "blocked": res.get("blocked", False)}


def _result(reproduced: bool, evidence: list[dict], meta: dict) -> dict:
    meta = {**meta, "requests": meta.get("requests", 0) + len(evidence)}
    return {"reproduced": reproduced, "evidence": evidence, "meta": meta}


def _proofs() -> dict[str, dict[str, Any]]:
    P = []

    def add(key, label, endpoint, method, fn):
        P.append({"key": key, "label": label, "endpoint": endpoint, "method": method, "run": fn})

    add("bola", "Booking IDOR across agencies", "/api/bookings/:id", "GET", lambda ctx: _result(
        (a := _send(ctx, "GET", "/api/bookings/BK-B-2001", role="agent", agency="A", label="Proof: agency A reads agency B booking"))["json"].get("authorizationBypassed") is True and a["json"].get("agency") == "B",
        [_send(ctx, "GET", "/api/bookings/mine", role="agent", agency="A", label="Control: own-agency bookings")["exchange"], a["exchange"]],
        {"rootCause":"booking-idor","businessContext":["bookings","pii"],"crossAgency":True,"authBypass":True,"impact":"Any agency agent can read another agency’s booking, PNR and passenger details, leaking partner data and violating tenancy isolation.","fix":"Enforce tenant-scoped authorization in the booking repository (WHERE agency_id = caller.agency_id) and return 404 for foreign identifiers.","requests":0}
    ))

    add("cross-agency-enum", "Cross-agency booking enumeration", "/v1/bookings", "GET", lambda ctx: _result(
        isinstance((a := _send(ctx, "GET", "/v1/bookings", role="agent", agency="A", label="Proof: legacy list spans agencies"))["json"].get("exposedAgencies"), list) and len(a["json"].get("exposedAgencies", [])) > 1,
        [_send(ctx, "GET", "/api/bookings/mine", role="agent", agency="A", label="Control: scoped booking list")["exchange"], a["exchange"]],
        {"rootCause":"legacy-cross-tenant-list","businessContext":["bookings","pii"],"crossAgency":True,"impact":"Legacy list aggregates bookings from both agencies, enabling cross-tenant enumeration.","fix":"Decommission /v1 or apply the same tenant policy and response schema as /api/bookings.","requests":0}
    ))

    add("unauth-legacy", "Legacy API missing authentication", "/v1/bookings", "GET", lambda ctx: _result(
        (a := _send(ctx, "GET", "/v1/bookings", label="Proof: unauthenticated legacy read"))["status"] == 200 and isinstance(a["json"].get("bookings"), list) and (c := _send(ctx, "GET", "/api/bookings/mine", label="Control: protected endpoint without credentials"))["status"] == 401,
        [c["exchange"], a["exchange"]],
        {"rootCause":"legacy-missing-auth","businessContext":["bookings"],"unauthenticated":True,"impact":"Unauthenticated callers can enumerate legacy booking records.","fix":"Remove legacy route from gateway or require the standard synthetic/staging auth policy.","requests":0}
    ))

    def fare(ctx):
        hold = _send(ctx, "POST", "/api/hold", role="agent", agency="A", body={"destination":"BOM"}, label="Control: server-issued fare")
        attack = _send(ctx, "POST", "/api/book", role="agent", agency="A", body={"holdId": hold["json"].get("holdId"), "fare": 1}, approval_key="fare-tamper", label="Proof: client sets fare to 1")
        reproduced = attack["json"].get("priceTampered") is True and attack["json"].get("fareCharged") == 1
        return _result(reproduced, [hold["exchange"], attack["exchange"]], {"rootCause":"client-controlled-fare","businessContext":["bookings","payments"],"destructive":True,"impact":"A caller can book at an arbitrary price, causing direct revenue loss and corrupt fare accounting.","fix":"Recompute fare server-side from holdId and reject requests containing client price fields.","requests":0})
    add("fare-tamper", "Client-controlled fare on booking", "/api/book", "POST", fare)

    def mass(ctx):
        control = _send(ctx, "POST", "/api/book", role="sub-agent", agency="A", body={}, approval_key="mass-assignment", label="Control: sub-agent baseline role")
        attack = _send(ctx, "POST", "/api/book", role="sub-agent", agency="A", body={"role":"admin"}, approval_key="mass-assignment", label="Proof: role field in body")
        reproduced = attack["json"].get("privilegeEscalated") is True and attack["json"].get("effectiveRole") == "admin" and control["json"].get("effectiveRole") != "admin"
        return _result(reproduced, [control["exchange"], attack["exchange"]], {"rootCause":"mass-assignment-role","businessContext":["bookings","supplier-access"],"authBypass":True,"destructive":True,"impact":"Sub-agents can assign themselves admin privileges by adding a role property to the booking payload.","fix":"Use explicit allowlisted DTO fields and derive role exclusively from the authenticated session.","requests":0})
    add("mass-assignment", "Sub-agent privilege escalation via mass assignment", "/api/book", "POST", mass)

    def coupon_reuse(ctx):
        control = _send(ctx, "POST", "/api/pay", role="agent", agency="A", body={"amount":420,"coupon":"SENTINEL50"}, approval_key="coupon-reuse", label="Control: first coupon use")
        attack = _send(ctx, "POST", "/api/pay", role="agent", agency="A", body={"amount":420,"coupon":"SENTINEL50"}, approval_key="coupon-reuse", label="Proof: coupon replay")
        reproduced = attack["json"].get("couponReused") is True
        return _result(reproduced, [control["exchange"], attack["exchange"]], {"rootCause":"coupon-replay","businessContext":["payments","coupons","credit"],"destructive":True,"impact":"A single promotional coupon can be replayed indefinitely, creating uncontrolled discounts.","fix":"Make coupon redemption atomic and single-use per booking with a unique redemption record.","requests":0})
    add("coupon-reuse", "Unlimited coupon reuse", "/api/pay", "POST", coupon_reuse)

    def double_refund(ctx):
        hold = _send(ctx, "POST", "/api/hold", role="agent", agency="A", body={"destination":"BOM"}, label="Control: fresh hold")
        cancel = _send(ctx, "POST", "/api/cancel", role="agent", agency="A", body={"holdId": hold["json"].get("holdId")}, approval_key="double-refund", label="Proof step 1: cancel and refund")
        rebook = _send(ctx, "POST", "/api/book", role="agent", agency="A", body={"holdId": hold["json"].get("holdId")}, approval_key="double-refund", label="Proof step 2: rebook same hold")
        reproduced = cancel["json"].get("refundIssued") is True and rebook["json"].get("doubleRefund") is True
        return _result(reproduced, [cancel["exchange"], rebook["exchange"]], {"rootCause":"cancel-rebook-double-refund","businessContext":["payments","credit","bookings"],"destructive":True,"impact":"Cancelling and rebooking the same hold issues a second refund, enabling cash extraction.","fix":"Bind refunds to immutable payment intents and enforce one refund per successful charge with idempotency keys.","requests":0})
    add("double-refund", "Double refund on cancel-rebook", "/api/cancel", "POST", double_refund)

    add("coupon-stack", "Unauthenticated coupon stacking in v2.1", "/api/v2/coupons/stack", "GET", lambda ctx: _result(
        (a := _send(ctx, "GET", "/api/v2/coupons/stack?count=6", label="Proof: stacked coupons"))["status"] == 200 and a["json"].get("negativeTotal") is True and a["json"].get("unauthenticated") is True,
        [_send(ctx, "GET", "/api/v2/coupons/stack?count=1", label="Control: single coupon")["exchange"], a["exchange"]],
        {"rootCause":"v21-coupon-stack","businessContext":["payments","coupons","credit"],"unauthenticated":True,"destructive":True,"impact":"The newly deployed v2.1 route allows unauthenticated coupon stacking that produces negative totals.","fix":"Gate the route behind auth, cap stacking server-side, and clamp totals to zero.","requests":0}
    ))

    add("debug-exposure", "Shadow debug endpoint leaks PII", "/internal/debug", "GET", lambda ctx: _result(
        (a := _send(ctx, "GET", "/internal/debug", label="Proof: unauthenticated debug data"))["status"] == 200 and bool(a["json"].get("passport")) and bool(a["json"].get("pnr")),
        [_send(ctx, "GET", "/health", label="Control: public health endpoint")["exchange"], a["exchange"]],
        {"rootCause":"shadow-debug-pii","businessContext":["pii"],"unauthenticated":True,"dataExposed":["passport","pnr","email"],"impact":"An undocumented internal route exposes passport, PNR and email fields without authentication.","fix":"Remove the debug route from staging, block /internal at the gateway, and rotate any exposed synthetic fixtures.","requests":0}
    ))

    add("ssrf-supplier", "SSRF via supplier webhook URL", "/api/supplier/webhook", "POST", lambda ctx: _result(
        (a := _send(ctx, "POST", "/api/supplier/webhook", role="agent", agency="A", body={"url": f"{ctx.target}/internal/debug"}, label="Proof: internal URL resolved"))["json"].get("ssrfConfirmed") is True and (c := _send(ctx, "POST", "/api/supplier/webhook", role="agent", agency="A", body={"url":"https://public.example.test/hook"}, label="Control: external URL rejected"))["status"] >= 400,
        [c["exchange"], a["exchange"]],
        {"rootCause":"supplier-webhook-ssrf","businessContext":["supplier-access","pii"],"dataExposed":["internal.debug","passport"],"impact":"A supplier-controlled webhook URL can reach internal staging routes and return their contents.","fix":"Allowlist supplier destinations, block RFC1918/loopback/link-local targets, and disable response-body echo.","requests":0}
    ))

    add("injection-probe", "SQLi probe on search", "/api/search", "POST", lambda ctx: _result(
        bool(__import__("re").search(r"sql|syntax", str((a := _send(ctx, "POST", "/api/search", role="agent", agency="A", body={"origin":"' OR 1=1--"}, label="Probe: benign SQLi marker"))["json"].get("error","")), __import__("re").I)),
        [_send(ctx, "POST", "/api/search", role="agent", agency="A", body={"origin":"DEL"}, label="Control: normal search")["exchange"], a["exchange"]],
        {"rootCause":"search-injection-probe","businessContext":["bookings"],"impact":"No injection signal observed with the safe marker; candidate retained only as a dropped false positive.","fix":"No change required based on this probe; keep parameterized queries.","requests":0}
    ))

    add("excess-data", "Excess data in invoice response", "/api/invoices/:id", "GET", lambda ctx: _result(
        (a := _send(ctx, "GET", "/api/invoices/BK-A-1001", role="agent", agency="A", label="Probe: invoice fields"))["json"].get("internalScore") is not None,
        [_send(ctx, "GET", "/health", label="Control: harmless response")["exchange"], a["exchange"]],
        {"rootCause":"invoice-excess-data","businessContext":["invoices"],"impact":"Invoice payload contains only expected fields in this staging build.","fix":"No change required; continue schema-level response filtering.","requests":0}
    ))

    add("negative-qty", "Negative quantity on booking", "/api/book", "POST", lambda ctx: _result(
        int((a := _send(ctx, "POST", "/api/book", role="agent", agency="A", body={"holdId": _send(ctx, "POST", "/api/hold", role="agent", agency="A", body={}, label="Control: hold")["json"].get("holdId"), "quantity": -1}, approval_key="negative-qty", label="Probe: negative quantity"))["json"].get("fareCharged", 0)) < 0,
        [a["exchange"]],
        {"rootCause":"negative-quantity","businessContext":["bookings"],"impact":"No negative charge observed in the staging adapter.","fix":"No change required; validate quantity > 0 as defence in depth.","requests":0}
    ))

    add("skip-payment", "Skipped payment step", "/api/book", "POST", lambda ctx: _result(
        (a := _send(ctx, "POST", "/api/book", role="agent", agency="A", body={"holdId": _send(ctx, "POST", "/api/hold", role="agent", agency="A", body={}, label="Control: hold")["json"].get("holdId")}, approval_key="skip-payment", label="Probe: book without payment"))["json"].get("paymentSkipped") is True,
        [a["exchange"]],
        {"rootCause":"skipped-payment-step","businessContext":["payments"],"impact":"No skipped-payment state transition observed; booking and payment remain separate staging steps.","fix":"No change required; keep server-side state-machine checks.","requests":0}
    ))

    return {p["key"]: p for p in P}


PROOFS = _proofs()
ALL_PROOFS = list(PROOFS.values())
