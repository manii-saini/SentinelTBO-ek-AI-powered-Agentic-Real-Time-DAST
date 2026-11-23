from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

from .config import TARGET_HOST


@dataclass
class Hold:
    id: str
    agency: str
    fare: int
    route: str
    pnr: str
    cancelled: bool = False


@dataclass
class Booking:
    id: str
    agency: str
    holdId: str
    fare: int
    status: str
    pnr: str
    passenger: str


class SyntheticTravelPlatform:
    """In-process synthetic staging target. No network listeners, no real systems."""

    def __init__(self):
        self.host = TARGET_HOST
        self.identities = [
            {"agency": "A", "role": "agent", "token": "test-agent-a"},
            {"agency": "A", "role": "sub-agent", "token": "test-subagent-a"},
            {"agency": "A", "role": "admin", "token": "test-admin-a"},
            {"agency": "B", "role": "agent", "token": "test-agent-b"},
            {"agency": "B", "role": "sub-agent", "token": "test-subagent-b"},
            {"agency": "B", "role": "admin", "token": "test-admin-b"},
        ]
        self.reset()

    def reset(self):
        self.holds = [Hold("HOLD-A-1001", "A", 420, "DEL-BOM", "PNRA1001"), Hold("HOLD-B-2001", "B", 690, "BLR-GOI", "PNRB2001")]
        self.bookings = [Booking("BK-A-1001", "A", "HOLD-A-1001", 420, "CONFIRMED", "PNRA1001", "Synthetic Passenger A"), Booking("BK-B-2001", "B", "HOLD-B-2001", 690, "CONFIRMED", "PNRB2001", "Synthetic Passenger B")]
        self.refunds: dict[str, int] = {}
        self.coupons_used: dict[str, int] = {}
        self.patched: set[str] = set()
        self.v2_deployed = False
        self.deploy_version = "v2.0"
        self.injection_probe_hits = 0
        self.traffic: list[dict[str, Any]] = []
        day = 86_400_000
        now = int(time.time() * 1000)
        seeded = [("POST", "/api/search"), ("POST", "/api/hold"), ("POST", "/api/book"), ("POST", "/api/pay"), ("POST", "/api/cancel"), ("GET", "/api/bookings/mine"), ("GET", "/api/invoices/BK-A-1001")]
        for d in range(90):
            for method, path in seeded:
                hits = (7 if path == "/api/search" else 1 + (d % 3)) if d < 30 else 1 + (d % 2)
                for i in range(hits):
                    self.traffic.append({"method": method, "path": path, "at": now - d * day - i * 60_000, "role": "agent"})

    def _identity(self, headers: dict[str, Any]) -> dict[str, Any] | None:
        raw = str(headers.get("authorization") or headers.get("Authorization") or "").replace("Bearer ", "").strip()
        return next((i for i in self.identities if i["token"] == raw), None)

    def _json(self, body: str | None) -> dict[str, Any]:
        if not body:
            return {}
        try:
            v = json.loads(body)
            return v if isinstance(v, dict) else {}
        except Exception:
            return {}

    def handle(self, req: dict[str, Any]) -> dict[str, Any]:
        method = str(req.get("method", "GET")).upper()
        url = req.get("url", "")
        u = urlparse(url)
        path = u.path
        headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
        body = self._json(req.get("body"))
        query = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(u.query).items()}
        ident = self._identity(headers)

        # record non-admin synthetic traffic for inventory diffs
        if not path.startswith("/__admin") and path != "/health" and headers.get("x-sentinel-synthetic", "").lower() != "true":
            self.traffic.append({"method": method, "path": path, "at": int(time.time()*1000), "role": (ident or {}).get("role", "anonymous")})

        if path == "/health":
            return self._ok({"ok": True, "service": "mock-travel-platform", "version": self.deploy_version, "syntheticOnly": True})
        if path == "/__admin/deploy" and method == "POST":
            self.v2_deployed = True; self.deploy_version = "v2.1"
            return self._ok({"deployed": "v2.1", "version": self.deploy_version, "newRoute": "GET /api/v2/coupons/stack"})
        if path == "/__admin/patch" and method == "POST":
            for k in body.get("keys", []) or []: self.patched.add(str(k))
            return self._ok({"patched": sorted(self.patched)})
        if path == "/__admin/reset" and method == "POST":
            self.reset(); return self._ok({"ok": True})
        if path == "/__admin/state":
            return self._ok({"version": self.deploy_version, "v2Deployed": self.v2_deployed, "patched": sorted(self.patched)})
        if path == "/__admin/traffic":
            days = int(query.get("window", 30))
            since = int(time.time()*1000) - days * 86_400_000
            rows = [t for t in self.traffic if t["at"] >= since]
            return self._ok(rows)
        if path == "/__admin/bundle":
            routes = ["/api/search","/api/hold","/api/book","/api/pay","/api/cancel","/api/bookings/mine","/api/invoices/:id","/api/supplier/webhook"]
            if self.v2_deployed: routes.append("/api/v2/coupons/stack")
            src = f'const ROUTES = {json.dumps(routes)};\nexport {{ ROUTES }};\n'
            return {"status": 200, "body": src}

        # app routes
        if path == "/api/search" and method == "POST":
            if not ident: return self._err(401, "Synthetic test credential required")
            if "or 1=1" in str(body.get("origin", "")).lower() and self.injection_probe_hits == 0:
                self.injection_probe_hits += 1
                return self._err(500, "SQL syntax artifact in staging query log (flaky fixture)")
            return self._ok({"results": [{"flightId": "F-101", "route": f"{body.get('origin','DEL')}-{body.get('destination','BOM')}", "fare": 420, "currency": "INR", "serverControlled": True}], "flow": "search"})
        if path == "/api/hold" and method == "POST":
            if not ident: return self._err(401, "Synthetic test credential required")
            hold = next((h for h in self.holds if h.agency == ident["agency"]), self.holds[0])
            return self._ok({"holdId": hold.id, "fare": hold.fare, "pnr": hold.pnr, "expiresIn": 600, "flow": "hold"})
        if path == "/api/book" and method == "POST":
            if not ident: return self._err(401, "Synthetic test credential required")
            hold = next((h for h in self.holds if h.id == body.get("holdId")), next((h for h in self.holds if h.agency == ident["agency"]), self.holds[0]))
            escalated = "mass-assignment" not in self.patched and str(body.get("role", "")).lower() == "admin" and ident["role"] != "admin"
            effective_role = "admin" if escalated else ident["role"]
            tampered = "fare-tamper" not in self.patched and "fare" in body and int(body.get("fare")) != hold.fare
            fare_charged = int(body.get("fare")) if tampered else hold.fare
            refund_issued = False; double_refund = False
            if hold.cancelled:
                count = self.refunds.get(hold.id, 1) + 1
                self.refunds[hold.id] = count
                refund_issued = True
                double_refund = "double-refund" not in self.patched and count >= 2
            booking = Booking(f"BK-{ident['agency']}-{int(time.time()*1000):x}".upper(), ident["agency"], hold.id, fare_charged, "CONFIRMED", hold.pnr, f"Synthetic Passenger {ident['agency']}")
            self.bookings.append(booking)
            return self._ok({"bookingId": booking.id, "flow": "book", "fareCharged": fare_charged, "serverFare": hold.fare, "priceTampered": tampered, "effectiveRole": effective_role, "privilegeEscalated": escalated, "refundIssued": refund_issued, "doubleRefund": double_refund, "refundCount": self.refunds.get(hold.id, 0)})
        if path == "/api/bookings/mine" and method == "GET":
            if not ident: return self._err(401, "Synthetic test credential required")
            return self._ok({"bookings": [b.__dict__ for b in self.bookings if b.agency == ident["agency"]][-5:], "agency": ident["agency"], "control": True})
        if path.startswith("/api/bookings/") and method == "GET":
            if not ident: return self._err(401, "Synthetic test credential required")
            bid = path.rsplit("/", 1)[-1]
            found = next((b for b in self.bookings if b.id == bid), None)
            if not found: return self._err(404, "booking not found")
            cross = found.agency != ident["agency"]
            if cross and "bola" in self.patched: return self._err(403, "Cross-agency access denied (policy enforced)")
            return self._ok({**found.__dict__, "crossAgency": cross, "agencyMatch": not cross, "authorizationBypassed": cross and "bola" not in self.patched})
        if path == "/api/pay" and method == "POST":
            if not ident: return self._err(401, "Synthetic test credential required")
            coupon_reused = False
            if body.get("coupon"):
                key = f"{ident['agency']}:{body['coupon']}"
                used = self.coupons_used.get(key, 0) + 1
                self.coupons_used[key] = used
                coupon_reused = "coupon-reuse" not in self.patched and used > 1
            return self._ok({"paid": True, "amount": int(body.get("amount", 420)), "couponReused": coupon_reused, "discountCount": self.coupons_used.get(f"{ident['agency']}:{body.get('coupon')}", 0), "flow": "pay"})
        if path == "/api/cancel" and method == "POST":
            if not ident: return self._err(401, "Synthetic test credential required")
            hold = next((h for h in self.holds if h.id == body.get("holdId")), self.holds[0])
            hold.cancelled = True
            count = self.refunds.get(hold.id, 0) + 1
            self.refunds[hold.id] = count
            return self._ok({"cancelled": True, "refundIssued": True, "refundCount": count, "holdId": hold.id, "flow": "cancel"})
        if path.startswith("/api/invoices/") and method == "GET":
            if not ident: return self._err(401, "Synthetic test credential required")
            bid = path.rsplit("/", 1)[-1]
            b = next((x for x in self.bookings if x.id == bid), None)
            if not b: return self._err(404, "invoice not found")
            return self._ok({"invoiceId": f"INV-{b.id}", "amount": b.fare, "pnr": b.pnr, "agency": b.agency})
        if path == "/api/supplier/webhook" and method == "POST":
            if not ident: return self._err(401, "Synthetic test credential required")
            target = str(body.get("url", ""))
            try:
                pu = urlparse(target)
            except Exception:
                return self._err(400, "invalid url")
            safe_host = pu.netloc in {self.host, f"127.0.0.1:4000", "localhost:4000"}
            if not safe_host or not pu.path.startswith(("/internal/", "/v1/")):
                return self._err(400, "Only internal staging URLs are resolved by this demo adapter")
            if "ssrf" in self.patched:
                return self._err(403, "Supplier URL allowlist enforced")
            inner = self.handle({"method": "GET", "url": f"http://{self.host}{pu.path}", "headers": {"x-sentinel-synthetic": "true", "authorization": f"Bearer {ident['token']}"}, "body": ""})
            return self._ok({"fetched": True, "target": pu.path, "ssrfConfirmed": True, "snippet": inner.get("body", "")[:240]})
        if path == "/v1/bookings" and method == "GET":
            if "zombie" in self.patched: return self._err(404, "legacy API decommissioned")
            return self._ok({"legacy": True, "bookings": [b.__dict__ for b in self.bookings[:3]], "exposedAgencies": ["A", "B"]})
        if path == "/internal/debug" and method == "GET":
            if "shadow" in self.patched: return self._err(404, "not found")
            return self._ok({"passport": "A1234567", "pnr": "PNRA1001", "email": "synthetic.passenger@travel.test", "env": "staging", "debug": True, "agencies": ["A", "B"]})
        if path == "/api/v2/coupons/stack" and method == "GET":
            if not self.v2_deployed: return self._err(404, "endpoint not deployed")
            count = int(query.get("count", 3))
            return self._ok({"stacked": count, "totalDiscount": count * 500, "negativeTotal": "coupon-stack" not in self.patched, "unauthenticated": True, "newInVersion": "v2.1"})

        return self._err(404, f"not found: {path}")

    def _ok(self, payload: Any) -> dict[str, Any]:
        return {"status": 200, "body": json.dumps(payload)}

    def _err(self, status: int, message: str) -> dict[str, Any]:
        return {"status": status, "body": json.dumps({"error": message})}
