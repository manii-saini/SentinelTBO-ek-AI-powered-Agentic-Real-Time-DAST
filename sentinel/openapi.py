from __future__ import annotations

from typing import Any
import re


def generate_openapi(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for e in endpoints:
        key = re.sub(r":([A-Za-z0-9_]+)", r"{\1}", e["path"])
        paths.setdefault(key, {})
        params = []
        for p in e.get("params", []):
            if p.get("location") == "path":
                params.append({"name": p["name"], "in": "path", "required": True, "schema": {"type": "number" if p.get("type") == "number" else "string"}})
            if p.get("location") == "query":
                params.append({"name": p["name"], "in": "query", "required": False, "schema": {"type": "number" if p.get("type") == "number" else "string"}})
        op = {
            "operationId": f"{e['method'].lower()}_{re.sub(r'[^a-zA-Z0-9]', '_', key)}",
            "summary": f"{e.get('flow')} flow · {e.get('status')} endpoint" + (f" · {e['vulnerableToVersion']}" if e.get("vulnerableToVersion") else ""),
            "tags": [e.get("flow", "unknown"), e.get("status", "active")],
            "security": [{"syntheticBearer": []}] if e.get("authRequired") else [],
            "responses": {"200": {"description": "Synthetic staging response"}},
        }
        if params: op["parameters"] = params
        body_params = [p for p in e.get("params", []) if p.get("location") == "body"]
        if body_params:
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "properties": {p["name"]: {"type": "number" if p.get("type") == "number" else "string"} for p in body_params}}}}}
        paths[key][e["method"].lower()] = op
    return {
        "openapi": "3.0.3",
        "info": {"title": "SentinelTBO inferred staging API", "version": "1.0.0-inferred", "description": "Generated from recon evidence. Synthetic staging only."},
        "servers": [{"url": "http://synthetic.travel.internal", "description": "in-process synthetic travel platform"}],
        "components": {"securitySchemes": {"syntheticBearer": {"type": "http", "scheme": "bearer", "description": "Test-account tokens only"}}},
        "paths": paths,
    }
