"""Adapter mode: the same decisions over HTTP for gateways (native, AuthZEN,
Docker interceptors) and as a ContextForge external plugin."""
from __future__ import annotations

import json
import os

from starlette.applications import Starlette
from starlette.testclient import TestClient

from aggrete import adapters
from aggrete.accumulator import MemoryStore
from aggrete.audit import Audit
from aggrete.policy import Engine
from aggrete.proxy import Proxy

COC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "coc.yaml")


def make(tmp_path):
    cfg = {"user": "static@example.com", "_config_dir": str(tmp_path), "audit_log": str(tmp_path / "a.jsonl"),
           "domains": {"finance__*": "finance-comp", "hr__*": "hr-personnel", "ops__*": "ops-rota", "crm__*": "crm-customers",
                       "corp__read_public_post": "untrusted-web", "corp__post_note": "shared-notes"},
           "redact": ["email", "ssn"], "scan_inbound": True, "upstreams": {},
           "adapters": {"token": "gw-secret"}}
    p = Proxy(cfg, Engine(COC, MemoryStore()), Audit(cfg["audit_log"]))
    return TestClient(Starlette(routes=adapters.adapter_routes(p, cfg))), p


H = {"Authorization": "Bearer gw-secret"}


def test_decide_request_phase_combination_and_hold(tmp_path):
    c, p = make(tmp_path)
    assert c.post("/v1/decide", json={"subject": {"id": "bob@example.com"}, "tool": "hr__x"}).status_code == 401
    body = {"subject": {"id": "bob@example.com"}, "tool": "finance__budget_roles", "arguments": {}}
    assert c.post("/v1/decide", json=body, headers=H).json()["decision"] == "allow"
    # response phase records the people and redacts
    r = c.post("/v1/decide", json={"phase": "response", "subject": {"id": "bob@example.com"}, "tool": "finance__budget_roles",
                                   "result": {"content": [{"type": "text", "text": json.dumps([{"email": "alice@x.com", "ssn": "123-45-6789"}])}]}}, headers=H).json()
    assert r["decision"] == "rewrite" and "123-45-6789" not in r["result"] and r["redacted"]["ssn"] == 1
    c.post("/v1/decide", json={"phase": "response", "subject": {"id": "bob@example.com"}, "tool": "hr__recent_joiners",
                               "result": {"content": [{"type": "text", "text": json.dumps([{"email": "alice@x.com"}])}]}}, headers=H)
    r = c.post("/v1/decide", json={"subject": {"id": "bob@example.com"}, "tool": "ops__oncall_draft"}, headers=H).json()
    assert r["decision"] == "deny" and r["rule"] == "COC-HR-004" and r["code"] == "PERMISSION_DENIED"
    r = c.post("/v1/decide", json={"subject": {"id": "bob@example.com"}, "tool": "crm__export", "arguments": {"note": "AKIAIOSFODNN7EXAMPLE"}}, headers=H).json()
    assert r["decision"] == "deny" and r["rule"] == "inbound-secret"
    rows = [json.loads(l) for l in open(p.cfg["audit_log"])]
    assert rows[-1]["via"] == "decide" and rows[-1]["user"] == "bob@example.com"


def test_authzen_mapping(tmp_path):
    c, _ = make(tmp_path)
    body = {"subject": {"type": "user", "id": "eve@example.com"}, "action": {"name": "tools/call"},
            "resource": {"type": "tool", "id": "crm__export", "properties": {"arguments": {"scope": "all"}}}}
    r = c.post("/access/v1/evaluation", json=body, headers=H).json()
    assert r["decision"] is False and r["context"]["rule"] == "COC-DATA-010"
    body["resource"]["properties"]["arguments"] = {"scope": "team"}
    assert c.post("/access/v1/evaluation", json=body, headers=H).json()["decision"] is True


def test_docker_interceptors(tmp_path):
    c, _ = make(tmp_path)
    hdr = {**H, "X-Aggrete-User": "bob@example.com"}
    r = c.post("/adapters/docker/before", json={"params": {"name": "corp__read_public_post", "arguments": {}}}, headers=hdr)
    assert r.status_code == 200 and r.content == b""
    c.post("/adapters/docker/after?tool=corp__read_public_post", json={"content": [{"type": "text", "text": "hello"}]}, headers=hdr)
    r = c.post("/adapters/docker/before", json={"params": {"name": "corp__post_note", "arguments": {"text": "x"}}}, headers=hdr)
    j = r.json()
    assert j["isError"] is True and "COC-SEC-002" in j["content"][0]["text"]
    r = c.post("/adapters/docker/after?tool=hr__leave_balance", json={"content": [{"type": "text", "text": "ssn 123-45-6789 for a@b.co"}]}, headers=hdr).json()
    assert "[redacted:ssn]" in r["content"][0]["text"]


def test_contextforge_hooks(tmp_path):
    _, p = make(tmp_path)
    d = adapters.Decider(p)
    ctx = {"global_context": {"user": "eve@example.com", "request_id": "r1"}}
    ok = adapters.contextforge_hook(d, "tool_pre_invoke", {"name": "crm__export", "args": {"scope": "team"}}, ctx)
    assert ok["continue_processing"] is True
    no = adapters.contextforge_hook(d, "tool_pre_invoke", {"name": "crm__export", "args": {"scope": "all"}}, ctx)
    assert no["continue_processing"] is False and no["violation"]["reason"] == "COC-DATA-010"
    post = adapters.contextforge_hook(d, "tool_post_invoke", {"name": "hr__leave_balance", "result": "a@b.co owes 123-45-6789"}, ctx)
    assert post["continue_processing"] is True and "[redacted:ssn]" in post["modified_payload"]["result"]
    assert adapters.plugin_config()["hooks"] == ["tool_pre_invoke", "tool_post_invoke"]
