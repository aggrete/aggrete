"""Agents are first-class subjects: every audit row names the agent as well as
the person it acted for; memory stays keyed to the person."""
from __future__ import annotations

import asyncio
import json
import os

import mcp.types as types
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette
from starlette.testclient import TestClient

from aggrete import adapters
from aggrete.accumulator import MemoryStore
from aggrete.audit import Audit
from aggrete.auth import agent_for
from aggrete.policy import Engine
from aggrete.proxy import Proxy

COC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "coc.yaml")


def tok(**claims):
    return AccessToken(token="t", client_id=claims.pop("_client", "dcr-8f2a"), scopes=["mcp"], expires_at=None, claims=claims)


def test_agent_derivation_order():
    assert agent_for(tok(email="a@x", act={"sub": "research-agent"}, azp="claude")) == "research-agent"   # RFC 8693 actor wins
    assert agent_for(tok(email="a@x", azp="claude-desktop")) == "claude-desktop"
    assert agent_for(tok(email="a@x")) == "dcr-8f2a"                                                        # falls back to the client id
    assert agent_for(tok(email="a@x"), labels={"dcr-8f2a": "Cursor"}) == "Cursor"
    assert agent_for(tok(email="a@x", bot="ops-bot", azp="claude"), claim="bot") == "ops-bot"
    assert agent_for(tok(email="a@x", _client="static")) is None


class Up:
    async def call_tool(self, tool, args, **kw):
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps({"email": "p@x.co"}))])


def test_rows_carry_the_agent_and_memory_stays_with_the_person(tmp_path):
    cfg = {"user": "maya@example.com", "agent": "planning-agent", "_config_dir": str(tmp_path), "audit_log": str(tmp_path / "a.jsonl"),
           "domains": {"finance__*": "finance-comp", "hr__*": "hr-personnel", "ops__*": "ops-rota"},
           "upstreams": {u: {"command": "x"} for u in ("finance", "hr", "ops")}}
    p = Proxy(cfg, Engine(COC, MemoryStore()), Audit(cfg["audit_log"]))
    for u in cfg["upstreams"]:
        p.sessions[u] = Up()
    call = lambda n: asyncio.run(p.call_tool(None, types.CallToolRequestParams(name=n, arguments={})))
    call("finance__budget_roles")
    p.static_agent = "reporting-agent"            # a different agent, same person
    call("hr__recent_joiners")
    out = call("ops__oncall_draft").content[0].text
    assert "COC-HR-004" in out                     # two agents, one person: the combination still forms
    rows = [json.loads(l) for l in open(cfg["audit_log"])]
    assert [r["agent"] for r in rows] == ["planning-agent", "reporting-agent", "reporting-agent"]
    assert {r["user"] for r in rows} == {"maya@example.com"}


def test_adapter_accepts_an_agent(tmp_path):
    cfg = {"user": "x", "_config_dir": str(tmp_path), "audit_log": str(tmp_path / "a.jsonl"), "upstreams": {},
           "domains": {"hr__*": "hr-personnel"}, "adapters": {"token": "gw"}, "agent_labels": {"agt-77": "Onboarding agent"}}
    p = Proxy(cfg, Engine(COC, MemoryStore()), Audit(cfg["audit_log"]))
    c = TestClient(Starlette(routes=adapters.adapter_routes(p, cfg)))
    r = c.post("/v1/decide", headers={"Authorization": "Bearer gw"},
               json={"subject": {"id": "bob@example.com"}, "agent": {"id": "agt-77"}, "tool": "hr__recent_joiners"})
    assert r.json()["decision"] == "allow"
    c.post("/v1/decide", headers={"Authorization": "Bearer gw"},
           json={"phase": "response", "subject": {"id": "bob@example.com"}, "agent": "agt-77", "tool": "hr__recent_joiners", "result": "a@b.co"})
    rows = [json.loads(l) for l in open(cfg["audit_log"])]
    assert rows and all(r["agent"] == "Onboarding agent" and r["user"] == "bob@example.com" for r in rows)
