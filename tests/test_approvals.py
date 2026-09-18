"""`action: approve`: the call is held, an approver grants a time-limited exception,
the retry goes through, and every step is audited."""

from __future__ import annotations

import asyncio
import json
import time

import mcp.types as types
import yaml

from aggrete import approvals as ap
from aggrete.accumulator import MemoryStore
from aggrete.audit import Audit
from aggrete.lint import lint
from aggrete.policy import Engine
from aggrete.proxy import Proxy

COC = {
    "version": 1,
    "rules": [
        {"rule_id": "COC-HR-900", "title": "Restructuring plan", "owner": "chro@example.com",
         "clause": "The restructuring plan may be read only with CHRO approval.",
         "remediation": "Ask the CHRO to approve a four-hour window.",
         "enforce": [{"layer": "retrieval", "action": "approve", "type": "wall",
                      "domains": ["restructuring-plan"], "allowed_users": ["cfo@example.com"]}],
         "tests": [{"name": "cfo_reads", "expect": "allow", "user": "cfo@example.com",
                    "sequence": [{"domain": "restructuring-plan", "entities": []}]},
                   {"name": "others_are_held", "expect": "hold",
                    "sequence": [{"domain": "restructuring-plan", "entities": []}]}]},
        {"rule_id": "COC-DATA-901", "title": "Company-wide export", "owner": "data-gov@example.com",
         "clause": "A company-wide export needs Data Governance approval.",
         "enforce": [{"layer": "retrieval", "action": "approve", "type": "arg_match",
                      "tools": ["*__export*"], "deny_when": [{"arg": "scope", "in": ["all"]}]}],
         "tests": [{"name": "team_ok", "expect": "allow", "tool": "crm__export", "args": {"scope": "team"}},
                   {"name": "all_held", "expect": "hold", "tool": "crm__export", "args": {"scope": "all"}}]},
    ],
}


def write_coc(tmp_path):
    p = tmp_path / "coc.yaml"; p.write_text(yaml.safe_dump(COC)); return str(p)


def test_engine_holds_instead_of_denying(tmp_path):
    e = Engine(write_coc(tmp_path), MemoryStore())
    d = e.pre_call("bob@example.com", "restructuring-plan")
    assert not d.allow and d.needs_approval and d.rule_id == "COC-HR-900"
    assert d.explain().startswith("Held for approval under COC-HR-900")
    assert e.pre_call("cfo@example.com", "restructuring-plan").allow          # allowed_users skip the gate
    e.grant_purpose("bob@example.com", "COC-HR-900", "approved by chro@example.com", 60)
    d2 = e.pre_call("bob@example.com", "restructuring-plan")
    assert d2.allow and d2.granted_purpose == "approved by chro@example.com"
    a = e.check_args("bob@example.com", "crm__export", {"scope": "all"})
    assert not a.allow and a.needs_approval
    assert e.tool_visible("bob@example.com", "restructuring-plan")            # held tools stay listed


def test_simulate_reports_hold(tmp_path):
    e = Engine(write_coc(tmp_path), MemoryStore())
    results, blocked = e.simulate([{"domain": "restructuring-plan", "entities": []}], "bob@example.com")
    assert blocked == 0 and results[0]["verdict"] == "hold"


def test_lint_accepts_approve_and_hold_tests(tmp_path):
    findings = lint(write_coc(tmp_path), None)
    assert not [f for f in findings if f.level == "error"], findings


def test_store_lifecycle(tmp_path):
    s = ap.Approvals(path=str(tmp_path / "approvals.json"), ttl_s=2, approvers=["sec@example.com"])
    req, created = s.request("bob@example.com", "COC-HR-900", "corp__plan", "restructuring-plan",
                             "clause text", "chro@example.com", "ask")
    assert created and req["status"] == "pending"
    again, created2 = s.request("bob@example.com", "COC-HR-900", "corp__plan_v2", "restructuring-plan")
    assert not created2 and again["id"] == req["id"] and set(again["tools"]) == {"corp__plan", "corp__plan_v2"}
    assert [r["id"] for r in s.pending()] == [req["id"]]
    assert s.can_approve("chro@example.com", req) and s.can_approve("SEC@example.com", req)
    assert not s.can_approve("bob@example.com", req)
    assert s.approve(req["id"], "chro@example.com", ttl_s=1)["status"] == "approved"
    assert s.pending() == [] and len(s.approved_for("bob@example.com")) == 1
    time.sleep(1.1)
    assert s.approved_for("bob@example.com") == []                            # approvals expire
    assert json.loads((tmp_path / "approvals.json").read_text())["requests"][req["id"]]["by"] == "chro@example.com"
    r2, _ = s.request("eve@example.com", "COC-HR-900", "corp__plan", "restructuring-plan")
    assert s.deny(r2["id"], "chro@example.com", "no")["status"] == "denied"


class FakeSession:
    async def call_tool(self, tool, args, **kw):
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps({"plan": "secret"}))])


def make_proxy(tmp_path, wait=0):
    cfg = {"user": "bob@example.com", "_config_dir": str(tmp_path),
           "domains": {"corp__plan": "restructuring-plan", "crm__*": "crm"},
           "approvals": {"ttl": "1h", "wait": wait, "approvers": ["sec@example.com"]},
           "upstreams": {"corp": {"command": "x"}, "crm": {"command": "x"}}}
    p = Proxy(cfg, Engine(write_coc(tmp_path), MemoryStore()), Audit(str(tmp_path / "audit.jsonl")))
    p.sessions["corp"] = FakeSession(); p.sessions["crm"] = FakeSession()
    return p


def call(p, name, args=None):
    return asyncio.run(p.call_tool(None, types.CallToolRequestParams(name=name, arguments=args or {})))


def text(res):
    return res.content[0].text


def test_proxy_holds_then_allows_after_approval(tmp_path):
    p = make_proxy(tmp_path)
    out = text(call(p, "corp__plan"))
    assert "HELD" in out and "Held for approval under COC-HR-900" in out and "aggrete approve" in out
    pending = p.approvals.pending()
    assert len(pending) == 1 and pending[0]["user"] == "bob@example.com"
    rows = [json.loads(l) for l in open(tmp_path / "audit.jsonl")]
    assert rows[-1]["decision"] == "hold" and rows[-1]["rule"] == "COC-HR-900" and rows[-1]["evidence"]["approval"] == pending[0]["id"]
    # same request again: no duplicate, still held
    call(p, "corp__plan"); assert len(p.approvals.pending()) == 1
    # an approver grants it (as the CLI or console would, out of process)
    p.approvals.approve(pending[0]["id"], "chro@example.com")
    out2 = text(call(p, "corp__plan"))
    assert "secret" in out2
    rows = [json.loads(l) for l in open(tmp_path / "audit.jsonl")]
    assert rows[-1]["stage"] == "post" and rows[-1]["decision"] == "allow" and rows[-1]["purpose"] == "approved by chro@example.com"


def test_proxy_holds_arg_match_and_check_reports_hold(tmp_path):
    p = make_proxy(tmp_path)
    assert "HELD" in text(call(p, "crm__export", {"scope": "all"}))
    assert "secret" in text(call(p, "crm__export", {"scope": "team"}))
    chk = text(p._run_check({"tools": [{"tool": "crm__export", "args": {"scope": "all"}}]}))
    assert chk.startswith("Plan check: HELD for approval") and "COC-DATA-901" in chk


def test_short_wait_returns_when_approved_meanwhile(tmp_path):
    p = make_proxy(tmp_path, wait=3)

    async def run():
        async def approve_soon():
            await asyncio.sleep(1.2)
            p.approvals.approve(p.approvals.pending()[0]["id"], "chro@example.com")
        t0 = time.time()
        res, _ = await asyncio.gather(p.call_tool(None, types.CallToolRequestParams(name="corp__plan", arguments={})),
                                      approve_soon())
        return text(res), time.time() - t0
    out, took = asyncio.run(run())
    assert out.startswith("Approved.") and took < 3


def test_cli_lists_and_approves(tmp_path, capsys):
    cfgp = tmp_path / "proxy.config.yaml"; cfgp.write_text("coc: coc.yaml\n")
    p = make_proxy(tmp_path); call(p, "corp__plan")
    rid = p.approvals.pending()[0]["id"]
    assert ap.cli(["approvals", "--config", str(cfgp)]) == 0
    assert rid in capsys.readouterr().out
    assert ap.cli(["approve", rid, "--by", "chro@example.com", "--ttl", "30m", "--config", str(cfgp)]) == 0
    assert "approved" in capsys.readouterr().out
    assert p.approvals.approved_for("bob@example.com")[0]["by"] == "chro@example.com"
    assert "secret" in text(call(p, "corp__plan"))


def test_http_approval_routes(tmp_path):
    from starlette.applications import Starlette
    from starlette.authentication import AuthCredentials, AuthenticationBackend
    from starlette.middleware import Middleware
    from starlette.middleware.authentication import AuthenticationMiddleware
    from starlette.testclient import TestClient
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken
    from aggrete.proxy import approval_routes

    p = make_proxy(tmp_path); call(p, "corp__plan")
    rid = p.approvals.pending()[0]["id"]

    class Backend(AuthenticationBackend):
        async def authenticate(self, conn):
            who = conn.headers.get("x-who")
            if not who:
                return None
            tok = AccessToken(token="t", client_id="c", scopes=["mcp"], expires_at=None, claims={"email": who})
            return AuthCredentials(["authenticated"]), AuthenticatedUser(tok)

    app = Starlette(routes=approval_routes(p, {}), middleware=[Middleware(AuthenticationMiddleware, backend=Backend())])
    c = TestClient(app)
    assert c.get("/approvals").status_code == 401
    assert c.get("/approvals", headers={"x-who": "bob@example.com"}).json()["pending"] == []      # not an approver
    assert c.get("/approvals", headers={"x-who": "chro@example.com"}).json()["pending"][0]["id"] == rid
    assert c.post(f"/approvals/{rid}/approve", headers={"x-who": "bob@example.com"}).status_code == 403
    assert c.post(f"/approvals/nope/approve", headers={"x-who": "chro@example.com"}).status_code == 404
    r = c.post(f"/approvals/{rid}/approve", headers={"x-who": "sec@example.com"}, json={"ttl": "30m", "note": "ok"})
    assert r.status_code == 200 and r.json()["request"]["status"] == "approved" and r.json()["request"]["by"] == "sec@example.com"
    rows = [json.loads(l) for l in open(tmp_path / "audit.jsonl")]
    assert rows[-1]["stage"] == "approval" and rows[-1]["decision"] == "approved" and rows[-1]["evidence"]["by"] == "sec@example.com"
    assert "secret" in text(call(p, "corp__plan"))
