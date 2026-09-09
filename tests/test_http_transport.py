"""Aggrete served over streamable HTTP: identity comes from the bearer token."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx2 as httpx
import pytest
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

ROOT = Path(__file__).resolve().parent.parent
TOKENS = {"tok-alice": {"subject": "alice@corp.example"}, "tok-bob": {"subject": "bob@corp.example"}}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


@pytest.fixture
def proxy_http(tmp_path):
    cfg = yaml.safe_load((ROOT / "proxy.config.yaml").read_text())
    cfg["coc"] = str(ROOT / "coc.yaml")
    cfg["audit_log"] = str(tmp_path / "audit.jsonl")
    cfg["user"] = "config-user-must-not-appear@example.com"
    cfg["auth"] = {"mode": "static", "tokens": TOKENS}
    path = tmp_path / "proxy.config.yaml"; path.write_text(yaml.safe_dump(cfg))
    port = free_port()
    proc = subprocess.Popen([sys.executable, "-m", "aggrete.proxy", "--config", str(path),
                             "--transport", "streamable-http", "--port", str(port)],
                            cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0: break
            time.sleep(0.1)
        else:
            raise RuntimeError("proxy never listened")
        yield f"http://127.0.0.1:{port}/mcp", tmp_path / "audit.jsonl"
    finally:
        proc.terminate(); proc.wait(timeout=5)


async def session_for(url, token):
    stack = contextlib.AsyncExitStack()
    client = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    await stack.enter_async_context(client)
    read, write = await stack.enter_async_context(streamable_http_client(url, http_client=client))
    s = await stack.enter_async_context(ClientSession(read, write))
    await s.initialize()
    return stack, s


async def four_turns(url, token):
    stack, s = await session_for(url, token)
    try:
        for tool, args in [("finance__headcount_plan", {"team": "platform"}),
                           ("finance__budget_roles", {"team": "platform"}),
                           ("hr__recent_joiners", {"team": "platform"}),
                           ("ops__oncall_draft", {"team": "platform", "quarter": "Q4"})]:
            last = await s.call_tool(tool, args)
        return last.content[0].text
    finally:
        await stack.aclose()


def test_missing_token_is_401(proxy_http):
    url, _ = proxy_http
    r = httpx.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                   headers={"Accept": "application/json, text/event-stream"})
    assert r.status_code == 401
    assert "Bearer" in r.headers.get("www-authenticate", "")


def test_identity_comes_from_token_not_config(proxy_http):
    url, audit = proxy_http
    text = asyncio.run(four_turns(url, "tok-alice"))
    assert "COC-HR-004" in text
    rows = [json.loads(l) for l in audit.read_text().splitlines()]
    users = {r["user"] for r in rows}
    assert users == {"alice@corp.example"}


def test_state_is_per_token_subject(proxy_http):
    url, audit = proxy_http
    asyncio.run(four_turns(url, "tok-alice"))          # alice ends up denied
    stack_bob = asyncio.run(_bob_first_three(url))       # bob, same turns, fresh state
    rows = [json.loads(l) for l in audit.read_text().splitlines()]
    bob = [r for r in rows if r["user"] == "bob@corp.example"]
    assert bob and all(r["decision"] == "allow" for r in bob)


async def _bob_first_three(url):
    stack, s = await session_for(url, "tok-bob")
    try:
        for tool in ["finance__headcount_plan", "finance__budget_roles", "hr__recent_joiners"]:
            await s.call_tool(tool, {"team": "platform"})
    finally:
        await stack.aclose()


def test_anonymous_mode_builds_app_without_auth():
    from mcp.server.lowlevel import Server
    from starlette.applications import Starlette
    from aggrete.proxy import build_http_app
    async def _noop(stack):
        return None
    cfg = {"user": "guest@demo", "auth": {"mode": "anonymous"}, "http": {"allowed_hosts": ["try.example"]}}
    app = build_http_app(Server("t"), cfg, _noop)
    assert isinstance(app, Starlette)
    assert "/mcp" in [getattr(r, "path", None) for r in app.routes]
    assert app.user_middleware == []          # anonymous: no bearer/auth middleware


def test_http_without_auth_block_is_rejected():
    from mcp.server.lowlevel import Server
    from aggrete.proxy import build_http_app
    async def _noop(stack):
        return None
    with pytest.raises(SystemExit):
        build_http_app(Server("t"), {"user": "x"}, _noop)
