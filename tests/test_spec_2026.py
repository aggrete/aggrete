"""MCP 2026-07-28: multi-round-trip passthrough, tool metadata preserved, private list caching."""
from __future__ import annotations

import asyncio
import json
import os

import mcp.types as types

from aggrete.accumulator import MemoryStore
from aggrete.audit import Audit
from aggrete.forward import ocsf_event
from aggrete.policy import Engine
from aggrete.proxy import Proxy

COC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "coc.yaml")


class Upstream:
    def __init__(self):
        self.seen = []

    async def list_tools(self):
        return types.ListToolsResult(tools=[types.Tool(
            name="oncall_draft", title="Draft", description="d", inputSchema={"type": "object"},
            outputSchema={"type": "object", "properties": {"result": {"type": "string"}}},
            annotations=types.ToolAnnotations(readOnlyHint=True), _meta={"x": 1})])

    async def call_tool(self, tool, args, **kw):
        self.seen.append(kw)
        if not kw.get("input_responses"):
            return types.InputRequiredResult(
                input_requests={"q": {"method": "elicitation/create",
                                      "params": {"message": "which team?", "mode": "form",
                                                 "requestedSchema": {"type": "object", "properties": {"team": {"type": "string"}}}}}},
                request_state="opaque-1")
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps({"team": "platform", "email": "e@x.co"}))],
                                    structuredContent={"result": "e@x.co"})


def make(tmp_path):
    cfg = {"user": "u@example.com", "_config_dir": str(tmp_path), "audit_log": str(tmp_path / "a.jsonl"),
           "domains": {"ops__*": "ops-rota"}, "redact": ["email"], "upstreams": {"ops": {"command": "x"}}}
    p = Proxy(cfg, Engine(COC, MemoryStore()), Audit(cfg["audit_log"]))
    up = Upstream(); p.sessions["ops"] = up
    return p, up


def test_list_preserves_metadata_and_is_private(tmp_path):
    p, _ = make(tmp_path)
    res = asyncio.run(p.list_tools(None, None))
    t = next(x for x in res.tools if x.name == "ops__oncall_draft")
    assert t.annotations.read_only_hint is True and t.meta == {"x": 1} and t.output_schema is None
    assert res.cache_scope == "private" and res.ttl_ms == 0


def test_mrtr_passthrough(tmp_path):
    p, up = make(tmp_path)
    first = asyncio.run(p.call_tool(None, types.CallToolRequestParams(name="ops__oncall_draft", arguments={})))
    assert isinstance(first, types.InputRequiredResult) and first.request_state == "opaque-1"
    assert up.seen[0]["allow_input_required"] is True
    rows = [json.loads(l) for l in open(p.cfg["audit_log"])]
    assert rows[-1]["decision"] == "input_required"
    retry = types.CallToolRequestParams(name="ops__oncall_draft", arguments={},
                                        input_responses={"q": {"action": "accept", "content": {"team": "platform"}}},
                                        request_state="opaque-1")
    second = asyncio.run(p.call_tool(None, retry))
    assert isinstance(second, types.CallToolResult)
    assert up.seen[1]["request_state"] == "opaque-1" and "q" in up.seen[1]["input_responses"]
    assert "[redacted:email]" in second.content[0].text and second.structured_content["result"] == "[redacted:email]"


def test_ocsf_mapping():
    ev = ocsf_event({"ts": 1.0, "user": "u@x", "tool": "finance__pay_band", "domain": "pay", "stage": "pre",
                     "write": False, "decision": "deny", "rule": "COC-HR-031", "evidence": {"k": 10}, "hash": "abc"})
    assert ev["class_uid"] == 6003 and ev["type_uid"] == 600302 and ev["disposition_id"] == 2 and ev["action_id"] == 2
    assert ev["policy"]["uid"] == "COC-HR-031" and ev["resources"][0]["uid"] == "finance__pay_band"
    assert ev["api"]["service"]["name"] == "finance" and ev["metadata"]["uid"] == "abc"
    held = ocsf_event({"ts": 1.0, "user": "u", "tool": "a__b", "stage": "pre", "decision": "hold", "rule": "R", "evidence": {"approval": "x1"}})
    assert held["disposition_id"] == 14 and held["status_detail"].endswith("x1")
    red = ocsf_event({"ts": 1.0, "user": "u", "tool": "a__b", "stage": "post", "decision": "allow", "redacted": {"email": 2}})
    assert red["action_id"] == 4 and red["disposition"] == "Corrected"
