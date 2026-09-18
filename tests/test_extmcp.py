"""agentgateway ExtMCP adapter over real gRPC."""
from __future__ import annotations

import json
import os

import pytest

grpc = pytest.importorskip("grpc")

from google.protobuf.struct_pb2 import Struct  # noqa: E402

from aggrete import extmcp  # noqa: E402
from aggrete.accumulator import MemoryStore  # noqa: E402
from aggrete.audit import Audit  # noqa: E402
from aggrete.extmcp import ext_mcp_pb2 as pb, ext_mcp_pb2_grpc as pbg  # noqa: E402
from aggrete.policy import Engine  # noqa: E402
from aggrete.proxy import Proxy  # noqa: E402

COC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "coc.yaml")


@pytest.fixture()
def stub(tmp_path):
    cfg = {"user": "x", "_config_dir": str(tmp_path), "audit_log": str(tmp_path / "a.jsonl"), "upstreams": {},
           "domains": {"finance__*": "finance-comp", "hr__*": "hr-personnel", "ops__*": "ops-rota",
                       "corp__restructuring_plan": "restructuring-plan", "crm__*": "crm-customers"},
           "redact": ["email", "ssn"], "scan_inbound": True}
    proxy = Proxy(cfg, Engine(COC, MemoryStore()), Audit(cfg["audit_log"]))
    server, port = extmcp.serve(proxy, "127.0.0.1", 0, block=False)
    ch = grpc.insecure_channel(f"127.0.0.1:{port}")
    yield pbg.ExtMcpStub(ch), proxy
    ch.close(); server.stop(0)


def meta(**kw):
    s = Struct(); s.update(kw); return s


def call(stub, svc, name, args=None, user="bob@example.com"):
    return stub.CheckRequest(pb.McpRequest(service_names=[svc], method="tools/call", metadata_context=meta(user=user),
                                           mcp_request=json.dumps({"name": name, "arguments": args or {}}).encode()))


def respond(stub, svc, tool, payload, user="bob@example.com"):
    res = {"content": [{"type": "text", "text": json.dumps(payload)}]}
    return stub.CheckResponse(pb.McpResponse(service_names=[svc], method="tools/call",
                                             metadata_context=meta(user=user, tool=tool), mcp_response=json.dumps(res).encode()))


def test_combination_is_refused_and_results_are_redacted(stub):
    s, proxy = stub
    people = [{"email": "alice@x.com", "ssn": "123-45-6789"}]
    assert call(s, "finance", "budget_roles").WhichOneof("result") == "pass"
    r = respond(s, "finance", "budget_roles", people)
    assert r.WhichOneof("result") == "mutated"
    masked = json.loads(r.mutated)
    assert "123-45-6789" not in masked["content"][0]["text"] and "[redacted:ssn]" in masked["content"][0]["text"]
    call(s, "hr", "recent_joiners"); respond(s, "hr", "recent_joiners", people)
    third = call(s, "ops", "oncall_draft")
    assert third.WhichOneof("result") == "error" and "COC-HR-004" in third.error.reason
    assert third.error.code == pb.AuthorizationError.PERMISSION_DENIED
    rows = [json.loads(l) for l in open(proxy.cfg["audit_log"])]
    assert rows[-1]["via"] == "agentgateway" and rows[-1]["user"] == "bob@example.com" and rows[-1]["tool"] == "ops__oncall_draft"


def test_no_subject_fails_closed_and_secrets_are_blocked(stub):
    s, _ = stub
    r = s.CheckRequest(pb.McpRequest(service_names=["hr"], method="tools/call",
                                     mcp_request=json.dumps({"name": "recent_joiners"}).encode()))
    assert r.WhichOneof("result") == "error" and "no subject" in r.error.reason
    r = call(s, "crm", "export", {"note": "AKIAIOSFODNN7EXAMPLE"})
    assert r.WhichOneof("result") == "error" and "secret" in r.error.reason
    assert s.CheckRequest(pb.McpRequest(service_names=["hr"], method="prompts/list")).WhichOneof("result") == "pass"


def test_response_falls_back_to_the_last_tool_and_lists_hide_walled_tools(stub):
    s, _ = stub
    call(s, "hr", "leave_balance")
    res = {"content": [{"type": "text", "text": "a@b.co"}]}
    r = s.CheckResponse(pb.McpResponse(service_names=["hr"], method="tools/call", metadata_context=meta(user="bob@example.com"),
                                       mcp_response=json.dumps(res).encode()))
    assert r.WhichOneof("result") == "mutated" and "[redacted:email]" in json.loads(r.mutated)["content"][0]["text"]
    listing = {"tools": [{"name": "restructuring_plan", "description": "plan"}, {"name": "org_chart", "description": "chart"}]}
    r = s.CheckResponse(pb.McpResponse(service_names=["corp"], method="tools/list", metadata_context=meta(user="bob@example.com"),
                                       mcp_response=json.dumps(listing).encode()))
    assert r.WhichOneof("result") == "mutated" and [t["name"] for t in json.loads(r.mutated)["tools"]] == ["org_chart"]
    r = s.CheckResponse(pb.McpResponse(service_names=["corp"], method="tools/list", metadata_context=meta(user="cfo@example.com"),
                                       mcp_response=json.dumps(listing).encode()))
    assert r.WhichOneof("result") == "pass"
