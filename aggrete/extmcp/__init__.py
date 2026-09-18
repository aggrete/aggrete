"""agentgateway ExtMCP adapter: Aggrete as an MCP-aware external policy server.

agentgateway (https://agentgateway.dev) calls an ExtMCP server over gRPC before
and after each MCP method. This serves that contract with the same decider as
`/v1/decide`: deterministic rules, per-person memory, holds, redaction, and one
hash-chained audit row per decision.

    pip install "aggrete[agentgateway]"
    aggrete extmcp --config proxy.config.yaml --port 9001

agentgateway config (standalone):

    policies:
      mcpGuardrails:
        processors:
          - kind: remote
            host: localhost:9001
            failureMode: failClosed
            metadata: {user: jwt.email, tool: mcp.tool.name}
            methods: {"tools/call": full, "tools/list": response}

`metadata.user` is who the policy is evaluated for; without it every call is
refused (there is no one to keep memory about). `metadata.tool` lets the
response phase know which tool produced a result, since the ExtMCP response
message does not carry the request; if it is absent the adapter falls back to
the last tool that person called on that backend.

`ext_mcp.proto` and the generated stubs are vendored from agentgateway
(Apache-2.0, https://github.com/agentgateway/agentgateway).
"""

from __future__ import annotations

import json
import threading

from ..adapters import Decider, _result_text

SEP = "__"


def _qualify(service_names, name: str) -> str:
    """Tool name in the `<upstream>__<tool>` form the policy's domain map uses."""
    if not name or SEP in name or not service_names:
        return name
    return f"{service_names[0]}{SEP}{name}"


def redact_result(proxy, result: dict) -> tuple[dict, dict]:
    """Mask every text item and structuredContent of a CallToolResult dict in
    place of the joined-text shortcut, so the mutated result stays well-formed."""
    from ..redact import redact
    total: dict = {}

    def mask(s: str) -> str:
        masked, counts = redact(s, proxy.redact_rules)
        for k, n in counts.items():
            total[k] = total.get(k, 0) + n
        return masked

    def walk(v):
        if isinstance(v, str):
            return mask(v)
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    out = dict(result)
    out["content"] = [({**c, "text": mask(str(c.get("text", "")))} if isinstance(c, dict) and c.get("type") == "text" else c)
                      for c in (result.get("content") or [])]
    if result.get("structuredContent") is not None:
        out["structuredContent"] = walk(result["structuredContent"])
    return out, total


def build_servicer(proxy, user_key: str = "user", tool_key: str = "tool"):
    from google.protobuf.json_format import MessageToDict
    from . import ext_mcp_pb2 as pb, ext_mcp_pb2_grpc as pbg

    decider = Decider(proxy)
    lock = threading.Lock()
    last_tool: dict[tuple[str, str], str] = {}

    def err(code, reason: str):
        return pb.AuthorizationError(code=code, reason=reason)

    class Servicer(pbg.ExtMcpServicer):
        def CheckRequest(self, request, context):  # noqa: N802 (gRPC naming)
            if request.method != "tools/call":
                return pb.McpRequestResult(**{"pass": pb.Pass()})
            meta = MessageToDict(request.metadata_context) if request.HasField("metadata_context") else {}
            user = str(meta.get(user_key) or "")
            if not user:
                return pb.McpRequestResult(error=err(
                    pb.AuthorizationError.PERMISSION_DENIED,
                    f"Aggrete: no subject. Configure the processor's metadata with `{user_key}: jwt.email` (or jwt.sub)."))
            try:
                params = json.loads(request.mcp_request or b"{}")
            except ValueError:
                return pb.McpRequestResult(error=err(pb.AuthorizationError.INVALID, "params are not JSON"))
            svc = list(request.service_names)
            tool = _qualify(svc, str(params.get("name") or ""))
            with lock:
                out = decider.request(user, tool, params.get("arguments") or {}, "agentgateway")
                last_tool[(user, svc[0] if svc else "")] = tool
            md = {"aggrete_decision": out["decision"]}
            if out.get("rule"):
                md["aggrete_rule"] = out["rule"]
            from google.protobuf.struct_pb2 import Struct
            st = Struct(); st.update(md)
            if out["decision"] == "allow":
                return pb.McpRequestResult(**{"pass": pb.Pass()}, metadata=st)
            if out["decision"] == "rewrite":
                return pb.McpRequestResult(mutated=json.dumps({**params, "arguments": out["arguments"]}).encode(), metadata=st)
            code = (pb.AuthorizationError.RESOURCE_EXHAUSTED if out.get("code") == "RESOURCE_EXHAUSTED"
                    else pb.AuthorizationError.PERMISSION_DENIED)
            return pb.McpRequestResult(error=err(code, out.get("reason", "refused")))

        def CheckResponse(self, request, context):  # noqa: N802
            meta = MessageToDict(request.metadata_context) if request.HasField("metadata_context") else {}
            user = str(meta.get(user_key) or "")
            svc = list(request.service_names)
            try:
                result = json.loads(request.mcp_response or b"{}")
            except ValueError:
                return pb.McpResponseResult(**{"pass": pb.Pass()})
            if request.method == "tools/list":
                tools = result.get("tools")
                if not isinstance(tools, list) or not user:
                    return pb.McpResponseResult(**{"pass": pb.Pass()})
                kept = []
                for t in tools:
                    name = str(t.get("name") or "")
                    cands = [name] if SEP in name or not svc else [f"{s}{SEP}{name}" for s in svc]
                    hidden = False
                    for cand in cands:
                        dom = proxy.domain_for(cand)
                        if not proxy._tool_allowed(cand):
                            hidden = True
                        elif dom != proxy.cfg.get("default_domain", "unclassified") and not proxy.engine.tool_visible(user, dom):
                            hidden = True
                        else:
                            flag = proxy._integrity_flag(cand, t.get("description"), t.get("inputSchema"))
                            hidden = bool(flag and flag["action"] == "block")
                        if hidden and len(cands) == 1:
                            break
                        if not hidden:
                            break
                    if not hidden:
                        kept.append(t)
                if len(kept) == len(tools):
                    return pb.McpResponseResult(**{"pass": pb.Pass()})
                return pb.McpResponseResult(mutated=json.dumps({**result, "tools": kept}).encode())
            if request.method != "tools/call" or not user:
                return pb.McpResponseResult(**{"pass": pb.Pass()})
            tool = _qualify(svc, str(meta.get(tool_key) or "")) or last_tool.get((user, svc[0] if svc else ""), "")
            if not tool:
                return pb.McpResponseResult(**{"pass": pb.Pass()})
            with lock:
                out = decider.response(user, tool, _result_text(result), "agentgateway")
            if out["decision"] == "allow":
                return pb.McpResponseResult(**{"pass": pb.Pass()})
            if out["decision"] == "rewrite":
                masked, _ = redact_result(proxy, result)
                return pb.McpResponseResult(mutated=json.dumps(masked).encode())
            return pb.McpResponseResult(error=err(pb.AuthorizationError.PERMISSION_DENIED, out.get("reason", "refused")))

    return Servicer()


def serve(proxy, host: str = "127.0.0.1", port: int = 9001, user_key: str = "user", tool_key: str = "tool",
          block: bool = True):
    from concurrent import futures
    import grpc
    from . import ext_mcp_pb2_grpc as pbg
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pbg.add_ExtMcpServicer_to_server(build_servicer(proxy, user_key, tool_key), server)
    bound = server.add_insecure_port(f"{host}:{port}")
    server.start()
    if block:
        print(f"aggrete extmcp: serving agentgateway ExtMCP on {host}:{bound}", flush=True)
        server.wait_for_termination()
    return server, bound


def cli(argv: list[str]) -> int:
    import argparse
    from pathlib import Path
    import yaml
    ap = argparse.ArgumentParser(prog="aggrete extmcp", description="agentgateway ExtMCP policy server (gRPC)")
    ap.add_argument("--config", default="proxy.config.yaml")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--user-key", default="user", help="metadata_context key holding the person (default: user)")
    ap.add_argument("--tool-key", default="tool", help="metadata_context key holding mcp.tool.name (default: tool)")
    ns = ap.parse_args(argv[1:])
    try:
        import grpc  # noqa: F401
    except ImportError:
        print('aggrete extmcp needs gRPC: pip install "aggrete[agentgateway]"')
        return 2
    from ..accumulator import MemoryStore
    from ..audit import Audit
    from ..forward import build_forwarder
    from ..metrics import Metrics
    from ..policy import Engine
    from ..proxy import Proxy, build_store
    cfg = yaml.safe_load(Path(ns.config).read_text())
    root = Path(ns.config).parent
    cfg["_config_dir"] = str(root)
    engine = Engine(str(root / cfg.get("coc", "coc.yaml")), build_store(cfg.get("store")) or MemoryStore(),
                    pack_state_path=cfg.get("pack_state"))
    proxy = Proxy(cfg, engine, Audit(cfg.get("audit_log"), forward=build_forwarder(cfg.get("audit_forward")), metrics=Metrics()))
    serve(proxy, ns.host, ns.port, ns.user_key, ns.tool_key)
    return 0
