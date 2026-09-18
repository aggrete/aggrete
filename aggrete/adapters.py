"""Adapter mode: run the policy engine inside a gateway you already have.

The proxy can serve as a decision point instead of (or as well as) a proxy.
Point a gateway's hook at these endpoints and it gets the same deterministic,
stateful decisions, the same redaction and the same audit rows, without
inserting a second hop in the MCP path.

    POST /v1/decide                    the native shape (request and response phases)
    POST /access/v1/evaluation         OpenID AuthZEN 1.0 (allow/deny only)
    POST /adapters/docker/before       Docker MCP Gateway `--interceptor before:http:<url>`
    POST /adapters/docker/after        Docker MCP Gateway `--interceptor after:http:<url>`
    python -m aggrete.adapters --config proxy.config.yaml
                                       IBM ContextForge external plugin (MCP server exposing
                                       get_plugin_config / invoke_hook)

Identity comes from the gateway (a `subject.id`, an `X-Aggrete-User` header, or
the ContextForge context), so run these behind the gateway's own auth and set
`adapters: {token: "${ADAPTER_TOKEN}"}` so only the gateway can call them.
"""

from __future__ import annotations

import json
import os
import time

import mcp.types as types

from .entities import extract
from .redact import redact


class Decider:
    """The proxy's call path, minus the upstream call, keyed by an explicit subject."""

    def __init__(self, proxy):
        self.p = proxy

    def _refusal(self, decision: str, code: str, reason: str, **extra) -> dict:
        return {"decision": decision, "code": code, "reason": reason, **extra}

    def request(self, subject: str, tool: str, arguments: dict | None, gateway: str = "") -> dict:
        """Everything the proxy decides before it would contact the upstream."""
        p = self.p
        args = dict(arguments or {})
        domain = p.domain_for(tool)
        is_write = p._is_write(tool)
        base = {"tool": tool, "domain": domain, "write": is_write, "subject": subject}
        if p.rate_limiter is not None:
            ok, count = p.rate_limiter.allow(subject)
            if not ok:
                p.audit.emit(user=subject, tool=tool, domain=domain, stage="pre", write=is_write, via=gateway or "adapter",
                             decision="deny", rule="rate-limit", evidence={"count": count})
                return self._refusal("deny", "RESOURCE_EXHAUSTED", "rate limit exceeded", rule="rate-limit", **base)
        if not p._tool_allowed(tool):
            return self._refusal("deny", "PERMISSION_DENIED", f"tool {tool} is not available", rule="deny-tools", **base)
        if not p.engine.tool_visible(subject, domain):
            d = p.engine.pre_call(subject, domain, is_write=is_write)
            if not d.allow and not d.needs_approval:
                p.audit.emit(user=subject, tool=tool, domain=domain, stage="pre", write=is_write, via=gateway or "adapter",
                             decision="deny", rule=d.rule_id, evidence=d.evidence)
                return self._refusal("deny", "PERMISSION_DENIED", d.explain(), rule=d.rule_id, **base)
        if p.inbound_rules and args:
            args, hits = p._scan_inbound(args)
            if hits:
                blocked = p.inbound_action == "block"
                p.audit.emit(user=subject, tool=tool, domain=domain, stage="pre", write=is_write, via=gateway or "adapter",
                             decision="deny" if blocked else "allow", rule="inbound-secret", evidence={"hits": hits})
                if blocked:
                    return self._refusal("deny", "PERMISSION_DENIED", f"arguments contain a secret ({', '.join(hits)})",
                                         rule="inbound-secret", **base)
        p._sync_approvals(subject)
        for d in (p.engine.check_args(subject, tool, args), p.engine.pre_call(subject, domain, is_write=is_write)):
            if not d.allow:
                if d.needs_approval:
                    req, created = p.approvals.request(subject, d.rule_id, tool, domain, d.clause or "", d.owner or "", d.remediation or "")
                    if created:
                        p.approvals.notify(req, p._approve_hint(req["id"]))
                    p.audit.emit(user=subject, tool=tool, domain=domain, stage="pre", write=is_write, via=gateway or "adapter",
                                 decision="hold", rule=d.rule_id, evidence={**d.evidence, "approval": req["id"]})
                    return self._refusal("hold", "PERMISSION_DENIED", d.explain(), rule=d.rule_id, approval=req["id"], **base)
                p.audit.emit(user=subject, tool=tool, domain=domain, stage="pre", write=is_write, via=gateway or "adapter",
                             decision="deny", rule=d.rule_id, evidence=d.evidence)
                return self._refusal("deny", "PERMISSION_DENIED", d.explain(), rule=d.rule_id, **base)
        out = {"decision": "allow", **base}
        if args != (arguments or {}):
            out["decision"] = "rewrite"; out["arguments"] = args
        return out

    def response(self, subject: str, tool: str, result_text: str, gateway: str = "") -> dict:
        """Everything the proxy decides after the upstream answered: record who
        appeared, re-evaluate, and redact. `result_text` is the tool's text output
        (JSON or prose)."""
        p = self.p
        domain = p.domain_for(tool)
        is_write = p._is_write(tool)
        ents = extract(result_text or "")
        post = p.engine.post_call(subject, domain, ents)
        masked, counts = (redact(result_text or "", p.redact_rules) if p.redact_rules else (result_text, {}))
        p.audit.emit(user=subject, tool=tool, domain=domain, stage="post", write=is_write, via=gateway or "adapter",
                     entities=len(ents), decision="deny" if not post.allow else "allow",
                     entity_ids=(ents if p.cfg.get("audit_entities", True) else None),
                     rule=post.rule_id, alerts=post.alerts, evidence=post.evidence, redacted=(counts or None))
        base = {"tool": tool, "domain": domain, "subject": subject}
        if not post.allow:
            code = "PERMISSION_DENIED"
            return self._refusal("hold" if post.needs_approval else "deny", code, post.explain(), rule=post.rule_id, **base)
        if counts:
            return {"decision": "rewrite", "result": masked, "redacted": counts, "alerts": post.alerts, **base}
        return {"decision": "allow", "alerts": post.alerts, **base}


def _result_text(result: dict | None) -> str:
    """Text of a CallToolResult-shaped dict (camelCase or snake_case)."""
    if not result:
        return ""
    parts = []
    for c in result.get("content") or []:
        if isinstance(c, dict) and c.get("type") == "text":
            parts.append(str(c.get("text", "")))
    sc = result.get("structuredContent") or result.get("structured_content")
    if sc is not None:
        parts.append(json.dumps(sc, default=str))
    return "\n".join(parts)


def _refused_result(reason: str) -> dict:
    return {"isError": True, "content": [{"type": "text", "text": reason}]}


def adapter_routes(proxy, cfg: dict) -> list:
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route
    from .auth import identity_for, unexpired
    acfg = cfg.get("adapters") or {}
    token = os.path.expandvars(str(acfg.get("token"))) if acfg.get("token") else None
    decider = Decider(proxy)

    def caller(request) -> str | None:
        """The gateway's identity (shared token), or an authenticated principal."""
        if token:
            return "gateway" if request.headers.get("authorization") == f"Bearer {token}" else None
        user = getattr(request, "user", None)
        tok = getattr(user, "access_token", None)
        if tok is not None and unexpired(tok):
            return identity_for(tok, (cfg.get("auth") or {}).get("identity_claim"))
        return None

    def subject_of(request, body: dict) -> str | None:
        s = body.get("subject")
        if isinstance(s, dict) and s.get("id"):
            return str(s["id"])
        if isinstance(s, str) and s:
            return s
        return request.headers.get("x-aggrete-user") or request.query_params.get("user")

    async def decide(request):
        if caller(request) is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        body = await request.json()
        subject = subject_of(request, body)
        tool = str((body.get("tool") or {}).get("name") if isinstance(body.get("tool"), dict) else body.get("tool") or "")
        if not subject or not tool:
            return JSONResponse({"error": "subject and tool are required"}, status_code=400)
        phase = body.get("phase", "request")
        gw = str(body.get("gateway") or "decide")
        if phase == "response":
            out = decider.response(subject, tool, _result_text(body.get("result")) if isinstance(body.get("result"), dict)
                                   else str(body.get("result") or ""), gw)
        else:
            out = decider.request(subject, tool, body.get("arguments") or {}, gw)
        return JSONResponse(out)

    async def authzen(request):
        """OpenID AuthZEN 1.0 evaluation with the COAZ-MCP default mapping:
        subject.id, action.name=tools/call, resource.id=<tool>, arguments in
        resource.properties.arguments (or context.arguments)."""
        if caller(request) is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        body = await request.json()
        subject = str(((body.get("subject") or {}).get("id")) or "")
        resource = body.get("resource") or {}
        tool = str(resource.get("id") or resource.get("name") or "")
        props = resource.get("properties") or {}
        args = props.get("arguments") or (body.get("context") or {}).get("arguments") or {}
        if not subject or not tool:
            return JSONResponse({"error": "subject.id and resource.id are required"}, status_code=400)
        out = decider.request(subject, tool, args, "authzen")
        allowed = out["decision"] in ("allow", "rewrite")
        ctx = {"reason": out.get("reason", "allowed"), "rule": out.get("rule"), "decision": out["decision"]}
        if out.get("approval"):
            ctx["approval"] = out["approval"]
        return JSONResponse({"decision": allowed, "context": ctx})

    async def docker_before(request):
        """Docker MCP Gateway `before` interceptor: empty body = pass through;
        a CallToolResult body = returned to the client instead of calling the tool."""
        if caller(request) is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        body = await request.json()
        params = body.get("params") or body.get("Params") or body
        tool = str(params.get("name") or params.get("Name") or "")
        args = params.get("arguments") or params.get("Arguments") or {}
        subject = subject_of(request, body) or "docker-gateway"
        out = decider.request(subject, tool, args, "docker")
        if out["decision"] in ("allow", "rewrite"):
            return Response(b"", status_code=200)
        return JSONResponse(_refused_result(out["reason"]))

    async def docker_after(request):
        """Docker MCP Gateway `after` interceptor: sees the CallToolResult; returns a
        replacement (redacted, or a refusal) or nothing."""
        if caller(request) is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        body = await request.json()
        tool = request.query_params.get("tool") or request.headers.get("x-aggrete-tool") or str(body.get("tool") or "")
        subject = subject_of(request, body) or "docker-gateway"
        out = decider.response(subject, tool, _result_text(body), "docker")
        if out["decision"] == "allow":
            return Response(b"", status_code=200)
        if out["decision"] == "rewrite":
            return JSONResponse({"content": [{"type": "text", "text": out["result"]}], "isError": False})
        return JSONResponse(_refused_result(out["reason"]))

    return [Route("/v1/decide", decide, methods=["POST"]),
            Route("/access/v1/evaluation", authzen, methods=["POST"]),
            Route("/adapters/docker/before", docker_before, methods=["POST"]),
            Route("/adapters/docker/after", docker_after, methods=["POST"])]


# ---------- IBM ContextForge external plugin (MCP server) ----------

PLUGIN_NAME = "aggrete"


def contextforge_hook(decider: Decider, hook_type: str, payload: dict, context: dict | None) -> dict:
    """One `invoke_hook` call -> a PluginResult dict."""
    gc = (context or {}).get("global_context") or {}
    subject = str(gc.get("user") or (context or {}).get("user") or "contextforge")
    name = str(payload.get("name") or "")
    if hook_type == "tool_pre_invoke":
        out = decider.request(subject, name, payload.get("args") or {}, "contextforge")
        if out["decision"] in ("allow", "rewrite"):
            mod = {**payload, "args": out.get("arguments", payload.get("args"))} if out["decision"] == "rewrite" else None
            return {"continue_processing": True, "modified_payload": mod, "metadata": {"aggrete": out}}
        return {"continue_processing": False,
                "violation": {"code": "AGGRETE_" + out["decision"].upper(), "reason": out.get("rule") or out["code"],
                              "description": out["reason"], "details": {k: out[k] for k in ("approval",) if k in out}}}
    if hook_type == "tool_post_invoke":
        res = payload.get("result")
        text = _result_text(res) if isinstance(res, dict) else str(res or "")
        out = decider.response(subject, name, text, "contextforge")
        if out["decision"] == "allow":
            return {"continue_processing": True, "metadata": {"aggrete": out}}
        if out["decision"] == "rewrite":
            return {"continue_processing": True, "modified_payload": {**payload, "result": out["result"]},
                    "metadata": {"aggrete": {"redacted": out["redacted"]}}}
        return {"continue_processing": False,
                "violation": {"code": "AGGRETE_" + out["decision"].upper(), "reason": out.get("rule") or out["code"],
                              "description": out["reason"]}}
    return {"continue_processing": True}


def plugin_config() -> dict:
    return {"name": PLUGIN_NAME, "description": "Aggrete policy: deterministic, stateful code-of-conduct enforcement",
            "author": "Aggrete", "kind": "external", "version": "1",
            "hooks": ["tool_pre_invoke", "tool_post_invoke"], "mode": "enforce", "priority": 50}


async def serve_contextforge(proxy) -> None:
    """Serve the ContextForge external-plugin contract over stdio: tools
    `get_plugin_config` and `invoke_hook`."""
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    decider = Decider(proxy)

    async def list_tools(ctx, params):
        return types.ListToolsResult(tools=[
            types.Tool(name="get_plugin_config", description="Plugin manifest", inputSchema={"type": "object", "properties": {"name": {"type": "string"}}}),
            types.Tool(name="invoke_hook", description="Run a hook", inputSchema={"type": "object", "properties": {
                "hook_type": {"type": "string"}, "plugin_name": {"type": "string"},
                "payload": {"type": "object"}, "context": {"type": "object"}}, "required": ["hook_type", "payload"]}),
        ])

    async def call_tool(ctx, params):
        a = params.arguments or {}
        if params.name == "get_plugin_config":
            out = plugin_config()
        else:
            out = contextforge_hook(decider, str(a.get("hook_type") or ""), a.get("payload") or {}, a.get("context"))
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(out, default=str))])

    server = Server("aggrete-contextforge-plugin", on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    import argparse
    import asyncio
    from pathlib import Path
    import yaml
    from .accumulator import MemoryStore
    from .audit import Audit
    from .policy import Engine
    from .proxy import Proxy, build_store
    ap = argparse.ArgumentParser(prog="python -m aggrete.adapters", description="ContextForge external plugin over stdio")
    ap.add_argument("--config", default="proxy.config.yaml")
    ns = ap.parse_args()
    cfg = yaml.safe_load(Path(ns.config).read_text())
    root = Path(ns.config).parent
    cfg["_config_dir"] = str(root)
    engine = Engine(str(root / cfg.get("coc", "coc.yaml")), build_store(cfg.get("store")) or MemoryStore())
    proxy = Proxy(cfg, engine, Audit(cfg.get("audit_log")))
    asyncio.run(serve_contextforge(proxy))


if __name__ == "__main__":
    main()
