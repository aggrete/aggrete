"""An MCP proxy that enforces a code of conduct across connectors.

Speaks MCP to the client, MCP to each upstream server, and evaluates every
tools/call against accumulated state before and after execution.

    python -m aggrete.proxy --config proxy.config.yaml

    python -m aggrete.proxy --config proxy.config.yaml --transport streamable-http --port 8080

Identity: over stdio the user is `user:` from the config. Whoever launched
the process, advisory only. Over streamable HTTP every request must carry a
bearer token; the user is derived from its claims (see auth.py) and nothing in
the config can override it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fnmatch
import json
import os
import re
import sys
import time
from pathlib import Path

import mcp.types as types
import yaml
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .auth import build_verifier, identity_for, unexpired
from .entities import extract
from .policy import Engine
from .audit import Audit
from .redact import rules_from_config, redact, BUILTIN as REDACT_BUILTIN
from .accumulator import RedisStore
from . import integrity, ratelimit, credentials

# Inbound scan default: credential-shaped patterns only, so a legitimate email or
# id in an argument is not mistaken for a secret. Override with `scan_inbound:`.
INBOUND_DEFAULT = ["aws_key", "api_key", "bearer"]

SEP = "__"
# Tools that act on the world (write / egress). Override with `write_tools:` in config.
DEFAULT_WRITE_TOOLS = ["*create*", "*update*", "*write*", "*upload*", "*delete*",
                       "*post*", "*send*", "*share*", "*append*", "*move*", "*put*"]
ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Built-in tools the proxy answers itself (no upstream). `check` dry-runs a
# proposed plan against the policy; `scenarios` lists things to try. Disable
# with `builtin_tools: false` in the config.
CHECK_TOOL = f"aggrete{SEP}check"
SCENARIOS_TOOL = f"aggrete{SEP}scenarios"


def expand_env(value: str) -> str:
    """Replace ${VAR} references so secrets stay out of the config file."""
    def sub(m):
        name = m.group(1)
        if name not in os.environ:
            raise KeyError(f"config references ${{{name}}} but it is not set")
        return os.environ[name]
    return ENV_REF.sub(sub, value)



class Proxy:
    def __init__(self, config: dict, engine: Engine, audit: Audit):
        self.cfg = config
        self.engine = engine
        self.audit = audit
        self.sessions: dict[str, ClientSession] = {}
        self.static_user = config.get("user", "unknown")
        self.identity_claim = (config.get("auth") or {}).get("identity_claim")
        self.redact_rules = rules_from_config(config.get("redact"))
        # Tool integrity (rug-pull / poisoning). Off unless `tool_integrity:` is set.
        self.integrity_cfg = config.get("tool_integrity") or {}
        self.pins = integrity.PinStore(self.integrity_cfg.get("pins")) if self.integrity_cfg else None
        self.tool_flags: dict[str, dict | None] = {}
        self._integrity_audited: set[str] = set()
        # Per-user rate limit, sharing Redis with the accumulator when present.
        redis_client = engine.store.r if isinstance(engine.store, RedisStore) else None
        self.rate_limiter = ratelimit.from_config(config.get("rate_limit"), redis_client)
        # Inbound secret scanning of tool arguments.
        sc = config.get("scan_inbound")
        names = (INBOUND_DEFAULT if sc is True else list(sc)) if sc else []
        self.inbound_rules = [(n, REDACT_BUILTIN[n]) for n in names if n in REDACT_BUILTIN]
        self.inbound_action = config.get("scan_inbound_action", "block")

    @property
    def user(self) -> str:
        """Who the policy engine evaluates. Token first; config only when no token."""
        from mcp.server.auth.middleware.auth_context import get_access_token
        token = get_access_token()
        if token is None:
            return self.static_user
        if not unexpired(token):
            raise PermissionError("token expired")
        return identity_for(token, self.identity_claim)

    def domain_for(self, tool: str) -> str:
        for pattern, domain in self.cfg.get("domains", {}).items():
            if fnmatch.fnmatch(tool, pattern):
                return domain
        return self.cfg.get("default_domain", "unclassified")

    async def connect(self, stack: contextlib.AsyncExitStack):
        for name, spec in self.cfg["upstreams"].items():
            try:
                if "url" in spec:
                    read, write = await self._connect_http(stack, spec)
                elif "command" in spec:
                    read, write = await self._connect_stdio(stack, spec)
                else:
                    raise ValueError(f"upstream {name!r} needs either 'command' or 'url'")
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                self.sessions[name] = session
            except Exception as e:  # a broken connector must not take the whole proxy down
                print(f"aggrete: upstream {name!r} failed to connect, skipping it: {e}", file=sys.stderr)
        if self.pins:
            await self._scan_integrity()

    async def _scan_integrity(self) -> None:
        """Fingerprint and scan every upstream tool at startup, so a rug-pull or a
        poisoned description is caught (and cached for call_tool) before anyone lists."""
        for upstream, session in self.sessions.items():
            try:
                for t in (await session.list_tools()).tools:
                    self._integrity_flag(f"{upstream}{SEP}{t.name}", t.description, t.input_schema)
            except Exception as e:
                print(f"aggrete: integrity scan of {upstream!r} failed: {e}", file=sys.stderr)

    def _integrity_flag(self, name: str, description, input_schema) -> dict | None:
        """Evaluate one tool's integrity, cache the verdict for call_tool, and audit
        it once. Returns the flag ({action, reasons, fingerprint}) or None if clean."""
        if not self.pins:
            return None
        flag = integrity.evaluate(name, description, input_schema, self.pins, self.integrity_cfg)
        self.tool_flags[name] = flag
        if flag and name not in self._integrity_audited:
            self._integrity_audited.add(name)
            self.audit.emit(user="-", tool=name, domain=self.domain_for(name), stage="integrity",
                            write=False, decision=flag["action"], rule="tool-integrity",
                            evidence={"reasons": flag["reasons"], "fingerprint": flag["fingerprint"][:16]})
        return flag

    def _stdio_params(self, spec: dict, extra_env: dict | None = None) -> StdioServerParameters:
        """Build the stdio spawn parameters. `extra_env` carries a per-user
        on-behalf-of credential (from credentials.resolve) when present."""
        command = spec["command"]
        # Use the interpreter running the proxy, so a venv's deps resolve
        # for locally-spawned Python servers without hardcoding paths.
        if command in ("python", "python3"):
            command = sys.executable
        # Inherit the proxy's environment (certs, PATH, etc.) so a connector runs
        # the same way it does from the shell, plus any per-upstream overrides,
        # plus the per-user credential last so it wins.
        return StdioServerParameters(
            command=command, args=spec.get("args", []),
            env={**os.environ, **(spec.get("env") or {}), **(extra_env or {})},
        )

    async def _connect_stdio(self, stack, spec, extra_env: dict | None = None):
        return await stack.enter_async_context(stdio_client(self._stdio_params(spec, extra_env)))

    def _http_headers(self, spec: dict, extra_headers: dict | None = None) -> dict:
        """Header set for an HTTP upstream; `extra_headers` is the per-user
        on-behalf-of credential when present (it wins over the shared header)."""
        headers = {k: expand_env(str(v)) for k, v in (spec.get("headers") or {}).items()}
        headers.update(extra_headers or {})
        return headers

    async def _connect_http(self, stack, spec, extra_headers: dict | None = None):
        """Remote connector over streamable HTTP.

        `headers` values may reference ${ENV_VARS}, so a bearer token for the
        upstream lives in the proxy's environment, never in the YAML. This is
        the proxy's own credential to the connector; the end user never holds
        it, which is what makes the proxy un-bypassable. `extra_headers` carries
        a per-user on-behalf-of credential when present.
        """
        headers = self._http_headers(spec, extra_headers)
        client = create_mcp_http_client(headers=headers or None)
        await stack.enter_async_context(client)
        return await stack.enter_async_context(
            streamable_http_client(expand_env(spec["url"]), http_client=client)
        )

    @contextlib.asynccontextmanager
    async def _upstream_session(self, user: str, upstream: str):
        """Yield the ClientSession to use for (user, upstream).

        A shared upstream yields the single startup session (kept open). A
        `per_user: true` upstream opens a fresh connection with the caller's own
        on-behalf-of credential, yields it, and closes it when the call is done,
        all within this task so nothing crosses an anyio cancel scope. That means
        one connection per call for per-user upstreams; connection pooling is a
        planned optimization.
        """
        spec = self.cfg.get("upstreams", {}).get(upstream, {})
        if not spec.get("per_user"):
            yield self.sessions.get(upstream)
            return
        cred = await asyncio.to_thread(credentials.resolve, spec, user, upstream)
        async with contextlib.AsyncExitStack() as sstack:
            if "url" in spec:
                read, write = await self._connect_http(sstack, spec, extra_headers=cred.headers)
            else:
                read, write = await self._connect_stdio(sstack, spec, extra_env=cred.env)
            session = await sstack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            yield session

    async def list_tools(self, ctx, params) -> types.ListToolsResult:
        tools: list[types.Tool] = []
        for upstream, session in self.sessions.items():
            for t in (await session.list_tools()).tools:
                name = f"{upstream}{SEP}{t.name}"
                if not self._tool_allowed(name):
                    continue  # tool filtering: what is never listed is never called
                if not self.engine.tool_visible(self.user, self.domain_for(name)):
                    continue  # selective exposure: walls and blocks hide tools per user
                flag = self._integrity_flag(name, t.description, t.input_schema)
                if flag and flag["action"] == "block":
                    continue  # a rug-pulled or poisoned tool is hidden and never callable
                description = f"[{self.domain_for(name)}] {t.description or ''}".strip()
                if flag:  # alert: keep it listed, but flag it so the assistant is warned
                    description = f"[integrity: {'; '.join(flag['reasons'])}] {description}"
                tools.append(
                    types.Tool(
                        name=name,
                        title=t.title,
                        description=description,
                        inputSchema=t.input_schema,
                    )
                )
        if self.cfg.get("builtin_tools", True):
            tools.extend(self._builtin_tools())
        return types.ListToolsResult(tools=tools)

    def _builtin_tools(self) -> list[types.Tool]:
        """Tools the proxy answers itself, so the policy is explorable without
        having to trip it. `check` is a dry run; `scenarios` is a guided menu."""
        return [
            types.Tool(
                name=CHECK_TOOL,
                title="Check a plan against the code of conduct",
                description=(
                    "Ask whether a sequence of tool calls would be allowed before running any of "
                    "them. Returns the decision (allowed, allowed-with-alert, or refused), the rule "
                    "that applies, its clause, and the remediation. Nothing is fetched. Use this to "
                    "answer 'can I do X?' questions: translate the request into the tool calls it "
                    "would take, then pass them as `tools` in order."),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tools": {
                            "type": "array",
                            "items": {"oneOf": [
                                {"type": "string"},
                                {"type": "object",
                                 "properties": {"tool": {"type": "string"},
                                                "args": {"type": "object"}},
                                 "required": ["tool"]},
                            ]},
                            "description": ("The tool calls you are considering, in order, by their "
                                            "exact names on this server, e.g. [\"hr__recent_joiners\", "
                                            "\"finance__budget_roles\"]. To check a call by its "
                                            "arguments (e.g. an export's scope), pass an object "
                                            "instead of a name: {\"tool\": \"crm__export\", "
                                            "\"args\": {\"scope\": \"all\"}}."),
                        },
                        "entities": {
                            "type": "array", "items": {"type": "string"},
                            "description": ("Optional. The people the plan concerns, as p:<email> ids, "
                                            "applied to each read. Omit to evaluate assuming the calls "
                                            "concern the same people (you and a colleague)."),
                        },
                    },
                    "required": ["tools"],
                },
            ),
            types.Tool(
                name=SCENARIOS_TOOL,
                title="Things to try in this demo",
                description=("List concrete things to try here, each showing a different kind of "
                             "policy decision (redaction, refusing a combination, individual pay, "
                             "comparing colleagues, the prompt-injection shield, hidden tools). "
                             "Takes no arguments. Start here if you are new."),
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    def _is_write(self, name: str) -> bool:
        """A call that acts on the world (write/egress). Governed as egress by
        the prompt-injection shield and by any `on: write` rule."""
        return any(fnmatch.fnmatch(name, p) for p in self.cfg.get("write_tools", DEFAULT_WRITE_TOOLS))

    def _tool_allowed(self, name: str) -> bool:
        allow = self.cfg.get("allow_tools")
        deny = self.cfg.get("deny_tools", [])
        if any(fnmatch.fnmatch(name, p) for p in deny):
            return False
        return not allow or any(fnmatch.fnmatch(name, p) for p in allow)

    async def call_tool(self, ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name, args = params.name, params.arguments or {}

        if self.cfg.get("builtin_tools", True):
            if name == CHECK_TOOL:
                return self._run_check(args)
            if name == SCENARIOS_TOOL:
                return self._run_scenarios()

        if self.rate_limiter is not None:
            ok, count = self.rate_limiter.allow(self.user)
            if not ok:
                self.audit.emit(user=self.user, tool=name, domain=self.domain_for(name), stage="pre",
                                write=False, decision="deny", rule="rate-limit",
                                evidence={"count": count, "max": self.rate_limiter.max,
                                          "window_s": self.rate_limiter.window})
                return self._refuse(
                    f"Rate limit exceeded: more than {self.rate_limiter.max} calls in "
                    f"{self.rate_limiter.window}s. Slow down and retry shortly.")

        domain = self.domain_for(name)

        if not self._tool_allowed(name):
            return self._refuse(f"Tool {name} is not available through this gateway.")

        flag = self.tool_flags.get(name)
        if flag and flag["action"] == "block":
            self.audit.emit(user=self.user, tool=name, domain=domain, stage="pre", write=False,
                            decision="deny", rule="tool-integrity", evidence={"reasons": flag["reasons"]})
            return self._refuse(
                f"Tool {name} is blocked by tool integrity: {'; '.join(flag['reasons'])}. "
                "A connector changed its tool definition since it was first seen, or the "
                "description carries hidden instructions. Re-pin it deliberately if expected.")

        is_write = self._is_write(name)

        # Inbound secret scanning: a credential in the arguments never goes upstream.
        if self.inbound_rules and args:
            args, hits = self._scan_inbound(args)
            if hits:
                blocked = self.inbound_action == "block"
                self.audit.emit(user=self.user, tool=name, domain=domain, stage="pre", write=is_write,
                                decision="deny" if blocked else "allow", rule="inbound-secret",
                                evidence={"hits": hits})
                if blocked:
                    return self._refuse(
                        f"Blocked: the arguments to {name} contain what looks like a secret "
                        f"({', '.join(hits)}). Aggrete does not forward credentials into tools. "
                        "Remove it and retry.")

        # Argument-level rules: the same tool can be fine or forbidden depending
        # on what it is asked to do (export your team vs the whole company).
        argd = self.engine.check_args(self.user, name, args)
        if not argd.allow:
            self.audit.emit(user=self.user, tool=name, domain=domain, stage="pre", write=is_write,
                            decision="deny", rule=argd.rule_id, evidence=argd.evidence)
            return self._refuse(argd.explain())

        # --- Layer 3/4, before the fetch -----------------------------------
        pre = self.engine.pre_call(self.user, domain, is_write=is_write)
        if not pre.allow:
            self.audit.emit(user=self.user, tool=name, domain=domain, stage="pre", write=is_write,
                            decision="deny", rule=pre.rule_id, evidence=pre.evidence)
            return self._refuse(pre.explain())

        upstream, _, tool = name.partition(SEP)
        # For an upstream that impersonates the caller (e.g. Drive with domain-wide
        # delegation), forward the caller's identity as a trusted argument. The
        # proxy sets it, overriding anything the model supplied, so the assistant
        # can never choose whose permissions it acts under.
        if self.cfg.get("upstreams", {}).get(upstream, {}).get("impersonate"):
            args = {**args, "acting_user": self.user}
        try:
            # Per-user upstreams open a connection with the caller's own resolved
            # credential (on-behalf-of); shared upstreams reuse the one session.
            async with self._upstream_session(self.user, upstream) as session:
                if session is None:
                    return self._refuse(f"Unknown upstream {upstream!r}.")
                result = await session.call_tool(tool, args)
        except Exception as e:
            self.audit.emit(user=self.user, tool=name, domain=domain, stage="pre", write=is_write,
                            decision="deny", rule="obo-credential", evidence={"error": str(e)[:200]})
            return self._refuse(f"Could not reach {upstream!r} on your behalf: {e}")

        # --- Layer 3/4, after the fetch ------------------------------------
        text = "\n".join(c.text for c in result.content if isinstance(c, types.TextContent))
        ents = extract(text)
        post = self.engine.post_call(self.user, domain, ents)

        redacted: dict = {}
        if post.allow and self.redact_rules:
            result, redacted = self._redact_result(result)

        self.audit.emit(user=self.user, tool=name, domain=domain, stage="post", write=is_write,
                        entities=len(ents), decision="deny" if not post.allow else "allow",
                        entity_ids=(ents if self.cfg.get("audit_entities", True) else None),
                        rule=post.rule_id, alerts=post.alerts, evidence=post.evidence,
                        redacted=(redacted or None), purpose=pre.granted_purpose)

        if not post.allow:
            # The data left the upstream, but it does not reach the model.
            return self._refuse(post.explain())
        return result

    def _scan_inbound(self, args):
        """Walk argument values and mask secret-shaped strings, returning
        (args, hits). In block mode the caller refuses on any hit; in redact mode
        these masked arguments are what goes upstream."""
        hits: dict[str, int] = {}

        def walk(v):
            if isinstance(v, str):
                masked, counts = redact(v, self.inbound_rules)
                for k, n in counts.items():
                    hits[k] = hits.get(k, 0) + n
                return masked
            if isinstance(v, dict):
                return {k: walk(x) for k, x in v.items()}
            if isinstance(v, list):
                return [walk(x) for x in v]
            return v

        return walk(args), hits

    def _redact_result(self, result: types.CallToolResult):
        """Mask secrets/PII in text content before it reaches the model.
        Enforcement already ran on the original text; this only touches the
        payload handed back to the assistant."""
        total: dict = {}
        new_content = []
        for c in result.content:
            if isinstance(c, types.TextContent):
                masked, counts = redact(c.text, self.redact_rules)
                for k, v in counts.items():
                    total[k] = total.get(k, 0) + v
                new_content.append(types.TextContent(type="text", text=masked))
            else:
                new_content.append(c)
        result.content = new_content
        return result, total

    # ---------- built-in tools: check and scenarios ----------

    def _run_check(self, args: dict) -> types.CallToolResult:
        """Dry-run a proposed plan against the policy and report the verdict,
        without fetching anything. The heart of 'would this be allowed?'."""
        raw = args.get("tools") or []
        if isinstance(raw, (str, dict)):
            raw = [raw]
        items = []
        for it in raw:
            if isinstance(it, dict):
                nm = it.get("tool") or it.get("name")
                if nm:
                    items.append((str(nm), it.get("args") or {}))
            else:
                items.append((str(it), {}))
        tools = [nm for nm, _ in items]
        if not tools:
            return self._refuse(
                "check: pass `tools`, the list of tool calls you are considering, in order. "
                "For example {\"tools\": [\"hr__recent_joiners\", \"finance__budget_roles\", "
                "\"hr__leave_balance\"]}. Call aggrete__scenarios for ideas.")

        user = self.user
        supplied = args.get("entities")
        # Default probe: you and a colleague, so relationship rules (join,
        # comparison, small-group) are visible. Reads carry it; writes do not.
        probe = ([str(e) for e in supplied] if supplied
                 else [f"p:{user.strip().lower()}", "p:teammate@example.com"])
        steps = []
        for name, iargs in items:
            is_write = self._is_write(name)
            step = {"tool": name, "domain": self.domain_for(name),
                    "write": is_write, "entities": [] if is_write else probe}
            if iargs:
                step["args"] = iargs
            steps.append(step)

        results, blocked_at = self.engine.simulate(steps, user)
        self.audit.emit(user=user, tool=CHECK_TOOL, domain="-", stage="check", write=False,
                        decision="deny" if blocked_at is not None else "allow",
                        rule=(results[blocked_at]["decision"].rule_id if blocked_at is not None else None),
                        evidence={"tools": tools})
        return self._refuse(self._format_check(tools, steps, results, blocked_at, bool(supplied)))

    def _format_check(self, tools, steps, results, blocked_at, supplied) -> str:
        head = "REFUSED" if blocked_at is not None else "allowed"
        out = [f"Plan check: {head}.", ""]
        tag = {"allow": "allowed", "alert": "allowed (with an alert)", "deny": "REFUSED"}
        for i, name in enumerate(tools):
            dom = steps[i]["domain"]
            if i >= len(results):
                out.append(f"  {i + 1}. {name}  [{dom}]  ->  not reached (the plan is already refused)")
                continue
            r = results[i]
            d = r["decision"]
            line = f"  {i + 1}. {name}  [{dom}]  ->  {tag[r['verdict']]}"
            if r["verdict"] == "deny":
                line += f"   {d.rule_id}"
            out.append(line)
            if r["verdict"] == "alert":
                for a in d.alerts:
                    out.append(f"        alert {a.get('rule_id', '')}: {self._alert_phrase(a)}")
            if r["verdict"] == "deny":
                out += ["",
                        f"     {' '.join((d.clause or '').split())}",
                        f"     Fix: {' '.join((d.remediation or '').split())}",
                        f"     Rule owner: {d.owner}", ""]
        out.append("")
        if supplied:
            out.append("Evaluated for the people you named.")
        else:
            out.append("Evaluated assuming these calls concern the same people (you and a "
                       "colleague). Pass `entities` (p:<email> ids) for an exact check.")
        out.append("Nothing was fetched to produce this. Run the calls for real to see it enforced.")
        return "\n".join(out)

    @staticmethod
    def _alert_phrase(a: dict) -> str:
        if "distinct" in a:
            return f"{a['distinct']} distinct people, over the budget of {a['max']}"
        if "people" in a:
            return f"a result about {a['people']} people, under the minimum of {a['k']}"
        if "overlap" in a:
            return f"overlapping on {len(a['overlap'])} people"
        return "flagged"

    def _run_scenarios(self) -> types.CallToolResult:
        """A guided menu. Supplied per-deployment via `scenarios:` in the config so
        it names the tools this instance actually exposes; `{user}` is substituted
        with the caller. Falls back to pointing at `check` when unset."""
        text = self.cfg.get("scenarios")
        if not text:
            return self._refuse(
                "Call aggrete__check with a list of tool calls to see whether they would be "
                "allowed, and why, without fetching anything, using the tool names on this "
                "server, for example {\"tools\": [\"hr__recent_joiners\", \"finance__budget_roles\"]}.")
        return self._refuse(str(text).replace("{user}", self.user).rstrip())

    def _refuse(self, message: str) -> types.CallToolResult:
        # Not is_error: the model should read this and relay it, not retry it.
        return types.CallToolResult(content=[types.TextContent(type="text", text=message)])


def build_store(store_cfg: dict | None):
    """`store: {redis_url: redis://...}` for shared state across replicas; else in-memory."""
    if not store_cfg or not store_cfg.get("redis_url"):
        return None
    import redis
    from .accumulator import RedisStore
    client = redis.Redis.from_url(expand_env(store_cfg["redis_url"]))
    client.ping()
    return RedisStore(client, prefix=store_cfg.get("prefix", "aggrete"))


def cli() -> None:
    asyncio.run(main())


def build_http_app(server: Server, cfg: dict, connect):
    """Starlette app: bearer auth → auth context → MCP streamable HTTP at /mcp.

    `connect(stack)` is awaited inside the lifespan so upstream sessions live
    exactly as long as the HTTP server.
    """
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.authentication import AuthenticationMiddleware
    from starlette.routing import Route
    from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
    from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
    from mcp.server.auth.routes import build_resource_metadata_url, create_protected_resource_routes
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from mcp.server.transport_security import TransportSecuritySettings
    from pydantic import AnyHttpUrl

    auth_cfg = cfg.get("auth")
    if not auth_cfg:
        raise SystemExit("streamable-http requires an `auth:` block. Identity must come from a token, "
                         "or set `auth: {mode: anonymous}` for a public no-auth demo (mock data only).")
    anonymous = auth_cfg.get("mode") == "anonymous"
    signin = None
    verifier = None
    if anonymous:
        pass  # deliberately unauthenticated: identity is the static `user`. Public demos only.
    elif auth_cfg.get("mode") == "builtin":
        from mcp.server.auth.provider import ProviderTokenVerifier
        from .signin import BuiltinAuthServer
        users = {k: expand_env(str(v)) for k, v in (auth_cfg.get("users") or {}).items()}
        signin = BuiltinAuthServer(users, auth_cfg["issuer"], auth_cfg.get("state"))
        verifier = ProviderTokenVerifier(signin)
    else:
        verifier = build_verifier(auth_cfg)
    http_cfg = cfg.get("http", {})
    allowed_hosts = http_cfg.get("allowed_hosts", [])
    # DNS-rebinding protection turns on automatically once you pin `allowed_hosts`
    # (there is nothing to check the Host header against until then), and an
    # explicit `dns_rebinding_protection:` always wins. Pinning the host you serve
    # on is recommended; it is defense in depth on top of the mandatory bearer auth.
    dns_rebind = http_cfg.get("dns_rebinding_protection")
    if dns_rebind is None:
        dns_rebind = bool(allowed_hosts)
    manager = StreamableHTTPSessionManager(
        app=server, json_response=bool(http_cfg.get("json_response", False)),
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=bool(dns_rebind),
            allowed_hosts=allowed_hosts, allowed_origins=http_cfg.get("allowed_origins", [])),
        session_idle_timeout=http_cfg.get("session_idle_timeout", 1800),
    )

    resource_url = auth_cfg.get("resource_url") or (auth_cfg["issuer"].rstrip("/") + "/mcp" if signin else None)
    routes = []
    metadata_url = None
    if signin:
        from mcp.server.auth.routes import create_auth_routes
        from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
        routes += create_auth_routes(provider=signin, issuer_url=AnyHttpUrl(auth_cfg["issuer"]),
                                     client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=["mcp"], default_scopes=["mcp"]),
                                     revocation_options=RevocationOptions(enabled=True))
        routes.append(Route("/signin", signin.signin, methods=["GET", "POST"]))

    brand = cfg.get("brand", {})
    if brand.get("icon_file"):
        from starlette.responses import FileResponse
        icon_path = str((Path(cfg.get("_config_dir", ".")) / brand["icon_file"]).resolve())
        async def _icon(request):
            return FileResponse(icon_path, media_type=brand.get("icon_mime", "image/svg+xml"))
        routes.append(Route("/icon.svg", _icon))
        routes.append(Route("/favicon.ico", _icon))
    if resource_url:
        routes += create_protected_resource_routes(
            resource_url=AnyHttpUrl(resource_url),
            authorization_servers=[AnyHttpUrl(auth_cfg["issuer"])] if auth_cfg.get("issuer") else [],
            scopes_supported=auth_cfg.get("required_scopes"), resource_name="aggrete")
        metadata_url = build_resource_metadata_url(AnyHttpUrl(resource_url))
    class _RawASGI:  # Starlette treats a bound method as a request handler; wrap so /mcp is ASGI.
        def __init__(self, app):
            self._app = app
        async def __call__(self, scope, receive, send):
            await self._app(scope, receive, send)
    mcp_endpoint = (_RawASGI(manager.handle_request) if anonymous else RequireAuthMiddleware(
        manager.handle_request, auth_cfg.get("required_scopes") or [], metadata_url))
    routes.append(Route("/mcp", endpoint=mcp_endpoint, methods=["GET", "POST", "DELETE"]))

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with contextlib.AsyncExitStack() as stack:
            await connect(stack)
            async with manager.run():
                yield

    mw = [] if anonymous else [
        Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(verifier)),
        Middleware(AuthContextMiddleware),
    ]
    return Starlette(routes=routes, lifespan=lifespan, middleware=mw)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="proxy.config.yaml")
    ap.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--demo", action="store_true",
                    help="self-contained demo: a terminal walkthrough when run in a shell, or a real MCP server (bundled mock connectors and policy, no config) when a client attaches over stdio")
    ap.add_argument("--version", action="store_true",
                    help="print package version and exit")
    args = ap.parse_args()

    if args.version:
        from importlib.metadata import version
        print(f"aggrete {version('aggrete')}")
        return

    if args.demo and sys.stdin.isatty() and sys.stdout.isatty():
        # A person at a terminal: run the guided walkthrough and exit.
        from ._demo import run
        run()
        return

    if args.demo:
        # A client attached over stdio: run a real, self-contained demo MCP
        # server (bundled mock upstreams + bundled policy, no config, no auth).
        from ._demo import demo_config, DEMO_DIR
        cfg = demo_config()
        root = DEMO_DIR
        cfg["_config_dir"] = str(root)
        args.transport = "stdio"
    else:
        if not Path(args.config).exists():
            print(
                f"aggrete: no config file at {args.config!r}.\n\n"
                f"  Try the demo (no config needed):   aggrete --demo\n"
                f"  Point it at your own config:       aggrete --config /path/to/proxy.config.yaml\n"
                f"  Get started in 15 minutes:         https://aggrete.com/guide",
                file=sys.stderr)
            raise SystemExit(1)
        cfg = yaml.safe_load(Path(args.config).read_text())
        root = Path(args.config).parent
        cfg["_config_dir"] = str(root)
    engine = Engine(str(root / cfg.get("coc", "coc.yaml")), build_store(cfg.get("store")),
                    pack_state_path=cfg.get("pack_state"))
    from .forward import build_forwarder
    audit = Audit(cfg.get("audit_log"), forward=build_forwarder(cfg.get("audit_forward")))
    proxy = Proxy(cfg, engine, audit)

    brand = cfg.get("brand", {})
    icons = None
    if brand.get("icon_url"):
        icons = [types.Icon(src=brand["icon_url"], mime_type=brand.get("icon_mime", "image/svg+xml"))]
    try:
        from importlib.metadata import version as _pkg_version
        _ver = _pkg_version("aggrete")
    except Exception:
        _ver = "0"
    server = Server(
        "aggrete",
        version=_ver,
        title=brand.get("title", "Aggrete"),
        instructions=cfg.get("instructions"),  # advertised in the MCP handshake; clients surface it
        website_url=brand.get("website_url", "https://aggrete.com"),
        icons=icons,
        on_list_tools=proxy.list_tools,
        on_call_tool=proxy.call_tool,
    )

    if args.transport == "streamable-http":
        import uvicorn
        app = build_http_app(server, cfg, proxy.connect)
        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
        await uvicorn.Server(config).serve()
        return

    async with contextlib.AsyncExitStack() as stack:
        await proxy.connect(stack)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    cli()
