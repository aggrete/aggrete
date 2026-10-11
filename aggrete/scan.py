"""`aggrete scan`: harden an existing MCP setup before (or without) the proxy.

Finds every MCP server your clients are configured to use, connects to each,
and reports the things no single-server scanner prints:

  - tool combinations across *separate* servers that form a known leak path
    (personnel + budget + rota; an untrusted reader next to a writer)
  - tool descriptions carrying hidden instructions, and descriptions that
    changed since you last looked (pinned on first sight)
  - secrets sitting in client configs, and servers reachable without the proxy
  - a GitHub token whose scopes are wider than the tools ever need (opt-in)

Then `--fix DIR` writes a proxy.config.yaml and coc.yaml that route the same
servers through Aggrete with rules for exactly the combinations it found.

    aggrete scan                      # this machine
    aggrete scan --dir ~/work/repo    # plus a project's .mcp.json / .cursor
    aggrete scan --format json        # exit 1 on any high-severity finding
    aggrete scan --fix ./aggrete      # write the config that closes the findings
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

import mcp.types as types
import yaml

from . import integrity
from .redact import BUILTIN as REDACT_BUILTIN

# ---------- discovery ----------

def _json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _toml_servers(path: Path) -> dict:
    """Codex: [mcp_servers.<name>] tables. tomllib when available (3.11+), else a
    small line parser that is enough for command/args/url/env."""
    text = path.read_text()
    try:
        import tomllib
        return tomllib.loads(text).get("mcp_servers") or {}
    except Exception:
        pass
    servers: dict = {}; cur = None; sub = None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^\[mcp_servers\.([^\].]+)(?:\.(\w+))?\]$", s)
        if m:
            cur = servers.setdefault(m.group(1), {}); sub = m.group(2)
            if sub:
                cur = cur.setdefault(sub, {})
            continue
        if cur is None or "=" not in s or s.startswith("#"):
            continue
        k, _, v = s.partition("="); k = k.strip(); v = v.strip()
        try:
            cur[k] = json.loads(v)
        except Exception:
            cur[k] = v.strip('"')
    return servers


def discover(home: Path | None = None, cwd: Path | None = None, extra: list[str] | None = None) -> list[dict]:
    """Every MCP client config we know how to read. Returns [{client, path, servers}]."""
    home = Path(home or Path.home()); cwd = Path(cwd or Path.cwd())
    found: list[dict] = []

    def add(client, path, servers):
        if servers:
            found.append({"client": client, "path": str(path), "servers": servers})

    cj = _json(home / ".claude.json") or {}
    add("Claude Code (user)", home / ".claude.json", cj.get("mcpServers") or {})
    for proj, pd in (cj.get("projects") or {}).items():
        if isinstance(pd, dict) and pd.get("mcpServers"):
            add(f"Claude Code (local, {proj})", home / ".claude.json", pd["mcpServers"])
    for p in ("/Library/Application Support/ClaudeCode/managed-mcp.json", "/etc/claude-code/managed-mcp.json"):
        d = _json(Path(p)) or {}
        add("Claude Code (managed)", p, d.get("mcpServers") or {})
    d = _json(cwd / ".mcp.json") or {}
    add("Claude Code (project)", cwd / ".mcp.json", d.get("mcpServers") or {})
    for p in (home / "Library/Application Support/Claude/claude_desktop_config.json",
              home / ".config/Claude/claude_desktop_config.json",
              home / "AppData/Roaming/Claude/claude_desktop_config.json"):
        d = _json(p) or {}
        add("Claude Desktop", p, d.get("mcpServers") or {})
    for p in (home / ".cursor/mcp.json", cwd / ".cursor/mcp.json"):
        d = _json(p) or {}
        add("Cursor", p, d.get("mcpServers") or {})
    for p in (home / "Library/Application Support/Code/User/mcp.json", home / ".config/Code/User/mcp.json",
              home / "AppData/Roaming/Code/User/mcp.json", cwd / ".vscode/mcp.json"):
        d = _json(p) or {}
        add("VS Code / Copilot", p, d.get("servers") or d.get("mcpServers") or {})
    p = home / ".codeium/windsurf/mcp_config.json"; d = _json(p) or {}
    add("Windsurf", p, d.get("mcpServers") or {})
    p = home / ".gemini/settings.json"; d = _json(p) or {}
    add("Gemini CLI", p, d.get("mcpServers") or {})
    p = home / ".codex/config.toml"
    if p.exists():
        try:
            add("Codex", p, _toml_servers(p))
        except Exception:
            pass
    # Claude Code plugins (marketplace and synced): each ships its own .mcp.json
    plug = home / ".claude" / "plugins"
    if plug.is_dir():
        for mp in sorted(plug.rglob(".mcp.json")):
            if ".trash" in mp.parts:
                continue
            d = _json(mp) or {}
            add(f"Claude Code plugin {mp.parent.name.split('~')[0]}", mp, d.get("mcpServers") or {})
    # Claude Desktop extensions (.mcpb / DXT bundles): manifest.json carries the server
    for extdir in (home / "Library/Application Support/Claude/Claude Extensions",
                   home / "AppData/Roaming/Claude/Claude Extensions", home / ".config/Claude/Claude Extensions"):
        if extdir.is_dir():
            for mf in sorted(extdir.glob("*/manifest.json")):
                d = _json(mf) or {}
                srv = (d.get("server") or {}).get("mcp_config") or {}
                if srv:
                    add("Claude Desktop extension", mf, {d.get("name") or mf.parent.name: srv})
    # Claude Desktop agent mode (Cowork) keeps a copy of the servers each session ran
    sess = home / "Library/Application Support/Claude/local-agent-mode-sessions"
    if sess.is_dir():
        seen: set = set()
        for cj2 in sess.rglob(".claude.json"):
            d = _json(cj2) or {}
            for name, spec in (d.get("mcpServers") or {}).items():
                k = json.dumps(spec, sort_keys=True, default=str)
                if k not in seen:
                    seen.add(k); add("Claude Desktop (agent mode)", cj2, {name: spec})
    # VS Code settings.json `mcp.servers` (older layout); Cline; Continue; Zed; Goose
    for p in (home / "Library/Application Support/Code/User/settings.json", home / ".config/Code/User/settings.json"):
        if p.exists():
            try:
                t = re.sub(r"^\s*//.*$", "", p.read_text(), flags=re.M); t = re.sub(r",(\s*[}\]])", r"\1", t)
                d = json.loads(t); add("VS Code settings", p, ((d.get("mcp") or {}).get("servers")) or {})
            except Exception:
                pass
    for client, p, key in (("Cline", home / "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "mcpServers"),
                           ("Zed", home / ".config/zed/settings.json", "context_servers")):
        d = _json(p) or {}
        add(client, p, d.get(key) or {})
    for e in extra or []:
        ep = Path(e).expanduser(); d = _json(ep) or {}
        add(f"file {ep.name}", ep, d.get("mcpServers") or d.get("servers") or {})
    return found


# Connector surfaces that are not on disk. The scan says so rather than seeing less quietly.
NOT_VISIBLE = [
    ("claude.ai connectors (web, Desktop, Cowork)", "stored in your Claude account, not on this machine",
     "claude.ai -> Settings -> Connectors; org-wide at claude.ai/admin-settings. With enterprise-managed auth an admin can point every connector at the proxy."),
    ("ChatGPT apps and connectors", "stored in your OpenAI account",
     "ChatGPT -> Settings -> Apps, or the workspace admin console."),
    ("Microsoft 365 Copilot connectors and agents", "tenant-side, in Entra and Agent 365",
     "Microsoft 365 admin center -> Copilot; Agent 365 for the inventory."),
    ("IDE-extension-provided servers (VS Code, JetBrains)", "registered by extensions at runtime, not in a config file",
     "the client's own MCP server list in its UI."),
]


# ---------- classification ----------

DOMAIN_HINTS = {
    "hr-personnel": ["hr", "employee", "people", "person", "staff", "joiner", "leaver", "headcount", "org_chart", "orgchart", "leave", "absence", "timesheet", "workday", "bamboo"],
    "finance-comp": ["budget", "salary", "pay", "comp", "payroll", "finance", "invoice", "expense", "ledger"],
    "ops-rota": ["oncall", "on_call", "rota", "roster", "shift", "schedule", "pagerduty", "opsgenie"],
    "untrusted-web": ["fetch", "browse", "web", "http", "url", "scrape", "search", "public_post", "rss", "read_page", "crawl"],
    "private-code": ["repo", "git", "code", "source", "commit", "pull_request", "branch"],
    "crm-customers": ["crm", "customer", "account", "lead", "contact", "salesforce", "hubspot", "deal", "opportunity"],
    "secrets-store": ["secret", "vault", "credential", "api_key", "token", "password", "kms"],
    "shared-notes": ["note", "wiki", "doc", "page", "confluence", "notion", "drive", "file"],
    "chat": ["slack", "teams", "discord", "message", "channel", "dm"],
    "mail": ["mail", "email", "gmail", "outlook", "smtp"],
}
WRITE_VERBS = ("create", "update", "write", "upload", "delete", "post", "send", "share", "publish", "comment", "reply", "push", "merge", "set_", "put", "patch", "remove", "execute", "run")
SECRET_RES = {name: REDACT_BUILTIN[name] for name in ("aws_key", "api_key", "bearer") if name in REDACT_BUILTIN}
SECRET_RES["github_token"] = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}")
SECRET_RES["slack_token"] = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")
SECRET_RES["private_key"] = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

COMBOS = [
    {"id": "layoff-list", "severity": "high", "need": ["hr-personnel", "finance-comp", "ops-rota"],
     "title": "Personnel + budget + rota are all reachable: the layoff-list path",
     "why": "Each read is allowed on its own. Together, about the same people, they name who is about to leave. Nothing in the clients stops the fourth question."},
    {"id": "lethal-trifecta", "severity": "high", "need": ["untrusted-web", "WRITE"],
     "title": "An untrusted reader sits next to a writer: the exfiltration path",
     "why": "A web page or inbound message can carry instructions. Once the assistant reads it, any write tool is a way out. This is the 2025 GitHub MCP attack and the 2026 Copilot invoice attack."},
    {"id": "code-exfil", "severity": "high", "need": ["untrusted-web", "private-code"],
     "title": "Untrusted content next to private code",
     "why": "Instructions hidden in a public issue or page can point the assistant at private repositories."},
    {"id": "secrets-egress", "severity": "high", "need": ["secrets-store", "WRITE"],
     "title": "A secrets or credential tool next to a writer",
     "why": "Anything that can read a secret and anything that can send is a credential-exfiltration path."},
    {"id": "pay-ranking", "severity": "medium", "need": ["finance-comp", "hr-personnel"],
     "title": "Pay data next to people data",
     "why": "Pay bands plus a team list is a named pay ranking."},
    {"id": "crm-export", "severity": "medium", "need": ["crm-customers", "WRITE"],
     "title": "Customer records next to a writer",
     "why": "Bulk customer data can leave through any send or post tool."},
]


def classify(tool_name: str, description: str | None) -> list[str]:
    hay = (tool_name + " " + (description or "")).lower()
    hay = re.sub(r"[^a-z0-9_]+", " ", hay)
    out = []
    for dom, hints in DOMAIN_HINTS.items():
        if any(re.search(r"(^|[\s_])" + re.escape(h) + r"($|[\s_])", hay) or h in tool_name.lower() for h in hints):
            out.append(dom)
    return out


READ_VERBS = ("read", "get", "list", "search", "fetch", "find", "query", "lookup", "describe", "show", "view", "browse", "scrape", "export", "summarize", "check")
WRITE_TOKENS = ("create", "update", "write", "upload", "delete", "post", "send", "share", "publish", "comment", "reply", "push", "merge", "set", "put", "patch", "remove", "execute", "run", "add", "edit", "move", "rename", "approve", "submit")


def is_write(tool_name: str) -> bool:
    """Does the tool act on the world? Decided by the first verb in the name, so
    read_public_post is a read and notes_post_note is a write."""
    tokens = re.split(r"[_\-.\s]+", tool_name.split("__")[-1].lower())
    for tok in tokens:
        if tok in READ_VERBS:
            return False
        if tok in WRITE_TOKENS:
            return True
    return False


def is_aggrete(name: str, spec: dict, proxy_host: str | None) -> bool:
    """Is this entry the Aggrete proxy itself (as opposed to a server it should front)?"""
    cmd = str(spec.get("command") or "")
    args = [str(a) for a in (spec.get("args") or [])]
    url = str(spec.get("url") or "")
    if os.path.basename(cmd) == "aggrete" or "aggrete.proxy" in args or (len(args) >= 1 and args[0] == "aggrete"):
        return True
    if url and (("aggrete" in url.lower()) or (proxy_host and proxy_host in url)):
        return True
    return name.lower() in ("aggrete", "aggrete-proxy", "aggrete-demo") and not any("_mockco" in a for a in args)


def secrets_in(spec: dict) -> list[tuple[str, str]]:
    hits = []
    def check(where, value):
        if not isinstance(value, str) or value.startswith("${"):
            return
        # most specific kind wins per value (a GitHub token is also a bearer token)
        for kind in ("private_key", "github_token", "slack_token", "aws_key", "api_key", "bearer"):
            rx = SECRET_RES.get(kind)
            if rx and rx.search(value):
                hits.append((where, kind)); return
    for k, v in (spec.get("env") or {}).items():
        check(f"env {k}", v)
    for k, v in (spec.get("headers") or {}).items():
        check(f"header {k}", v)
    for a in spec.get("args") or []:
        check("args", a)
    check("url", spec.get("url") or "")
    return hits


# ---------- connecting ----------

async def _list_tools(spec: dict, timeout: float) -> list[dict]:
    from mcp import ClientSession

    async def go():
        if spec.get("url"):
            from mcp.client.streamable_http import streamable_http_client
            from mcp.shared._httpx_utils import create_mcp_http_client
            headers = {k: os.path.expandvars(str(v)) for k, v in (spec.get("headers") or {}).items()}
            async with create_mcp_http_client(headers=headers or None) as client:
                async with streamable_http_client(os.path.expandvars(str(spec["url"])), http_client=client) as (r, w, *_):
                    async with ClientSession(r, w) as s:
                        await s.initialize()
                        return [{"name": t.name, "description": t.description, "schema": t.input_schema} for t in (await s.list_tools()).tools]
        from mcp.client.stdio import StdioServerParameters, stdio_client
        cmd = spec.get("command")
        if cmd in ("python", "python3"):
            cmd = sys.executable
        env = {**os.environ, **{k: os.path.expandvars(str(v)) for k, v in (spec.get("env") or {}).items()}}
        async with stdio_client(StdioServerParameters(command=cmd, args=[str(a) for a in spec.get("args") or []], env=env)) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                return [{"name": t.name, "description": t.description, "schema": t.input_schema} for t in (await s.list_tools()).tools]
    return await asyncio.wait_for(go(), timeout)


def _reason(e: BaseException, spec: dict) -> str:
    """The leaf cause of a connection failure, in words a person can act on."""
    # Exception groups (3.11+ builtin, anyio backport on 3.10): walk to the first leaf
    while getattr(e, "exceptions", None):
        e = e.exceptions[0]
    name = type(e).__name__
    msg = " ".join(str(x) for x in (e, getattr(e, "message", ""), getattr(e, "data", ""), getattr(e, "code", "")) if x)
    m = re.search(r"\b(401|403|404|407|500|502|503)\b", msg)
    if m:
        code = m.group(1)
        return {"401": "HTTP 401, sign-in required (OAuth or a token the config does not carry)",
                "403": "HTTP 403, forbidden with the credentials in the config",
                "404": "HTTP 404, no MCP endpoint at that URL"}.get(code, f"HTTP {code}")
    if isinstance(e, FileNotFoundError) or name == "FileNotFoundError":
        return f"command not found: {spec.get('command')}"
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)) or "Timeout" in name:
        return "no answer within the timeout"
    if "Connect" in name or "connection" in msg.lower():
        return "connection refused or host unreachable"
    if name == "MCPError":
        return "the server answered with an error during handshake" + (f" ({getattr(e, 'code', '')})" if getattr(e, "code", None) else "")
    return f"{name}: {str(e)[:80]}" if str(e) else name


def _run(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


def github_scopes(token: str) -> list[str] | None:
    """Scopes of a classic or fine-grained GitHub token, from a harmless GET /user."""
    import urllib.request
    req = urllib.request.Request("https://api.github.com/user", headers={"Authorization": f"Bearer {token}", "User-Agent": "aggrete-scan"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            sc = r.headers.get("X-OAuth-Scopes") or ""
            return [s.strip() for s in sc.split(",") if s.strip()]
    except Exception:
        return None


# ---------- the scan ----------

def scan(home=None, cwd=None, extra=None, connect=True, timeout=15.0, pins_path: str | None = None,
         proxy_host: str | None = None, check_scopes=False) -> dict:
    sources = discover(home, cwd, extra)
    pins = integrity.PinStore(pins_path or str(Path(home or Path.home()) / ".aggrete" / "scan-pins.json"))
    servers: list[dict] = []
    findings: list[dict] = []
    seen_keys: set[str] = set()
    has_proxy = False

    def finding(sev, kind, title, detail, server=None, fix=None):
        findings.append({"severity": sev, "kind": kind, "title": title, "detail": detail, "server": server, "fix": fix})

    for src in sources:
        for name, spec in src["servers"].items():
            if not isinstance(spec, dict):
                continue
            cmd_key = sys.executable if spec.get("command") in ("python", "python3") else spec.get("command")
            key = json.dumps({"c": cmd_key, "a": spec.get("args"), "u": spec.get("url")}, sort_keys=True)
            dup = key in seen_keys; seen_keys.add(key)
            srv = {"name": name, "client": src["client"], "path": src["path"], "transport": "http" if spec.get("url") else "stdio",
                   "target": spec.get("url") or " ".join([str(spec.get("command") or "")] + [str(a) for a in spec.get("args") or []]),
                   "aggrete": is_aggrete(name, spec, proxy_host), "tools": [], "domains": set(), "writes": [], "status": "not connected", "dup": dup}
            has_proxy = has_proxy or srv["aggrete"]
            for where, kind in secrets_in(spec):
                finding("high", "secret-in-config", f"A {kind.replace('_', ' ')} sits in {src['client']}'s config for '{name}'",
                        f"{where} in {src['path']}. Anyone who can read that file holds the credential, and every tool call carries it.",
                        name, "Move it to the environment and reference it as ${VAR}; with the proxy, the credential lives only on the proxy host.")
            if spec.get("url") and not (spec.get("headers") or {}).get("Authorization") and not srv["aggrete"] and not str(spec["url"]).startswith("http://127.") and not str(spec["url"]).startswith("http://localhost"):
                finding("medium", "no-auth-header", f"'{name}' is a remote server with no Authorization header in the config",
                        f"{spec['url']}. Either the server is unauthenticated, or sign-in happens elsewhere; the scan cannot tell.", name)
            if connect and not dup:
                try:
                    tools = _run(_list_tools(spec, timeout)); srv["status"] = "connected"
                except Exception as e:
                    srv["status"] = "unreachable: " + _reason(e, spec); tools = []
                for t in tools:
                    fp = integrity.fingerprint(t["name"], t["description"], t["schema"])
                    st = pins.check(f"{name}::{t['name']}", fp)
                    poison = integrity.scan_poison(t["description"])
                    doms = classify(t["name"], t["description"]); w = is_write(t["name"])
                    srv["tools"].append({"name": t["name"], "pin": st, "poison": poison, "domains": doms, "write": w})
                    srv["domains"].update(doms)
                    if w:
                        srv["writes"].append(t["name"])
                    if poison:
                        finding("high", "poisoned-description", f"Tool '{t['name']}' on '{name}' carries hidden instructions in its description",
                                f"Matched: {'; '.join(poison)}. The user never sees a tool description; the model does.", name,
                                "Remove the server, or front it with the proxy with tool_integrity.on_poison: block.")
                    if st == "changed":
                        finding("medium", "description-changed", f"Tool '{t['name']}' on '{name}' changed since it was last seen",
                                "Its description or schema differs from the pinned fingerprint. A tool approved once that now behaves differently is a rug pull.", name,
                                "Review the change; re-pin deliberately. The proxy enforces this at every call (tool_integrity.on_change).")
            servers.append(srv)

    # cross-server combinations: the thing no per-server scanner prints
    governed = [s for s in servers if not s["aggrete"]]
    all_doms: dict[str, list[str]] = {}
    writers: list[str] = []
    for s in governed:
        for d in s["domains"]:
            all_doms.setdefault(d, []).append(s["name"])
        if s["writes"]:
            writers.append(s["name"])
    for c in COMBOS:
        parts = []
        ok = True
        for need in c["need"]:
            if need == "WRITE":
                if writers:
                    parts.append(f"writers: {', '.join(sorted(set(writers))[:4])}")
                else:
                    ok = False
            elif need in all_doms:
                parts.append(f"{need}: {', '.join(sorted(set(all_doms[need]))[:4])}")
            else:
                ok = False
        if ok:
            across = len({p.split(':')[1] for p in parts}) > 1 or len(c["need"]) == 1
            finding(c["severity"], f"combo:{c['id']}", c["title"], c["why"] + " Present via " + "; ".join(parts) + ".",
                    None, "Route these servers through the proxy; `aggrete scan --fix` writes the rule for exactly this combination.")
    if has_proxy:
        for s in governed:
            carries_data = bool(s["domains"] or s["writes"]) or s["status"] != "connected"
            if carries_data:
                finding("high", "bypasses-proxy", f"'{s['name']}' ({s['client']}) is reachable without going through Aggrete",
                        f"{s['target']}. A policy is only a control if the proxy is the only path; this client has a second road."
                        + ("" if s["status"] == "connected" else " It could not be inspected, so treat it as if it carried data."), s["name"],
                        "Remove the direct entry and expose the server as an upstream of the proxy instead (docs/DEPLOY.md, 'The only path').")
            else:
                finding("info", "outside-proxy", f"'{s['name']}' ({s['client']}) runs outside Aggrete, but exposes no data domains",
                        f"{s['target']}. {len(s['tools'])} tools, none recognised as reading company data or writing out. A utility server; worth knowing, not a leak path.", s["name"])
    if check_scopes:
        for src in sources:
            for name, spec in src["servers"].items():
                for k, v in (spec.get("env") or {}).items():
                    if isinstance(v, str) and SECRET_RES["github_token"].search(v):
                        scopes = github_scopes(v)
                        srv = next((s for s in servers if s["name"] == name), None)
                        if scopes is not None and srv is not None:
                            writes = bool(srv["writes"])
                            broad = [sc for sc in scopes if sc in ("repo", "write:org", "admin:org", "delete_repo", "workflow", "admin:repo_hook")]
                            if broad and not writes:
                                finding("medium", "scope-wider-than-use", f"The GitHub token for '{name}' has {', '.join(broad)} but its tools only read",
                                        f"Scopes: {', '.join(scopes)}. Tools seen: {len(srv['tools'])}, writers: none.", name,
                                        "Issue a read-only token for this server; let the proxy hold the broad one if a write tool ever needs it.")
    for s in servers:
        s["domains"] = sorted(s["domains"])
    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    return {"generated": time.strftime("%Y-%m-%d %H:%M"), "sources": [{"client": s["client"], "path": s["path"], "servers": len(s["servers"])} for s in sources],
            "not_visible": [{"surface": a, "why": b, "where": c} for a, b, c in NOT_VISIBLE],
            "servers": servers, "findings": findings, "proxy_present": has_proxy,
            "summary": {"servers": len(servers), "connected": sum(s["status"] == "connected" for s in servers),
                        "tools": sum(len(s["tools"]) for s in servers),
                        "high": sum(f["severity"] == "high" for f in findings), "medium": sum(f["severity"] == "medium" for f in findings),
                        "info": sum(f["severity"] == "info" for f in findings)}}


# ---------- fix ----------

def write_fix(rep: dict, dest: str) -> Path:
    """A proxy.config.yaml fronting the discovered servers and a coc.yaml with
    rules for the combinations the scan found."""
    root = Path(dest); root.mkdir(parents=True, exist_ok=True)
    ups: dict = {}; domains: dict = {}
    for s in rep["servers"]:
        if s["aggrete"] or s["dup"]:
            continue
        key = re.sub(r"[^a-z0-9]+", "_", s["name"].lower()).strip("_") or "srv"
        if s["transport"] == "http":
            ups[key] = {"url": s["target"]}
        else:
            parts = s["target"].split()
            ups[key] = {"command": parts[0], "args": parts[1:]}
        for t in s["tools"]:
            for d in t["domains"][:1]:
                domains[f"{key}__{t['name']}"] = d
        if s["domains"]:
            domains[f"{key}__*"] = s["domains"][0]
    cfg = {"coc": "coc.yaml", "user": "you@example.com", "audit_log": "audit.jsonl",
           "redact": ["email", "ssn", "credit_card", "aws_key", "api_key", "bearer"],
           "scan_inbound": True, "scan_inbound_action": "block",
           "tool_integrity": {"pins": "tool-pins.json", "on_change": "alert", "on_poison": "block", "scan_poison": True},
           "upstreams": ups, "domains": domains, "default_domain": "unclassified"}
    rules = []
    kinds = {f["kind"] for f in rep["findings"]}
    if "combo:layoff-list" in kinds or "combo:pay-ranking" in kinds:
        rules.append({"rule_id": "SCAN-HR-001", "title": "Combining personnel, budget and rotation records", "owner": "hr-privacy@example.com", "severity": "high",
                      "clause": "Personnel records, compensation or budget records, and operational rosters may not be combined to derive the employment status or planned departure of identifiable individuals.",
                      "remediation": "Request a purpose-bound session from HR Privacy.",
                      "enforce": [{"layer": "accumulation", "action": "alert", "type": "domain_join", "domains": ["hr-personnel", "finance-comp", "ops-rota"], "require_entity_overlap": True, "scope": "user", "window": "4h"}],
                      "tests": [{"name": "trio", "expect": "alert", "sequence": [{"domain": "finance-comp", "entities": ["p:a"]}, {"domain": "hr-personnel", "entities": ["p:a"]}, {"domain": "ops-rota", "entities": ["p:a"]}]},
                                {"name": "pair_ok", "expect": "allow", "sequence": [{"domain": "finance-comp", "entities": ["p:a"]}, {"domain": "ops-rota", "entities": ["p:a"]}]}]})
    if "combo:lethal-trifecta" in kinds or "combo:code-exfil" in kinds or "combo:secrets-egress" in kinds:
        rules.append({"rule_id": "SCAN-SEC-001", "title": "No egress after untrusted content", "owner": "security@example.com", "severity": "critical",
                      "clause": "After reading untrusted content, an assistant may not send, post, share or reach private code until the task ends.",
                      "remediation": "Finish the task; start a new session for the write.",
                      "enforce": [{"layer": "retrieval", "action": "deny", "type": "flow", "taint_domains": ["untrusted-web"], "egress_domains": ["private-code", "secrets-store", "mail", "chat"]}],
                      "tests": [{"name": "write_ok", "expect": "allow", "sequence": [{"domain": "shared-notes", "entities": [], "write": True}]},
                                {"name": "write_after_untrusted", "expect": "deny", "sequence": [{"domain": "untrusted-web", "entities": []}, {"domain": "shared-notes", "entities": [], "write": True}]}]})
    if "combo:crm-export" in kinds:
        rules.append({"rule_id": "SCAN-CRM-001", "title": "Bulk customer extraction", "owner": "data-governance@example.com", "severity": "medium",
                      "clause": "Assistants may not assemble large lists of customer records beyond what a single task requires.",
                      "remediation": "Bulk extracts go through the analytics team.",
                      "enforce": [{"layer": "accumulation", "action": "alert", "type": "entity_budget", "domain": "crm-customers", "max_distinct": 25, "scope": "user", "window": "24h"}],
                      "tests": [{"name": "few", "expect": "allow", "sequence": [{"domain": "crm-customers", "entities": ["p:a", "p:b"]}]},
                                {"name": "many", "expect": "alert", "sequence": [{"domain": "crm-customers", "entities": [f"p:{i}" for i in range(30)]}]}]})
    coc = {"version": 1, "defaults": {"window": "24h", "entity_kind": "person"}, "rules": rules}
    (root / "proxy.config.yaml").write_text("# Written by `aggrete scan --fix`. Review the domain map, then: aggrete --config proxy.config.yaml\n" + yaml.safe_dump(cfg, sort_keys=False))
    (root / "coc.yaml").write_text("# Written by `aggrete scan --fix` for the combinations the scan found. Every rule starts at alert; flip to deny once tuned.\n" + yaml.safe_dump(coc, sort_keys=False))
    return root


# ---------- output ----------

def render_text(rep: dict) -> str:
    s = rep["summary"]
    out = [f"aggrete scan, {rep['generated']}", "",
           f"  {s['servers']} MCP servers across {len(rep['sources'])} client configs, {s['connected']} reachable, {s['tools']} tools",
           f"  {s['high']} high, {s['medium']} medium, {s.get('info', 0)} informational" + ("" if rep["findings"] else "  (nothing to report)"), ""]
    for srv in rep["servers"]:
        tag = " [aggrete]" if srv["aggrete"] else (" [duplicate]" if srv["dup"] else "")
        out.append(f"  {srv['name']:<22} {srv['client']:<28} {srv['status']:<24}{tag}")
        if srv["tools"]:
            out.append(f"  {'':<22} {len(srv['tools'])} tools, domains: {', '.join(srv['domains']) or '-'}; writers: {', '.join(srv['writes'][:5]) or 'none'}")
    for f in rep["findings"]:
        out += ["", f"  {f['severity'].upper():6} {f['title']}", f"         {f['detail']}"]
        if f.get("fix"):
            out.append(f"         fix: {f['fix']}")
    if rep.get("not_visible"):
        out += ["", "  Not visible from this machine (inventory them where they live):"]
        out += [f"    {a['surface']}: {a['why']}. See {a['where']}" for a in rep["not_visible"]]
    if rep["findings"]:
        out += ["", "  aggrete scan --fix ./aggrete   writes a proxy config and policy that close these."]
    out += ["  --format table | md | json      same scan as a table, Markdown, or machine-readable JSON"]
    return "\n".join(out) + "\n"


def render_table(rep: dict) -> str:
    """Compact, aligned, no prose: one row per server, one row per finding."""
    s = rep["summary"]
    cut = lambda t, n: t if len(t) <= n else t[:n - 1] + "…"
    rows = [["SERVER", "CLIENT", "STATUS", "DOMAINS", "WRITERS"]]
    for x in rep["servers"]:
        rows.append([cut(x["name"] + (" (aggrete)" if x["aggrete"] else ""), 26), cut(x["client"], 28), cut(x["status"], 40),
                     cut(", ".join(x["domains"]) or "-", 44), cut(", ".join(x["writes"][:3]) + ("…" if len(x["writes"]) > 3 else "") or "-", 28)])
    out = _table(rows)
    out += f"\n{s['servers']} servers, {s['connected']} reachable, {s['tools']} tools. {s['high']} high, {s['medium']} medium, {s.get('info', 0)} info.\n"
    if rep["findings"]:
        frows = [["SEV", "FINDING", "SERVER", "KIND"]]
        for f in rep["findings"]:
            frows.append([f["severity"].upper(), cut(f["title"], 80), cut(f.get("server") or "-", 20), f["kind"]])
        out += "\n" + _table(frows)
    return out


def _table(rows: list[list[str]]) -> str:
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for n, r in enumerate(rows):
        lines.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip())
        if n == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines) + "\n"


def render_md(rep: dict) -> str:
    s = rep["summary"]
    out = ["# MCP hardening scan", "", f"{rep['generated']}. {s['servers']} servers, {s['connected']} reachable, {s['tools']} tools. **{s['high']} high, {s['medium']} medium.**", "",
           "| server | client | status | domains | writers |", "|---|---|---|---|---|"]
    out += [f"| {x['name']}{' (aggrete)' if x['aggrete'] else ''} | {x['client']} | {x['status']} | {', '.join(x['domains'])} | {', '.join(x['writes'][:4])} |" for x in rep["servers"]]
    out += ["", "| severity | finding | detail | fix |", "|---|---|---|---|"]
    out += [f"| {f['severity']} | {f['title']} | {f['detail']} | {f.get('fix') or ''} |" for f in rep["findings"]]
    return "\n".join(out) + "\n"


def cli(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="aggrete scan", description="Find leak paths, poisoned tools, secrets and bypasses in an existing MCP setup.")
    ap.add_argument("--dir", default=None, help="a project directory (its .mcp.json, .cursor, .vscode)")
    ap.add_argument("--config", action="append", default=[], help="an extra client config file (repeatable)")
    ap.add_argument("--no-connect", action="store_true", help="read configs only; do not start or contact servers")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--proxy", default=None, help="host of your Aggrete proxy, to flag servers that bypass it")
    ap.add_argument("--check-scopes", action="store_true", help="compare a GitHub token's scopes with what its tools use (one GET /user)")
    ap.add_argument("--format", choices=["text", "table", "md", "json"], default="text",
                    help="text (default, with explanations), table (compact), md (Markdown for a report), json (for CI)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--fix", metavar="DIR", default=None, help="write proxy.config.yaml and coc.yaml that close the findings")
    ns = ap.parse_args(argv[1:])
    rep = scan(cwd=ns.dir, extra=ns.config, connect=not ns.no_connect, timeout=ns.timeout, proxy_host=ns.proxy, check_scopes=ns.check_scopes)
    text = {"text": render_text, "table": render_table, "json": lambda r: json.dumps(r, indent=2, default=list), "md": render_md}[ns.format](rep)
    if ns.out:
        Path(ns.out).write_text(text); print(f"wrote {ns.out}")
    else:
        print(text, end="")
    if ns.fix:
        root = write_fix(rep, ns.fix)
        print(f"wrote {root}/proxy.config.yaml and {root}/coc.yaml. Review the domain map, then: aggrete --config {root}/proxy.config.yaml")
    return 1 if rep["summary"]["high"] else 0
