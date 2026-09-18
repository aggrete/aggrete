"""Black-box conformance: drive any MCP endpoint through the same scenarios.

Point your gateway at the fixture connector and run the suite against the
gateway. Nothing here knows how the gateway refuses; each fixture payload
carries a unique marker, and a scenario passes when the forbidden marker never
reaches the client.

    # the fixture upstream your gateway should front (stdio MCP server)
    python -m aggrete._mockco --profile fixture

    aggrete conformance --url https://gateway.example/mcp --token $TOKEN
    aggrete conformance --stdio "my-gateway --config gw.yaml"
    aggrete conformance --self            # Aggrete itself, fixture + reference policy
    aggrete conformance --write-fixture ./fx   # the reference config and policy

Scenarios run in one session as one identity, in a fixed order, because several
are about memory across calls.
"""

from __future__ import annotations

import json
import shlex
import sys
import tempfile
import time
from importlib import resources
from pathlib import Path

import yaml

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SSN = "123-45-6789"

# black-box scenario -> the in-process check it corresponds to (for framework mapping)
EQUIV = {"B01": ["C02"], "B02": ["C03"], "B03": ["C04"], "B04": ["C05"], "B05": ["C06"], "B06": ["C07"], "B07": ["C01", "C12"]}


def fixture_config(root: Path) -> dict:
    """Aggrete config fronting the fixture connector with the reference policy."""
    return {
        "coc": "coc.yaml", "user": "you@example.com", "audit_log": str(root / "audit.jsonl"),
        "upstreams": {"fx": {"command": sys.executable, "args": ["-m", "aggrete._mockco", "--profile", "fixture"]}},
        "domains": {"fx__fin_*": "finance-comp", "fx__hr_*": "hr-personnel", "fx__ops_*": "ops-rota",
                    "fx__web_*": "untrusted-web", "fx__notes_post_note": "shared-notes", "fx__crm_*": "crm-customers",
                    "fx__plan_*": "restructuring-plan", "fx__echo_*": "misc", "fx__notes_summarize": "notes"},
        "default_domain": "unclassified",
        "redact": ["email", "ssn", "aws_key", "api_key", "bearer"],
        "scan_inbound": True, "scan_inbound_action": "block",
        "tool_integrity": {"pins": str(root / "pins.json"), "on_change": "alert", "on_poison": "block", "scan_poison": True},
    }


def write_fixture(dest: str) -> Path:
    root = Path(dest); root.mkdir(parents=True, exist_ok=True)
    (root / "coc.yaml").write_text(resources.files("aggrete.conformance").joinpath("policy.yaml").read_text())
    (root / "proxy.config.yaml").write_text(yaml.safe_dump(fixture_config(root), sort_keys=False))
    return root


class Target:
    def __init__(self, session):
        self.s = session
        self.names: list[str] = []

    async def load(self):
        self.names = [t.name for t in (await self.s.list_tools()).tools]

    def find(self, suffix: str) -> str | None:
        """Gateways namespace tools differently (fx__x, fx_x, x); match by suffix."""
        hits = [n for n in self.names if n == suffix or n.endswith("_" + suffix) or n.endswith("." + suffix) or n.endswith("-" + suffix)]
        return sorted(hits, key=len)[0] if hits else None

    async def call(self, suffix: str, args: dict | None = None) -> tuple[bool, str]:
        """(listed, text). An exception or isError counts as text-less refusal."""
        name = self.find(suffix)
        if not name:
            return False, ""
        try:
            res = await self.s.call_tool(name, args or {})
        except Exception as e:  # a JSON-RPC error is a refusal
            return True, f"[error] {e}"
        parts = [getattr(c, "text", "") for c in (res.content or [])]
        if getattr(res, "structured_content", None) is not None:
            parts.append(json.dumps(res.structured_content, default=str))
        return True, "\n".join(parts)


async def run_scenarios(session) -> list[dict]:
    t = Target(session); await t.load()
    out: list[dict] = []

    def add(bid, title, status, evidence):
        out.append({"id": bid, "title": title, "status": status, "evidence": evidence})

    need = ["fin_budget_roles", "hr_recent_joiners", "ops_oncall_draft", "web_read_public_post", "notes_post_note", "crm_export", "echo_lookup"]
    missing = [n for n in need if not t.find(n)]
    if missing:
        add("B00", "Fixture tools are reachable through the target", "fail",
            f"not listed: {', '.join(missing)}. Front `python -m aggrete._mockco --profile fixture` with the gateway under test.")
        return out
    add("B00", "Fixture tools are reachable through the target", "pass", f"{len(t.names)} tools listed")

    # control: a write works before anything untrusted was read (the target is not just blocking everything)
    _, w0 = await t.call("notes_post_note", {"text": "control"})
    write_control = "MARKER-POSTED" in w0

    _, fin = await t.call("fin_budget_roles", {"team_name": "platform"})
    _, hr = await t.call("hr_recent_joiners", {"team_name": "platform"})
    _, ops = await t.call("ops_oncall_draft", {"team_name": "platform"})
    if "MARKER-BUDGET" not in fin or "MARKER-JOINERS" not in hr:
        add("B01", "Combination: budget + personnel + rota about the same people", "inconclusive",
            "the first two reads did not come back, so the third proves nothing")
    else:
        add("B01", "Combination: budget + personnel + rota about the same people",
            "pass" if "MARKER-ROTA" not in ops else "fail",
            "budget and joiners returned; the rota did not reach the client" if "MARKER-ROTA" not in ops
            else "all three reads returned: the combination formed")

    _, _web = await t.call("web_read_public_post")
    _, w1 = await t.call("notes_post_note", {"text": "rota: alice, bob"})
    if not write_control:
        add("B02", "Exfiltration: no write after reading untrusted content", "inconclusive",
            "the control write was refused before any untrusted read, so a refusal afterwards proves nothing")
    else:
        add("B02", "Exfiltration: no write after reading untrusted content",
            "pass" if "MARKER-POSTED" not in w1 else "fail",
            "write allowed before the untrusted read, refused after it" if "MARKER-POSTED" not in w1
            else "the write went through after an untrusted read")

    _, team = await t.call("crm_export", {"scope": "team"})
    _, allx = await t.call("crm_export", {"scope": "all"})
    if "MARKER-EXPORT-team" not in team:
        add("B03", "Arguments: the same tool allowed or refused by what it is asked", "inconclusive", "scope=team did not return")
    else:
        add("B03", "Arguments: the same tool allowed or refused by what it is asked",
            "pass" if "MARKER-EXPORT-all" not in allx else "fail",
            "scope=team returned, scope=all did not" if "MARKER-EXPORT-all" not in allx else "scope=all returned the whole base")

    add("B04", "Redaction: an SSN in a result never reaches the client",
        "pass" if SSN not in hr else "fail",
        "the joiners payload arrived without the SSN" if SSN not in hr else "the SSN arrived in clear")

    _, echo = await t.call("echo_lookup", {"note": f"use key {AWS_KEY}"})
    add("B05", "Inbound secrets: a credential in arguments never reaches the upstream",
        "pass" if AWS_KEY not in echo else "fail",
        "the upstream never echoed the key back" if AWS_KEY not in echo else "the upstream received and echoed the key")

    listed, pois = await t.call("notes_summarize", {"text": "x"})
    add("B06", "Tool poisoning: a tool with hidden instructions is not usable",
        "pass" if (not listed or "MARKER-POISON" not in pois) else "fail",
        ("not listed" if not listed else "listed but refused") if (not listed or "MARKER-POISON" not in pois) else "the poisoned tool ran")

    listed, plan = await t.call("plan_read")
    add("B07", "Walls: a tool this person may never call is hidden or refused",
        "pass" if (not listed or "MARKER-PLAN" not in plan) else "fail",
        ("not listed" if not listed else "listed but refused") if (not listed or "MARKER-PLAN" not in plan) else "the walled document was returned")

    refusals = [x for x in (ops, w1, allx) if x and "MARKER-" not in x]
    explained = [x for x in refusals if len(x) > 40 and not x.startswith("[error]")]
    add("B08", "Refusals explain themselves (rule and reason, not a bare error)",
        "pass" if refusals and len(explained) == len(refusals) else ("info" if not refusals else "fail"),
        f"{len(explained)} of {len(refusals)} refusals carried a readable reason")
    return out


async def _with_session(args, fn):
    from mcp import ClientSession
    if args.get("url"):
        from mcp.client.streamable_http import streamable_http_client
        from mcp.shared._httpx_utils import create_mcp_http_client
        headers = {"Authorization": f"Bearer {args['token']}"} if args.get("token") else None
        async with create_mcp_http_client(headers=headers) as client:
            async with streamable_http_client(args["url"], http_client=client) as (r, w, *_):
                async with ClientSession(r, w) as s:
                    await s.initialize(); return await fn(s)
    from mcp.client.stdio import StdioServerParameters, stdio_client
    cmd = args["stdio"]
    parts = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    async with stdio_client(StdioServerParameters(command=parts[0], args=parts[1:])) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize(); return await fn(s)


def run(url: str | None = None, token: str | None = None, stdio=None, self_test: bool = False) -> dict:
    import asyncio
    from . import _run
    label = url or (stdio if isinstance(stdio, str) else None)
    if self_test:
        root = write_fixture(tempfile.mkdtemp(prefix="aggrete-bb-"))
        stdio = [sys.executable, "-m", "aggrete.proxy", "--config", str(root / "proxy.config.yaml")]
        label = "aggrete (self, fixture + reference policy)"
    scenarios = _run(_with_session({"url": url, "token": token, "stdio": stdio}, run_scenarios))
    by = {s["id"]: s["status"] for s in scenarios}
    fw = yaml.safe_load(resources.files("aggrete.conformance").joinpath("frameworks.yaml").read_text())["frameworks"]
    covered = {c: b for b, cs in EQUIV.items() for c in cs}
    out_fw = []
    for f in fw:
        rows = []
        for ctl in f["controls"]:
            obs = sorted({covered[c] for c in ctl.get("checks") or [] if c in covered})
            if not obs:
                status = "not observable"
            elif any(by.get(b) == "fail" for b in obs):
                status = "fail"
            elif any(by.get(b) == "inconclusive" for b in obs):
                status = "inconclusive"
            else:
                status = "pass"
            rows.append({"id": ctl["id"], "title": ctl["title"], "status": status, "scenarios": obs})
        out_fw.append({"id": f["id"], "name": f["name"], "controls": rows,
                       "summary": {k: sum(r["status"] == k for r in rows) for k in ("pass", "fail", "inconclusive", "not observable")}})
    return {"mode": "black-box", "target": label, "generated": time.strftime("%Y-%m-%d"), "scenarios": scenarios, "frameworks": out_fw}


def render_text(rep: dict) -> str:
    out = [f"Aggrete black-box conformance, target: {rep['target']}, {rep['generated']}", ""]
    for s in rep["scenarios"]:
        out += [f"  {s['status'].upper():13} {s['id']}  {s['title']}", f"                {s['evidence']}"]
    for f in rep["frameworks"]:
        sm = f["summary"]
        out += ["", f"{f['name']}: {sm['pass']} pass, {sm['fail']} fail, {sm['inconclusive']} inconclusive, "
                    f"{sm['not observable']} not observable from outside"]
        for c in f["controls"]:
            if c["status"] != "not observable":
                out.append(f"  {c['status']:13} {c['id']:8} {c['title']}  ({', '.join(c['scenarios'])})")
    return "\n".join(out) + "\n"


def render_md(rep: dict) -> str:
    out = ["# Black-box conformance report", "", f"Target: `{rep['target']}`. Generated {rep['generated']} by `aggrete conformance`.",
           "Each scenario passes when the forbidden marker from the fixture connector never reaches the client.", "",
           "| Scenario | What it tests | Result | Evidence |", "|---|---|---|---|"]
    out += [f"| {s['id']} | {s['title']} | {s['status']} | {s['evidence']} |" for s in rep["scenarios"]]
    for f in rep["frameworks"]:
        sm = f["summary"]
        out += ["", f"## {f['name']}", "", f"{sm['pass']} pass, {sm['fail']} fail, {sm['inconclusive']} inconclusive, "
                f"{sm['not observable']} not observable from outside.", "", "| Control | Title | Status | Scenarios |", "|---|---|---|---|"]
        out += [f"| {c['id']} | {c['title']} | {c['status']} | {', '.join(c['scenarios'])} |" for c in f["controls"]]
    return "\n".join(out) + "\n"
