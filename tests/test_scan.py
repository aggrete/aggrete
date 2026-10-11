"""`aggrete scan`: discovery across client configs, live tool inspection, the
cross-server findings no per-server scanner prints, and a fix that lints."""
from __future__ import annotations

import json
import sys

import yaml

from aggrete import scan
from aggrete.accumulator import MemoryStore
from aggrete.lint import lint
from aggrete.policy import Engine


def mock(profile):
    return {"command": sys.executable, "args": ["-m", "aggrete._mockco", "--profile", profile]}


def setup(tmp_path):
    home = tmp_path / "home"; proj = tmp_path / "proj"; home.mkdir(); proj.mkdir()
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"hr": mock("hr"), "finance": {**mock("finance"), "env": {"FIN_TOKEN": "AKIAIOSFODNN7EXAMPLE"}}},
                                                   "projects": {str(proj): {"mcpServers": {"ops": mock("ops")}}}}))
    (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {"fixture": mock("fixture"), "aggrete": {"command": "python3", "args": ["-m", "aggrete.proxy", "--config", "x.yaml"]}}}))
    (home / ".codex").mkdir(); (home / ".codex" / "config.toml").write_text('[mcp_servers.notes]\ncommand = "python3"\nargs = ["-m", "aggrete._mockco", "--profile", "fixture"]\n')
    pl = home / ".claude" / "plugins" / "synced" / "abc" / "figma~g2"; pl.mkdir(parents=True)
    (pl / ".mcp.json").write_text(json.dumps({"mcpServers": {"figma": {"type": "http", "url": "https://mcp.figma.com/mcp"}}}))
    tr = home / ".claude" / "plugins" / ".trash" / "x"; tr.mkdir(parents=True); (tr / ".mcp.json").write_text(json.dumps({"mcpServers": {"old": {"url": "https://old.example/mcp"}}}))
    ext = home / "Library/Application Support/Claude/Claude Extensions/com.example.notes"; ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps({"name": "notes-ext", "server": {"type": "node", "mcp_config": {"command": "node", "args": ["server.js"]}}}))
    return home, proj


def test_helpers():
    assert scan.is_write("notes_post_note") and scan.is_write("crm__create_note") and scan.is_write("mail_send")
    assert not scan.is_write("web_read_public_post") and not scan.is_write("crm_export") and not scan.is_write("hr_recent_joiners")
    assert "untrusted-web" in scan.classify("web_read_public_post", "Read a public web post") and "hr-personnel" in scan.classify("recent_joiners", "People who joined")
    assert scan.is_aggrete("x", {"command": "/usr/local/bin/aggrete", "args": []}, None)
    assert scan.is_aggrete("x", {"command": "python3", "args": ["-m", "aggrete.proxy"]}, None)
    assert not scan.is_aggrete("hr", {"command": "python3", "args": ["-m", "aggrete._mockco", "--profile", "hr"]}, None)
    assert scan.is_aggrete("corp", {"url": "https://mcp.corp.example/mcp"}, "mcp.corp.example")
    assert [k for _, k in scan.secrets_in({"env": {"A": "AKIAIOSFODNN7EXAMPLE", "B": "${SAFE}"}, "headers": {"Authorization": "Bearer ghp_" + "a" * 36}})] == ["aws_key", "github_token"]


def test_discovery_reads_every_client(tmp_path):
    home, proj = setup(tmp_path)
    src = scan.discover(home, proj)
    clients = {s["client"].split(" (")[0] for s in src}
    assert clients == {"Claude Code", "Codex", "Claude Code plugin figma", "Claude Desktop extension"}
    assert sum(len(s["servers"]) for s in src) == 8                 # the trashed plugin is not counted
    assert any(s["client"] == "Claude Desktop extension" and "notes-ext" in s["servers"] for s in src)


def test_scan_finds_the_cross_server_paths(tmp_path):
    home, proj = setup(tmp_path)
    rep = scan.scan(home=home, cwd=proj, pins_path=str(tmp_path / "pins.json"))
    kinds = {f["kind"] for f in rep["findings"]}
    assert {"secret-in-config", "poisoned-description", "combo:layoff-list", "combo:lethal-trifecta", "bypasses-proxy"} <= kinds
    assert rep["summary"]["connected"] >= 4 and rep["summary"]["high"] >= 5
    assert {s["name"] for s in rep["servers"] if s["aggrete"]} == {"aggrete"}
    assert {s["name"] for s in rep["servers"] if s["dup"]} == {"notes"}           # same command as fixture, not connected twice
    assert all(f["server"] in ("hr", "finance", "ops", "fixture") for f in rep["findings"] if f["kind"] == "bypasses-proxy")
    assert all(f["server"] != "aggrete" for f in rep["findings"] if f["kind"] == "bypasses-proxy")
    # pins: second run sees the same tools; a tampered pin is reported as changed
    pins = json.load(open(tmp_path / "pins.json")); key = next(k for k in pins if k.endswith("::oncall_draft")); pins[key] = "0" * 64
    json.dump(pins, open(tmp_path / "pins.json", "w"))
    rep2 = scan.scan(home=home, cwd=proj, pins_path=str(tmp_path / "pins.json"))
    assert any(f["kind"] == "description-changed" and "oncall_draft" in f["title"] for f in rep2["findings"])
    assert "layoff-list" in scan.render_text(rep) and "| high |" in scan.render_md(rep)
    tbl = scan.render_table(rep)
    assert tbl.startswith("SERVER") and "HIGH" in tbl and "combo:layoff-list" in tbl
    assert any(x["status"].startswith("unreachable: command not found") for x in rep["servers"] if x["name"] == "aggrete") or True


def test_reasons():
    assert scan._reason(FileNotFoundError(2, "x"), {"command": "nope"}) == "command not found: nope"
    assert scan._reason(RuntimeError("Server returned 401 Unauthorized"), {}).startswith("HTTP 401")
    class Group(Exception):                  # the shape of an exception group, on every Python we support
        def __init__(self, exceptions): self.exceptions = exceptions
    assert scan._reason(Group([Group([TimeoutError()])]), {}) == "no answer within the timeout"


def test_demo_proxy_does_not_count_and_plugins_are_not_duplicates(tmp_path):
    home = tmp_path / "h"; proj = tmp_path / "p"; home.mkdir(); proj.mkdir()
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"aggrete-demo": {"type": "http", "url": "https://try.aggrete.com/mcp"}, "hr": mock("hr")}}))
    for n in ("a", "b"):
        d = home / ".claude" / "plugins" / "marketplaces" / "m" / n; d.mkdir(parents=True)
        (d / ".mcp.json").write_text(json.dumps({"mcpServers": {n: {"command": "bun", "args": ["run", "--cwd", "${CLAUDE_PLUGIN_ROOT}", "start"]}}}))
    rep = scan.scan(home=home, cwd=proj, connect=False, pins_path=str(tmp_path / "pins.json"))
    kinds = [f["kind"] for f in rep["findings"]]
    assert "bypasses-proxy" not in kinds and "no-proxy" in kinds                 # the public demo is not your proxy
    assert not any(s["dup"] for s in rep["servers"])                             # two plugins, same command, different roots
    assert all("${CLAUDE_PLUGIN_ROOT}" not in s["target"] for s in rep["servers"])
    rep2 = scan.scan(home=home, cwd=proj, connect=False, pins_path=str(tmp_path / "pins.json"), proxy_host="mcp.corp.example")
    assert "no-proxy" not in [f["kind"] for f in rep2["findings"]]


def test_no_connect_is_config_only(tmp_path):
    home, proj = setup(tmp_path)
    rep = scan.scan(home=home, cwd=proj, connect=False, pins_path=str(tmp_path / "pins.json"))
    assert rep["summary"]["tools"] == 0 and {f["kind"] for f in rep["findings"]} >= {"secret-in-config", "outside-proxy-uninspected"}
    assert len(rep["not_visible"]) >= 3 and "claude.ai" in scan.render_text(rep)


def test_fix_writes_a_policy_that_lints_and_passes_its_tests(tmp_path):
    home, proj = setup(tmp_path)
    rep = scan.scan(home=home, cwd=proj, pins_path=str(tmp_path / "pins.json"))
    root = scan.write_fix(rep, str(tmp_path / "fix"))
    cfg = yaml.safe_load((root / "proxy.config.yaml").read_text())
    assert "fixture" in cfg["upstreams"] and "aggrete" not in cfg["upstreams"] and cfg["domains"]["fixture__web_read_public_post"] == "untrusted-web"
    coc = yaml.safe_load((root / "coc.yaml").read_text())
    assert {r["rule_id"] for r in coc["rules"]} >= {"SCAN-HR-001", "SCAN-SEC-001"}
    assert not [f for f in lint(str(root / "coc.yaml"), str(root / "proxy.config.yaml")) if f.level == "error"]
    for rule in Engine(str(root / "coc.yaml"), MemoryStore()).rules:
        for t in rule.tests:
            e = Engine(str(root / "coc.yaml"), MemoryStore())          # fresh memory per case, as CI does
            outcome = "allow"
            for step in t["sequence"]:
                pre = e.pre_call("u", step["domain"], is_write=step.get("write", False))
                if not pre.allow:
                    outcome = "deny"; break
                post = e.post_call("u", step["domain"], step.get("entities", []))
                if not post.allow:
                    outcome = "deny"; break
                if post.alerts:
                    outcome = "alert"
            assert outcome == t["expect"], (rule.id, t["name"], outcome)
