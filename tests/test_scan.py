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
    assert clients == {"Claude Code", "Codex"}
    assert sum(len(s["servers"]) for s in src) == 6


def test_scan_finds_the_cross_server_paths(tmp_path):
    home, proj = setup(tmp_path)
    rep = scan.scan(home=home, cwd=proj, pins_path=str(tmp_path / "pins.json"))
    kinds = {f["kind"] for f in rep["findings"]}
    assert {"secret-in-config", "poisoned-description", "combo:layoff-list", "combo:lethal-trifecta", "bypasses-proxy"} <= kinds
    assert rep["summary"]["connected"] >= 4 and rep["summary"]["high"] >= 5
    assert {s["name"] for s in rep["servers"] if s["aggrete"]} == {"aggrete"}
    assert {s["name"] for s in rep["servers"] if s["dup"]} == {"notes"}           # same command as fixture, not connected twice
    assert all(f["server"] != "aggrete" for f in rep["findings"] if f["kind"] == "bypasses-proxy")
    # pins: second run sees the same tools; a tampered pin is reported as changed
    pins = json.load(open(tmp_path / "pins.json")); key = next(k for k in pins if k.endswith("::oncall_draft")); pins[key] = "0" * 64
    json.dump(pins, open(tmp_path / "pins.json", "w"))
    rep2 = scan.scan(home=home, cwd=proj, pins_path=str(tmp_path / "pins.json"))
    assert any(f["kind"] == "description-changed" and "oncall_draft" in f["title"] for f in rep2["findings"])
    assert "layoff-list" in scan.render_text(rep) and "| high |" in scan.render_md(rep)


def test_no_connect_is_config_only(tmp_path):
    home, proj = setup(tmp_path)
    rep = scan.scan(home=home, cwd=proj, connect=False, pins_path=str(tmp_path / "pins.json"))
    assert rep["summary"]["tools"] == 0 and {f["kind"] for f in rep["findings"]} >= {"secret-in-config", "bypasses-proxy"}


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
