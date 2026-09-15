"""The Aggrete skill ships twice on purpose: `skills/aggrete/` for the Claude Code
plugin, `aggrete/skill/` inside the wheel so a running proxy can serve it over
MCP as skill:// resources. These keep the copies identical and the plugin valid."""

from __future__ import annotations

import json
import re
from pathlib import Path

from aggrete import skill

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_SKILL = ROOT / "skills" / "aggrete"
PACKAGE_SKILL = ROOT / "aggrete" / "skill"


def test_plugin_and_package_copies_are_identical():
    for rel in skill.FILES:
        assert (PLUGIN_SKILL / rel).read_text() == (PACKAGE_SKILL / rel).read_text(), rel


def test_skill_frontmatter_and_size():
    text = (PLUGIN_SKILL / "SKILL.md").read_text()
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, "SKILL.md must start with YAML frontmatter"
    fm = m.group(1)
    assert re.search(r"^name: aggrete$", fm, re.M)
    desc = re.search(r"^description: (.+)$", fm, re.M)
    assert desc and len(desc.group(1)) <= 1536
    assert text.count("\n") < 500
    for rel in skill.FILES[1:]:                      # every reference the guide links to exists
        assert f"references/{Path(rel).name}" in text
        assert (PLUGIN_SKILL / rel).exists()


def test_plugin_manifests_agree():
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert plugin["name"] == "aggrete"
    assert market["plugins"][0]["name"] == plugin["name"]
    assert market["plugins"][0]["source"] == "./"


def test_skill_is_served_as_resources():
    listed = skill.list_resources()
    uris = {str(r.uri) for r in listed}
    assert uris == {skill.URI_PREFIX + f for f in skill.FILES}
    assert all(r.mime_type == "text/markdown" for r in listed)
    res = skill.read_resource("skill://aggrete/SKILL.md")
    assert res is not None and res.contents[0].text.startswith("---\nname: aggrete")
    assert skill.read_resource("skill://aggrete/../etc/passwd") is None
    assert skill.read_resource("file:///etc/passwd") is None


def test_proxy_wires_resource_handlers():
    src = (ROOT / "aggrete" / "proxy.py").read_text()
    assert "on_list_resources=proxy.list_resources" in src
    assert "on_read_resource=proxy.read_resource" in src
