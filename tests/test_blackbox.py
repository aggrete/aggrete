"""Black-box conformance: the scenarios pass against Aggrete itself over real MCP
stdio, and fail loudly against a target that governs nothing."""
from __future__ import annotations

import sys

import yaml

from aggrete.conformance import blackbox


def test_self_target_passes_every_scenario():
    rep = blackbox.run(self_test=True)
    bad = [s for s in rep["scenarios"] if s["status"] not in ("pass", "info")]
    assert not bad, bad
    assert {s["id"] for s in rep["scenarios"]} >= {"B00", "B01", "B02", "B03", "B04", "B05", "B06", "B07"}
    for f in rep["frameworks"]:
        assert f["summary"]["fail"] == 0 and f["summary"]["pass"] > 0
    assert "B01" in blackbox.render_text(rep) and "| B02 |" in blackbox.render_md(rep)


def test_ungoverned_target_fails():
    """The bare fixture connector, no gateway in front: everything leaks."""
    rep = blackbox.run(stdio=[sys.executable, "-m", "aggrete._mockco", "--profile", "fixture"])
    st = {s["id"]: s["status"] for s in rep["scenarios"]}
    assert st["B00"] == "pass"
    assert all(st[b] == "fail" for b in ("B01", "B02", "B03", "B04", "B05", "B06", "B07")), st


def test_write_fixture(tmp_path):
    root = blackbox.write_fixture(str(tmp_path / "fx"))
    cfg = yaml.safe_load((root / "proxy.config.yaml").read_text())
    assert cfg["upstreams"]["fx"]["args"][-1] == "fixture" and (root / "coc.yaml").read_text().startswith("# Conformance policy")
