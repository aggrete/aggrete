"""The conformance suite runs the real components; every check must pass and
every framework control must map to a check or carry a note."""
from __future__ import annotations

import json

from aggrete import conformance


def test_every_check_passes_and_frameworks_are_consistent():
    rep = conformance.run()
    failed = [c for c in rep["checks"] if c["status"] != "pass"]
    assert not failed, failed
    ids = {c["id"] for c in rep["checks"]}
    for f in rep["frameworks"]:
        assert f["summary"]["fail"] == 0
        for ctl in f["controls"]:
            assert set(ctl["checks"]) <= ids, ctl
            if not ctl["checks"]:
                assert ctl["note"], f"{f['id']} {ctl['id']} has neither checks nor a note"
    md = conformance.render_md(rep); txt = conformance.render_text(rep)
    assert "| C11 |" in md and "AIUC-1" in md and "C11" in txt
    json.dumps(rep)


def test_cli_writes_markdown(tmp_path, capsys):
    out = tmp_path / "r.md"
    assert conformance.cli(["conformance", "--format", "md", "--out", str(out)]) == 0
    assert out.read_text().startswith("# Aggrete conformance report")
