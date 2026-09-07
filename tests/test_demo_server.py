"""`aggrete --demo` is a real, self-contained MCP server when a client attaches:
bundled mock upstreams plus a bundled policy, so a catalog install actually runs.
These check the policy and wiring deterministically; the stdio round-trip is
covered by manual smoke and the mcp SDK's own transport tests.
"""

from __future__ import annotations

from aggrete.accumulator import MemoryStore
from aggrete.policy import Engine
from aggrete._demo import demo_config, DEMO_DIR
from aggrete import _mockco


def demo_engine() -> Engine:
    return Engine(str(DEMO_DIR / "coc.yaml"), MemoryStore())


def run_sequence(engine, steps, user="you@aggrete.demo") -> str:
    outcome = "allow"
    for step in steps:
        if not engine.pre_call(user, step["domain"], is_write=step.get("write", False)).allow:
            return "deny"
        post = engine.post_call(user, step["domain"], step.get("entities", []))
        if not post.allow:
            return "deny"
        if post.alerts:
            outcome = "alert"
    return outcome


def test_demo_policy_loads_and_covers_every_rule():
    e = demo_engine()
    assert len(e.rules) == 3
    for rule in e.rules:                       # each rule ships an allow and a deny/alert test
        expectations = {t["expect"] for t in rule.tests}
        assert "allow" in expectations
        assert expectations & {"deny", "alert"}


def test_demo_forbidden_trio_is_refused():
    e = demo_engine()
    assert run_sequence(e, [
        {"domain": "finance-comp", "entities": ["p:a", "p:b"]},
        {"domain": "hr-personnel", "entities": ["p:a", "p:b"]},
        {"domain": "ops-rota", "entities": ["p:a"]},
    ]) == "deny"


def test_demo_arg_match_export_scope():
    e = demo_engine()
    assert e.check_args("you@aggrete.demo", "crm__export", {"scope": "all"}).allow is False
    assert e.check_args("you@aggrete.demo", "crm__export", {"scope": "team"}).allow is True


def test_demo_config_is_self_contained():
    cfg = demo_config()
    ups = cfg["upstreams"]
    assert set(ups) == {"hr", "finance", "ops"}
    for name, spec in ups.items():
        assert spec["args"][:2] == ["-m", "aggrete._mockco"]
        assert spec["args"][-1] == name
    assert cfg["domains"]["hr__*"] == "hr-personnel"
    assert "auth" not in cfg           # no auth in the demo


def test_mockco_builds_each_profile():
    for profile in ("hr", "finance", "ops"):
        assert _mockco.build(profile) is not None
