"""Prometheus metrics derived from audit rows, plus /healthz, /readyz, /metrics."""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.testclient import TestClient

from aggrete.accumulator import MemoryStore
from aggrete.audit import Audit
from aggrete.metrics import Metrics
from aggrete.policy import Engine
from aggrete.proxy import Proxy, ops_routes
import os

COC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "coc.yaml")


def test_counters_follow_audit_rows(tmp_path):
    m = Metrics("9.9.9")
    a = Audit(str(tmp_path / "a.jsonl"), metrics=m)
    a.emit(user="u", tool="hr__x", domain="hr-personnel", stage="pre", write=False, decision="deny", rule="COC-HR-004")
    a.emit(user="u", tool="hr__x", domain="hr-personnel", stage="post", write=False, decision="allow",
           alerts=[{"rule_id": "COC-HR-011"}], redacted={"email": 3}, upstream_ms=120.0)
    a.emit(user="u", tool="corp__plan", domain="plan", stage="pre", write=False, decision="hold", rule="COC-HR-900")
    txt = m.render()
    assert 'aggrete_build_info{version="9.9.9"} 1' in txt
    assert 'aggrete_decisions_total{decision="deny",domain="hr-personnel",stage="pre"} 1' in txt
    assert 'aggrete_rule_hits_total{decision="deny",rule="COC-HR-004"} 1' in txt
    assert 'aggrete_rule_hits_total{decision="hold",rule="COC-HR-900"} 1' in txt
    assert 'aggrete_alerts_total{rule="COC-HR-011"} 1' in txt
    assert 'aggrete_redactions_total{kind="email"} 3' in txt
    assert 'aggrete_upstream_seconds_bucket{le="0.25"} 1' in txt and "aggrete_upstream_seconds_count 1" in txt
    assert 'aggrete_upstream_seconds_bucket{le="0.1"} 0' in txt


def make_app(tmp_path, cfg_extra=None, connected=()):
    cfg = {"user": "u", "_config_dir": str(tmp_path), "domains": {}, "upstreams": {"hr": {"command": "x"}, "ops": {"command": "x"}}}
    cfg.update(cfg_extra or {})
    p = Proxy(cfg, Engine(COC, MemoryStore()), Audit(None, metrics=Metrics("1.2.3")))
    for u in connected:
        p.sessions[u] = object()
    return TestClient(Starlette(routes=ops_routes(p, cfg))), p


def test_health_ready_metrics_routes(tmp_path):
    c, p = make_app(tmp_path, connected=("hr",))
    assert c.get("/healthz").json() == {"ok": True, "version": "1.2.3"}
    r = c.get("/readyz"); assert r.status_code == 503 and r.json()["upstreams"]["missing"] == ["ops"]
    p.sessions["ops"] = object()
    assert c.get("/readyz").status_code == 200
    r = c.get("/metrics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain") and "aggrete_build_info" in r.text


def test_metrics_token_and_disable(tmp_path, monkeypatch):
    monkeypatch.setenv("MT", "s3cret")
    c, _ = make_app(tmp_path, {"metrics": {"token": "${MT}"}})
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    c2, _ = make_app(tmp_path, {"metrics": {"enabled": False}})
    assert c2.get("/metrics").status_code == 404
