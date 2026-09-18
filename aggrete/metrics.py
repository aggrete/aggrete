"""Prometheus metrics, dependency-free.

Counters are derived from audit rows as they are emitted, so the numbers on
`/metrics` are exactly the decisions in `audit.jsonl`. Label sets are bounded
by construction (stages, decisions, rule ids, domains), never by user or tool
arguments.
"""

from __future__ import annotations

import threading

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def _lbl(labels: dict) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{str(v).replace(chr(92), chr(92)*2).replace(chr(34), chr(92)+chr(34))}"'
                     for k, v in sorted(labels.items()))
    return "{" + inner + "}"


class Metrics:
    def __init__(self, version: str = "0"):
        self.version = version
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = {}
        self._hist_buckets: dict[float, int] = {b: 0 for b in LATENCY_BUCKETS}
        self._hist_inf = 0
        self._hist_sum = 0.0
        self._hist_count = 0

    # ---------- recording ----------

    def inc(self, name: str, labels: dict | None = None, by: float = 1.0) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._counters.setdefault(name, {})
            self._counters[name][key] = self._counters[name].get(key, 0.0) + by

    def observe_latency(self, seconds: float) -> None:
        with self._lock:
            for b in LATENCY_BUCKETS:
                if seconds <= b:
                    self._hist_buckets[b] += 1
            self._hist_inf += 1
            self._hist_sum += seconds
            self._hist_count += 1

    def observe(self, row: dict) -> None:
        """Update counters from one audit row (called by Audit.emit)."""
        stage = str(row.get("stage") or "-")
        decision = str(row.get("decision") or "-")
        self.inc("aggrete_decisions_total", {"stage": stage, "decision": decision,
                                             "domain": str(row.get("domain") or "-")})
        rule = row.get("rule")
        if rule and decision in ("deny", "hold", "approved", "denied"):
            self.inc("aggrete_rule_hits_total", {"rule": str(rule), "decision": decision})
        for a in row.get("alerts") or []:
            if isinstance(a, dict) and a.get("rule_id"):
                self.inc("aggrete_alerts_total", {"rule": str(a["rule_id"])})
        for kind, n in (row.get("redacted") or {}).items():
            self.inc("aggrete_redactions_total", {"kind": str(kind)}, by=float(n or 0))
        if row.get("upstream_ms") is not None:
            self.observe_latency(float(row["upstream_ms"]) / 1000.0)

    # ---------- exposition ----------

    def render(self) -> str:
        out = ["# HELP aggrete_build_info Aggrete version.", "# TYPE aggrete_build_info gauge",
               f'aggrete_build_info{_lbl({"version": self.version})} 1']
        help_ = {
            "aggrete_decisions_total": "Policy decisions by stage, decision and domain (one per audit row).",
            "aggrete_rule_hits_total": "Refusals, holds and approval outcomes by rule id.",
            "aggrete_alerts_total": "Alert-only rule matches by rule id.",
            "aggrete_redactions_total": "Values masked in results by kind.",
        }
        with self._lock:
            for name in ("aggrete_decisions_total", "aggrete_rule_hits_total", "aggrete_alerts_total",
                         "aggrete_redactions_total"):
                out += [f"# HELP {name} {help_[name]}", f"# TYPE {name} counter"]
                for key, val in sorted(self._counters.get(name, {}).items()):
                    out.append(f"{name}{_lbl(dict(key))} {val:g}")
            out += ["# HELP aggrete_upstream_seconds Time spent in the upstream tool call.",
                    "# TYPE aggrete_upstream_seconds histogram"]
            for b in LATENCY_BUCKETS:
                out.append(f'aggrete_upstream_seconds_bucket{{le="{b:g}"}} {self._hist_buckets[b]}')
            out.append(f'aggrete_upstream_seconds_bucket{{le="+Inf"}} {self._hist_inf}')
            out.append(f"aggrete_upstream_seconds_sum {self._hist_sum:g}")
            out.append(f"aggrete_upstream_seconds_count {self._hist_count}")
        return "\n".join(out) + "\n"
