"""Static checks on a code of conduct, so a policy that quietly does nothing is
found before it ships. Enforcement tests prove a rule fires; the linter catches
the rules that *can't* fire and the ones that fire too softly.

    aggrete-lint coc.yaml --config proxy.config.yaml

Exits non-zero if any error-level finding is present, so it drops into CI next to
the generated tests. Deterministic; it never runs the model.
"""

from __future__ import annotations

import argparse
import datetime
import sys
from dataclasses import dataclass

import yaml

from .policy import VALID_ENFORCE_TYPES

# Required fields per enforce type; the engine assumes these exist.
REQUIRED = {
    "domain_join": ["domains"],
    "domain_block": ["domains"],
    "wall": ["domains"],
    "min_group": ["domain", "k"],
    "entity_budget": ["domain", "max_distinct"],
    "self_comparison": ["domain"],
    "flow": ["egress_domains"],   # taint_domains recommended; egress_on_write can stand in
    "arg_match": ["deny_when"],   # tools defaults to all; deny_when is the predicate
}
HIGH = {"high", "critical"}


@dataclass
class Finding:
    level: str          # error | warn | info
    where: str          # rule id or location
    message: str

    def __str__(self) -> str:
        return f"{self.level.upper():5}  {self.where:14}  {self.message}"


def _domains_of(block: dict) -> set[str]:
    out: set[str] = set()
    for key in ("domains", "taint_domains", "egress_domains"):
        out |= set(block.get(key, []) or [])
    if block.get("domain"):
        out.add(block["domain"])
    return out


def lint(coc_path: str, config_path: str | None = None) -> list[Finding]:
    doc = yaml.safe_load(open(coc_path))
    rules = doc.get("rules", [])
    findings: list[Finding] = []

    # Config domains: the set of domains any tool can actually be mapped to.
    mapped: set[str] | None = None
    if config_path:
        cfg = yaml.safe_load(open(config_path)) or {}
        mapped = set((cfg.get("domains") or {}).values())
        if cfg.get("default_domain"):
            mapped.add(cfg["default_domain"])

    declared_packs = {p.get("id") for p in doc.get("packs", [])}
    seen_ids: set[str] = set()
    today = datetime.date.today()

    for r in rules:
        rid = r.get("rule_id", "<no id>")
        if rid in seen_ids:
            findings.append(Finding("error", rid, "duplicate rule_id"))
        seen_ids.add(rid)

        if r.get("pack") and declared_packs and r["pack"] not in declared_packs:
            findings.append(Finding("warn", rid, f"pack {r['pack']!r} is not declared in packs:"))

        tests = r.get("tests", [])
        expects = {t.get("expect") for t in tests}
        if "allow" not in expects or not (expects & {"deny", "alert", "hold"}):
            findings.append(Finding("warn", rid, "should carry at least one allow and one deny/alert/hold test"))

        for e in r.get("enforce", []):
            kind = e.get("type")
            if kind not in VALID_ENFORCE_TYPES:
                findings.append(Finding("error", rid, f"unknown enforce type {kind!r}"))
                continue
            for field in REQUIRED.get(kind, []):
                if not e.get(field):
                    findings.append(Finding("error", rid, f"{kind} is missing required field {field!r}"))
            if kind == "domain_join" and len(e.get("domains", [])) < 2:
                findings.append(Finding("error", rid, "domain_join needs at least two domains"))
            if kind == "flow" and not e.get("taint_domains") and not e.get("egress_on_write", True) is False:
                if not e.get("taint_domains"):
                    findings.append(Finding("warn", rid, "flow has no taint_domains; nothing will ever taint a session"))

            action = e.get("action", "deny")
            if action not in ("deny", "alert", "approve"):
                findings.append(Finding("error", rid, f"unknown action {action!r} (use deny, approve or alert)"))
            if action == "alert" and r.get("severity") in HIGH:
                findings.append(Finding("warn", rid,
                                        f"severity {r.get('severity')} but only alerts; a leak would be logged, not stopped"))

            if e.get("allowed_users") and e.get("blocked_users"):
                findings.append(Finding("warn", rid, "both allowed_users and blocked_users set; the block is ambiguous"))

            until = e.get("until")
            if until:
                try:
                    d = until if isinstance(until, datetime.date) else datetime.date.fromisoformat(str(until)[:10])
                    if d < today:
                        findings.append(Finding("error", rid, f"until {until} is in the past; this wall no longer blocks"))
                except ValueError:
                    findings.append(Finding("error", rid, f"until {until!r} is not a valid date"))

            if mapped is not None:
                unreachable = _domains_of(e) - mapped
                if unreachable:
                    findings.append(Finding("warn", rid,
                                            f"domain(s) {sorted(unreachable)} are not mapped to any tool in the config; "
                                            "this rule can never fire"))

    return findings


def cli() -> None:
    ap = argparse.ArgumentParser(description="Lint an Aggrete code of conduct.")
    ap.add_argument("coc", nargs="?", default="coc.yaml")
    ap.add_argument("--config", help="proxy config, to check that rule domains are reachable")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors too")
    args = ap.parse_args()

    findings = lint(args.coc, args.config)
    order = {"error": 0, "warn": 1, "info": 2}
    for f in sorted(findings, key=lambda x: (order.get(x.level, 9), x.where)):
        print(f)

    errors = sum(1 for f in findings if f.level == "error")
    warns = sum(1 for f in findings if f.level == "warn")
    if not findings:
        print(f"clean: {args.coc} has no lint findings")
    else:
        print(f"\n{errors} error(s), {warns} warning(s)")
    fail = errors or (args.strict and warns)
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    cli()
