"""`aggrete --demo`: a self-contained walkthrough.

Runs four reasonable-looking questions through the real policy engine and prints
the decisions, then (in a terminal) drops into an interactive menu so you can try
scenarios yourself and watch Aggrete allow, alert, or refuse. No config file, no
auth, no network. The fourth question completes a picture COC-HR-004 forbids and
is refused before any upstream would be contacted.
"""
from __future__ import annotations

import os
import sys
import tempfile

from .accumulator import MemoryStore
from .policy import Engine

# A compact policy covering one rule of each interesting kind, so the interactive
# menu below can demonstrate the whole range without a config file.
_POLICY = """
version: 1
defaults: {window: 24h}
rules:
  - rule_id: COC-HR-004
    clause: >
      Personnel, budget and rotation records may not be combined to derive the
      employment status or planned departure of identifiable individuals.
    remediation: >
      If this is sanctioned workforce planning, request a purpose-bound session
      from HR Privacy. It is time-limited and every retrieval is logged.
    enforce:
      - {action: deny, type: domain_join, domains: [hr-personnel, finance-comp, ops-rota], require_entity_overlap: true, window: 4h}
  - rule_id: COC-HR-011
    clause: Bulk lists of identifiable people may not be assembled from personnel records.
    remediation: Bulk personnel extracts go through People Analytics, who scope the export to the question.
    enforce:
      - {action: alert, type: entity_budget, domain: hr-personnel, max_distinct: 8, window: 24h}
  - rule_id: COC-HR-031
    clause: Pay figures that describe fewer than ten people are individual pay and may not be disclosed.
    remediation: Ask for a larger category, a whole job family or location.
    enforce:
      - {action: deny, type: min_group, domain: pay-aggregates, k: 10, window: 24h}
  - rule_id: COC-HR-021
    clause: >
      Records of colleagues' working time may not be used to benchmark individuals
      against one another, including against oneself, outside a sanctioned review.
    remediation: Reviewing your own team is fine; for a sanctioned comparison ask HR Privacy for a purpose-bound session.
    enforce:
      - {action: deny, type: self_comparison, domain: timesheets, window: 24h}
  - rule_id: COC-SEC-002
    clause: Once an assistant has read untrusted content it may not then reach a tool that can send data out.
    remediation: Start a fresh session that has not read untrusted content, or ask Security to review the flow.
    enforce:
      - {action: deny, type: flow, taint_domains: [untrusted-web], egress_domains: [external-share]}
  - rule_id: COC-MGMT-001
    clause: Restructuring plans are confidential until announced and may not be retrieved before the announcement date.
    remediation: The announcement date is set by the CEO office; nothing is available earlier.
    enforce:
      - {action: deny, type: wall, domains: [restructuring-plan], until: 2099-01-01}
  - rule_id: COC-SEC-001
    clause: Secret stores, credentials and key vaults are never available to assistants.
    remediation: The secret store is not reachable through assistants. Use your normal break-glass process.
    enforce:
      - {action: deny, type: domain_block, domains: [secrets-store]}
"""

_USER = "manager@example.com"

# The scripted opener: four reasonable-looking requests, the last one refused.
_SEQUENCE = [
    ("Q3 headcount plan",   "finance-planning", []),
    ("Backfill-only roles", "finance-comp",     ["p:alice", "p:bob"]),
    ("Recent joiners",      "hr-personnel",     ["p:alice", "p:bob", "p:carol", "p:dan",
                                                 "p:erin", "p:finn", "p:gwen", "p:hank", "p:ivy", "p:jane"]),
    ("On-call gaps",        "ops-rota",         ["p:alice"]),
]

# Interactive menu: (label, steps) where each step is (domain, is_write, entities).
_SCENARIOS = [
    ("Build a layoff list  (personnel + budget + rota, same people)",
     [("finance-comp", False, ["p:a", "p:b"]),
      ("hr-personnel", False, ["p:a", "p:b"]),
      ("ops-rota", False, ["p:a"])]),
    ("Pull a bulk roster of people",
     [("hr-personnel", False, [f"p:{n}" for n in range(9)])]),
    ("Ask pay for a small team",
     [("pay-aggregates", False, ["p:a", "p:b", "p:c"])]),
    ("Compare your hours to a colleague's",
     [("timesheets", False, [f"p:{_USER}"]),
      ("timesheets", False, ["p:colleague@example.com"])]),
    ("Read an untrusted web page, then post out",
     [("untrusted-web", False, []),
      ("external-share", True, [])]),
    ("Open the embargoed restructuring plan",
     [("restructuring-plan", False, [])]),
    ("Reach the secret store",
     [("secrets-store", False, [])]),
]


import sys
from pathlib import Path

DEMO_DIR = Path(__file__).parent / "_demo"

_DEMO_INSTRUCTIONS = (
    "Aggrete demo for the Northwind sample company. The mock hr, finance and ops "
    "tools are governed by a bundled code of conduct. New here? Call "
    "aggrete__scenarios for things to try, or aggrete__check to ask whether a plan "
    "would be allowed, and why, without fetching anything. Point Aggrete at your "
    "own MCP servers with --config for the real thing: https://aggrete.com/guide"
)

_DEMO_SCENARIOS = """Things to try in this demo. Run any for real, or preview with aggrete__check (nothing is fetched).

  1. A combination the code of conduct forbids. Call hr__recent_joiners, then
     finance__budget_roles, then ops__oncall_draft for the same team. Combining
     personnel, budget and rota to profile people is refused (COC-HR-004).

  2. Ask before you act. aggrete__check takes a list of tool calls and returns the
     decision, the rule and the fix, without running anything. Try
     ["hr__recent_joiners", "finance__budget_roles", "ops__oncall_draft"].

  3. A rule that reads the arguments, not just the tool. Run aggrete__check with
     [{"tool": "crm__export", "args": {"scope": "all"}}] to see a company-wide
     customer export refused, while scope "team" is allowed (COC-CRM-001).
"""


def demo_config() -> dict:
    """A fully self-contained proxy config for `aggrete --demo` when a client
    attaches over stdio: bundled mock upstreams and a bundled policy, no auth,
    no external services."""
    py = sys.executable
    return {
        "coc": "coc.yaml",  # resolved against DEMO_DIR
        "user": "you@aggrete.demo",
        "instructions": _DEMO_INSTRUCTIONS,
        "scenarios": _DEMO_SCENARIOS,
        "brand": {"title": "Aggrete demo", "website_url": "https://aggrete.com"},
        "upstreams": {
            "hr": {"command": py, "args": ["-m", "aggrete._mockco", "--profile", "hr"]},
            "finance": {"command": py, "args": ["-m", "aggrete._mockco", "--profile", "finance"]},
            "ops": {"command": py, "args": ["-m", "aggrete._mockco", "--profile", "ops"]},
        },
        "domains": {
            "finance__headcount_plan": "finance-planning",
            "finance__*": "finance-comp",
            "hr__*": "hr-personnel",
            "ops__*": "ops-rota",
        },
        "default_domain": "unclassified",
    }


def run() -> None:
    on = sys.stdout.isatty()

    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if on else s

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(_POLICY)
        path = f.name
    try:
        eng = Engine(path, MemoryStore())
        _story(eng, c)
        if sys.stdin.isatty() and sys.stdout.isatty():
            _interactive(eng, c)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _story(eng, c) -> None:
    print()
    print("  " + c("1", "aggrete demo") + c("90", "  four questions, one afternoon"))
    print("  " + c("90", "  one manager, four reasonable-looking requests"))
    print()
    denied = False
    for label, domain, ents in _SEQUENCE:
        pre = eng.pre_call(_USER, domain)
        if not pre.allow:
            print("  " + c("90", ">") + f" {label:<24} " + c("41;97", " deny "))
            print("     " + c("31", f"{pre.rule_id}. " + " ".join((pre.clause or "").split())))
            print("     " + c("90", "refused at pre-call, the upstream is never contacted"))
            print("     " + c("90", " ".join((pre.remediation or "").split())))
            denied = True
            break
        post = eng.post_call(_USER, domain, ents)
        if not post.allow:
            print("  " + c("90", ">") + f" {label:<24} " + c("41;97", " deny "))
            print("     " + c("31", f"{post.rule_id}. " + " ".join((post.clause or "").split())))
            denied = True
            break
        tag = "alert" if post.alerts else "allow"
        badge = c("43;30", " alert ") if tag == "alert" else c("42;30", " allow ")
        print("  " + c("90", ">") + f" {label:<24} " + badge)
        print("     " + c("90", f"audit.jsonl  {domain}  post  {tag}"))
    print()
    if denied:
        print("  " + c("90", "The forbidden combination was blocked before any data was fetched."))


def _interactive(eng, c) -> None:
    badge = {"allow": c("42;30", " allow "), "alert": c("43;30", " alert "), "deny": c("41;97", " deny ")}
    while True:
        print()
        print("  " + c("1", "Try it yourself.") + c("90", "  Each runs through the real engine; nothing is fetched."))
        for i, (label, _steps) in enumerate(_SCENARIOS, 1):
            print("    " + c("36", str(i)) + f"  {label}")
        print("    " + c("36", "q") + "  quit")
        try:
            choice = input("\n  " + c("90", "pick a scenario: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("q", "quit", "exit"):
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(_SCENARIOS)):
            continue
        label, steps = _SCENARIOS[int(choice) - 1]
        sim = [{"domain": d, "write": w, "entities": e} for d, w, e in steps]
        results, blocked = eng.simulate(sim, _USER)
        print()
        print("  " + c("1", label))
        for r in results:
            d = r["decision"]
            line = "    " + c("90", "->") + f" {r['step']['domain']:<20} " + badge[r["verdict"]]
            if r["verdict"] == "deny":
                line += "  " + c("31", d.rule_id or "")
            print(line)
            if r["verdict"] == "deny":
                print("       " + c("31", " ".join((d.clause or "").split())))
                print("       " + c("90", "Fix: " + " ".join((d.remediation or "").split())))
        if blocked is None:
            print("    " + c("90", "allowed end to end."))
