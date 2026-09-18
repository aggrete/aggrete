"""Compiles coc.yaml into decisions. No model in this path. Deterministic only."""

from __future__ import annotations

import datetime
import fnmatch
import os
import re
import time

from dataclasses import dataclass, field
from itertools import combinations

import yaml

from .accumulator import MemoryStore, Store, parse_window

# Types the engine knows how to evaluate. Unknown values fail at load time.
VALID_ENFORCE_TYPES = frozenset({
    "domain_join",
    "self_comparison",
    "wall",
    "min_group",
    "entity_budget",
    "flow",
    "domain_block",
    "arg_match",
})


def _arg_matches(conds: list, args: dict) -> bool:
    """True if ALL argument conditions hold. Each condition names an `arg` and one
    operator: equals, in, regex, gt, lt, exists, or missing. Unknown operators do
    not match, so a misconfigured condition fails safe (it does not deny)."""
    if not conds:
        return False
    for c in conds:
        name = c.get("arg")
        present = name in args
        val = args.get(name)
        if "exists" in c:
            if bool(present) != bool(c["exists"]):
                return False
        elif "missing" in c:
            if present != (not c["missing"]):
                return False
        elif "equals" in c:
            if str(val) != str(c["equals"]):
                return False
        elif "in" in c:
            if val not in (c["in"] or []):
                return False
        elif "regex" in c:
            if val is None or not re.search(str(c["regex"]), str(val)):
                return False
        elif "gt" in c:
            try:
                if not float(val) > float(c["gt"]):
                    return False
            except (TypeError, ValueError):
                return False
        elif "lt" in c:
            try:
                if not float(val) < float(c["lt"]):
                    return False
            except (TypeError, ValueError):
                return False
        else:
            return False
    return True


@dataclass
class Decision:
    allow: bool = True
    rule_id: str | None = None
    clause: str | None = None
    owner: str | None = None
    remediation: str | None = None
    evidence: dict = field(default_factory=dict)
    alerts: list[dict] = field(default_factory=list)
    granted_purpose: str | None = None
    needs_approval: bool = False   # the rule's action is `approve`: hold until an approver grants it

    def explain(self) -> str:
        if self.allow:
            return "allowed"
        head = f"Held for approval under {self.rule_id}." if self.needs_approval else f"Blocked by {self.rule_id}."
        return (
            f"{head}\n\n"
            f"{' '.join((self.clause or '').split())}\n\n"
            f"{' '.join((self.remediation or '').split())}\n\n"
            f"Rule owner: {self.owner}"
        )


class Rule:
    def __init__(self, raw: dict, defaults: dict):
        self.id = raw["rule_id"]
        self.clause = raw["clause"]
        self.owner = raw.get("owner", "unassigned")
        self.severity = raw.get("severity", "medium")
        self.remediation = raw.get("remediation", "")
        self.tests = raw.get("tests", [])
        self.pack = raw.get("pack")
        self.enforce = []
        for e in raw.get("enforce", []):
            e = dict(e)
            kind = e.get("type")
            if kind not in VALID_ENFORCE_TYPES:
                valid = ", ".join(sorted(VALID_ENFORCE_TYPES))
                raise ValueError(
                    f"rule {self.id}: unknown enforce type {kind!r}; "
                    f"valid types: {valid}"
                )
            e["window_s"] = parse_window(e.get("window", defaults.get("window", "24h")))
            self.enforce.append(e)

    def blocks(self, kind: str):
        return [e for e in self.enforce if e.get("type") == kind]


def _ts(value) -> float | None:
    """ISO date or datetime to epoch seconds; None if unset."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime.datetime):
        return value.timestamp()
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.time()).timestamp()
    return datetime.datetime.fromisoformat(str(value)).timestamp()


def in_scope(e: dict, user: str, now: float | None = None) -> bool:
    """Does this enforcement block apply to this user right now?

    `allowed_users` exempts people (counsel, the consultation team);
    `blocked_users` targets people (the subject of an investigation);
    `since` / `until` bound the rule in time (embargoes, quiet periods).
    """
    now = time.time() if now is None else now
    u = user.strip().lower()
    if e.get("allowed_users") and u in {x.strip().lower() for x in e["allowed_users"]}:
        return False
    if e.get("blocked_users") and u not in {x.strip().lower() for x in e["blocked_users"]}:
        return False
    since, until = _ts(e.get("since")), _ts(e.get("until"))
    if since and now < since:
        return False
    if until and now >= until:
        return False
    return True


def gate(e: dict, default: str = "deny") -> str | None:
    """What an enforce block does when it fires. `deny` refuses, `approve` holds the
    call until an approver grants a time-limited exception, `alert` (or anything
    else) only records. Returns None for the record-only case."""
    a = e.get("action", default)
    return a if a in ("deny", "approve") else None


def applies_to(e: dict, is_write: bool) -> bool:
    """A rule block may target only writes (`applies: write`) or only reads
    (`applies: read`); by default it applies to both. (`on` is a YAML boolean.)"""
    a = e.get("applies")
    if a == "write":
        return is_write
    if a == "read":
        return not is_write
    return True


class Engine:
    """Evaluates Layer 3 (this call) and Layer 4 (everything so far)."""

    def __init__(self, coc_path: str, store: Store | None = None, pack_state_path: str | None = None):
        doc = yaml.safe_load(open(coc_path))
        self.defaults = doc.get("defaults", {})
        self.rules = [Rule(r, self.defaults) for r in doc["rules"]]
        self.store = store or MemoryStore()
        self.pack_meta = doc.get("packs", [])
        self._pack_default = {p["id"]: bool(p.get("enabled", True)) for p in self.pack_meta}
        self.pack_state_path = pack_state_path
        self._overrides: dict[str, bool] = {}
        self._overrides_mtime = 0.0
        self._load_overrides()

    def _load_overrides(self) -> None:
        """Pack on/off can be toggled from the console via a small JSON file the
        proxy re-reads lazily, so a toggle takes effect without a restart."""
        if not self.pack_state_path:
            return
        try:
            mtime = os.path.getmtime(self.pack_state_path)
        except OSError:
            self._overrides = {}
            return
        if mtime == self._overrides_mtime:
            return
        try:
            import json
            self._overrides = {k: bool(v) for k, v in json.load(open(self.pack_state_path)).items()}
            self._overrides_mtime = mtime
        except (OSError, ValueError):
            self._overrides = {}

    def pack_enabled(self, pack_id: str | None) -> bool:
        if not pack_id:
            return True
        self._load_overrides()
        if pack_id in self._overrides:
            return self._overrides[pack_id]
        return self._pack_default.get(pack_id, True)

    def _active(self, rule) -> bool:
        return self.pack_enabled(rule.pack)

    def packs(self) -> list[dict]:
        """Pack metadata plus live enabled state and rule counts, for the console."""
        counts: dict[str, int] = {}
        for r in self.rules:
            if r.pack:
                counts[r.pack] = counts.get(r.pack, 0) + 1
        out = []
        for p in self.pack_meta:
            out.append({**p, "enabled": self.pack_enabled(p["id"]), "rules": counts.get(p["id"], 0)})
        return out

    def set_pack(self, pack_id: str, enabled: bool) -> None:
        import json
        self._load_overrides()
        state = dict(self._overrides)
        state[pack_id] = bool(enabled)
        if self.pack_state_path:
            with open(self.pack_state_path, "w") as f:
                json.dump(state, f)
        self._overrides = state
        try:
            self._overrides_mtime = os.path.getmtime(self.pack_state_path) if self.pack_state_path else 0.0
        except OSError:
            pass

    # ---------- before the upstream call ----------

    def pre_call(self, user: str, domain: str, is_write: bool = False, store: Store | None = None) -> Decision:
        """Deny before fetching where we already know enough to decide.

        This is the difference between blocking a leak and merely logging one:
        data that is never retrieved cannot be redacted imperfectly.

        `store` defaults to the engine's own accumulator; pass a throwaway one
        to evaluate a hypothetical call without touching real state (`simulate`).
        """
        store = self.store if store is None else store
        for rule in self.rules:
            if not self._active(rule):
                continue
            for e in rule.blocks("flow"):
                # Prompt-injection shield: once a session has read untrusted
                # content, it may not reach an egress-capable domain. Any write
                # is egress by default.
                is_egress = domain in e.get("egress_domains", []) or (is_write and e.get("egress_on_write", True))
                if not is_egress or not in_scope(e, user):
                    continue
                act = gate(e)
                if act is None:
                    continue
                tainted = [t for t in e.get("taint_domains", []) if t in store.domains(user)]
                if tainted:
                    if purpose := store.granted(user, rule.id):
                        return Decision(allow=True, rule_id=rule.id, granted_purpose=purpose)
                    return self._deny(rule, {"egress": domain, "tainted_by": tainted}, approve=act == "approve")
            for e in rule.blocks("domain_block"):
                act = gate(e)
                if domain in e["domains"] and act and in_scope(e, user) and applies_to(e, is_write):
                    # `deny` here is deliberately not waivable by a purpose grant (legal hold);
                    # `approve` is, since an approval is exactly a grant.
                    if act == "approve" and (purpose := store.granted(user, rule.id)):
                        return Decision(allow=True, rule_id=rule.id, granted_purpose=purpose)
                    return self._deny(rule, {"domain": domain}, approve=act == "approve")

            for e in rule.blocks("wall"):
                # Embargoes, investigation walls, privilege: who may reach a domain, and until when.
                if domain not in e["domains"] or not in_scope(e, user) or not applies_to(e, is_write):
                    continue
                act = gate(e)
                if act is None:
                    continue
                if purpose := store.granted(user, rule.id):
                    return Decision(allow=True, rule_id=rule.id, granted_purpose=purpose)
                return self._deny(rule, {"domain": domain, "until": e.get("until"),
                                         "allowed_users": e.get("allowed_users"), "blocked_users": e.get("blocked_users")},
                                  approve=act == "approve")

            for e in rule.blocks("domain_join"):
                if domain not in e["domains"] or not in_scope(e, user):
                    continue
                already = [d for d in e["domains"] if d != domain and d in store.domains(user)]
                if len(already) != len(e["domains"]) - 1:
                    continue  # this call would not complete the set
                if e.get("require_entity_overlap", True):
                    overlap = set.intersection(*[store.entities(user, d) for d in already])
                    if not overlap:
                        continue
                else:
                    overlap = set()
                act = gate(e)
                if act is None:
                    continue
                if purpose := store.granted(user, rule.id):
                    return Decision(allow=True, rule_id=rule.id, granted_purpose=purpose)
                return self._deny(
                    rule,
                    {"completes": e["domains"], "already_held": already,
                     "shared_entities": sorted(overlap)[:10]},
                    approve=act == "approve",
                )
        return Decision(allow=True)

    def check_args(self, user: str, tool: str, args: dict, store: Store | None = None) -> Decision:
        """Decide a call from the *arguments*, not just its type: the same tool can
        be fine or forbidden depending on what it is asked to do (export your team
        vs the whole company). `arg_match` rules name tool-name globs and a set of
        argument conditions that must all hold to fire."""
        store = self.store if store is None else store
        for rule in self.rules:
            if not self._active(rule):
                continue
            for e in rule.blocks("arg_match"):
                pats = e.get("tools") or ["*"]
                if not any(fnmatch.fnmatch(tool, p) for p in pats):
                    continue
                if not in_scope(e, user) or not _arg_matches(e.get("deny_when", []), args):
                    continue
                act = gate(e)
                if act is None:
                    return Decision(allow=True, rule_id=rule.id,
                                    alerts=[{"rule_id": rule.id, "tool": tool}])
                if purpose := store.granted(user, rule.id):
                    return Decision(allow=True, rule_id=rule.id, granted_purpose=purpose)
                return self._deny(rule, {"tool": tool, "matched": e.get("deny_when")}, approve=act == "approve")
        return Decision(allow=True)

    def tool_visible(self, user: str, domain: str | None) -> bool:
        """Whether a tool in `domain` should even be listed for `user`.

        Static gates hide tools from people who could never call them: a
        `domain_block` domain, or a `wall` the user is not exempt from and has
        no granted purpose for. Accumulation rules (`domain_join`) do not hide
        anything, because the tool is fine until the forbidden set is completed.
        What is never listed is never called.
        """
        if not domain:
            return True
        for rule in self.rules:
            if not self._active(rule):
                continue
            for e in rule.blocks("domain_block"):
                if domain in e["domains"] and e.get("action", "deny") == "deny" and in_scope(e, user):
                    return False
            for e in rule.blocks("wall"):
                if domain in e["domains"] and in_scope(e, user) and e.get("action", "deny") == "deny":
                    if not self.store.granted(user, rule.id):
                        return False
        return True

    # ---------- after the upstream call ----------

    def post_call(self, user: str, domain: str, entities: list[str], store: Store | None = None) -> Decision:
        """Record what came back, then re-evaluate. Denials redact the result.

        `store` defaults to the engine's own accumulator; pass a throwaway one
        to evaluate a hypothetical call without recording it (`simulate`).
        """
        store = self.store if store is None else store
        ttl = max((e["window_s"] for r in self.rules for e in r.enforce), default=86400)
        store.record(user, domain, entities, ttl)

        alerts: list[dict] = []
        for rule in self.rules:
            if not self._active(rule):
                continue
            for e in rule.blocks("min_group"):
                # Aggregate-only answers: a result about fewer than k people is one person's data.
                if e["domain"] != domain or not in_scope(e, user):
                    continue
                n = len(set(entities))
                if 0 < n < int(e.get("k", 10)):
                    hit = {"rule_id": rule.id, "domain": domain, "people": n, "k": int(e.get("k", 10))}
                    act = gate(e, "alert")
                    if act and not store.granted(user, rule.id):
                        return self._deny(rule, hit, approve=act == "approve")
                    alerts.append(hit)

            for e in rule.blocks("entity_budget"):
                if e["domain"] != domain:
                    continue
                count = len(store.entities(user, e["domain"]))
                if count > e["max_distinct"]:
                    hit = {"rule_id": rule.id, "domain": e["domain"],
                           "distinct": count, "max": e["max_distinct"]}
                    act = gate(e, "alert")
                    if act and not store.granted(user, rule.id):
                        return self._deny(rule, hit, approve=act == "approve")
                    alerts.append(hit)

            for e in rule.blocks("self_comparison"):
                # The requester's own record next to colleagues' records in the
                # same domain: the precondition for any "how do I compare" answer.
                if e["domain"] != domain:
                    continue
                seen = store.entities(user, domain)
                me = f"p:{user.strip().lower()}"
                others = sorted(x for x in seen if x != me)
                if me in seen and others:
                    hit = {"rule_id": rule.id, "domain": domain, "self": me,
                           "others": others[:10], "distinct_others": len(others)}
                    act = gate(e, "alert")
                    if act and not store.granted(user, rule.id):
                        return self._deny(rule, hit, approve=act == "approve")
                    alerts.append(hit)

            for e in rule.blocks("domain_join"):
                if domain not in e["domains"] or not in_scope(e, user):
                    continue
                if not set(e["domains"]) <= store.domains(user):
                    continue
                overlap = set.intersection(*[store.entities(user, d) for d in e["domains"]])
                if e.get("require_entity_overlap", True) and not overlap:
                    continue
                act = gate(e)
                if act is None:
                    alerts.append({"rule_id": rule.id, "overlap": sorted(overlap)[:10]})
                    continue
                if purpose := store.granted(user, rule.id):
                    alerts.append({"rule_id": rule.id, "granted_purpose": purpose})
                    continue
                return self._deny(rule, {"domains": e["domains"],
                                         "shared_entities": sorted(overlap)[:10]}, alerts,
                                  approve=act == "approve")

        return Decision(allow=True, alerts=alerts)

    # ---------- dry run: would this be allowed? ----------

    def simulate(self, steps: list[dict], user: str) -> tuple[list[dict], int | None]:
        """Replay a proposed sequence of calls against a throwaway store and
        report the verdict per step, without touching real state or fetching
        anything. Each step is {domain, write?, entities?}. Mirrors the proxy's
        own pre_call -> post_call flow exactly, so the answer is faithful.

        Returns (results, blocked_at) where results has one entry per step
        evaluated ({step, verdict in allow|alert|deny, decision}) and blocked_at
        is the index of the first denied step, or None if the whole plan passes.
        A real client stops at the first deny, so evaluation stops there too.
        """
        sim = MemoryStore()
        results: list[dict] = []
        for i, step in enumerate(steps):
            domain = step["domain"]
            is_write = bool(step.get("write", False))
            ents = list(step.get("entities", []))
            tool = step.get("tool")
            if tool and step.get("args"):
                ad = self.check_args(user, tool, step["args"], store=sim)
                if not ad.allow:
                    results.append({"step": step, "verdict": "hold" if ad.needs_approval else "deny", "decision": ad})
                    return results, i
            pre = self.pre_call(user, domain, is_write=is_write, store=sim)
            if not pre.allow:
                results.append({"step": step, "verdict": "hold" if pre.needs_approval else "deny", "decision": pre})
                return results, i
            post = self.post_call(user, domain, ents, store=sim)
            if not post.allow:
                results.append({"step": step, "verdict": "hold" if post.needs_approval else "deny", "decision": post})
                return results, i
            results.append({"step": step, "verdict": "alert" if post.alerts else "allow",
                            "decision": post})
        return results, None

    # ---------- purpose binding ----------

    def grant_purpose(self, user: str, rule_id: str, purpose: str, ttl_s: int = 4 * 3600):
        """The escape valve. Without a workable one, users route around the system."""
        self.store.grant(user, rule_id, ttl_s, purpose)

    def _deny(self, rule: Rule, evidence: dict, alerts: list | None = None, approve: bool = False) -> Decision:
        return Decision(False, rule.id, rule.clause, rule.owner, rule.remediation,
                        evidence, alerts or [], needs_approval=approve)
