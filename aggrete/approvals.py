"""Human-in-the-loop approvals for rules whose action is `approve`.

A rule with `action: approve` does not refuse outright. The proxy holds the
call, records a pending request here, notifies an approver, and tells the
assistant to retry once it is approved. An approval is a time-limited purpose
grant for (user, rule), so it flows through the same `store.granted` path the
engine already honours, and every retrieval made under it is audited with the
approver's name.

State lives in a small JSON file next to the audit log (or in Redis when the
proxy has one), so `aggrete approve <id>` from another shell, or the console,
can act on it while the proxy keeps running.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_TTL_S = 4 * 3600
DEFAULT_FILE = "approvals.json"


def parse_ttl(value) -> int:
    if value is None:
        return DEFAULT_TTL_S
    if isinstance(value, (int, float)):
        return int(value)
    from .accumulator import parse_window
    return parse_window(str(value))


class Approvals:
    def __init__(self, path: str | None = None, redis=None, prefix: str = "aggrete",
                 ttl_s: int = DEFAULT_TTL_S, notify: dict | None = None, approvers: list[str] | None = None):
        self.path = Path(path) if path else None
        self.r = redis
        self.key = f"{prefix}:approvals"
        self.ttl_s = ttl_s
        self.notify_cfg = notify or {}
        self.approvers = [a.strip().lower() for a in (approvers or [])]

    # ---------- storage ----------

    def _load(self) -> dict:
        if self.r is not None:
            raw = self.r.get(self.key)
            raw = raw.decode() if isinstance(raw, bytes) else raw
            return json.loads(raw) if raw else {"requests": {}}
        if self.path and self.path.exists():
            try:
                return json.loads(self.path.read_text() or "{}") or {"requests": {}}
            except json.JSONDecodeError:
                return {"requests": {}}
        return {"requests": {}}

    def _save(self, data: dict) -> None:
        if self.r is not None:
            self.r.set(self.key, json.dumps(data))
            return
        if not self.path:
            self._mem = data           # no persistence configured: keep in-process only
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".approvals-")
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.path)

    def _data(self) -> dict:
        if self.r is None and not self.path:
            return getattr(self, "_mem", {"requests": {}})
        return self._load()

    # ---------- requests ----------

    @staticmethod
    def request_id(user: str, rule_id: str) -> str:
        return hashlib.sha256(f"{user.strip().lower()}|{rule_id}".encode()).hexdigest()[:10]

    def request(self, user: str, rule_id: str, tool: str, domain: str, clause: str = "",
                owner: str = "", remediation: str = "") -> tuple[dict, bool]:
        """Create (or return the existing) pending request for (user, rule).
        Returns (request, created)."""
        data = self._data()
        rid = self.request_id(user, rule_id)
        req = data["requests"].get(rid)
        now = time.time()
        if req and req.get("status") == "pending":
            req["last_seen"] = now
            req["tools"] = sorted(set(req.get("tools", [])) | {tool})
            self._save(data)
            return req, False
        req = {"id": rid, "user": user, "rule_id": rule_id, "tools": [tool], "domain": domain,
               "clause": " ".join(clause.split()), "owner": owner,
               "remediation": " ".join(remediation.split()),
               "status": "pending", "requested_at": now, "last_seen": now}
        data["requests"][rid] = req
        self._save(data)
        return req, True

    def pending(self) -> list[dict]:
        return sorted((r for r in self._data()["requests"].values() if r.get("status") == "pending"),
                      key=lambda r: r["requested_at"])

    def get(self, rid: str) -> dict | None:
        return self._data()["requests"].get(rid)

    def approve(self, rid: str, by: str, ttl_s: int | None = None, note: str = "") -> dict | None:
        data = self._data()
        req = data["requests"].get(rid)
        if not req:
            return None
        ttl = ttl_s or self.ttl_s
        req.update(status="approved", by=by, note=note, decided_at=time.time(),
                   expires_at=time.time() + ttl)
        self._save(data)
        return req

    def deny(self, rid: str, by: str, note: str = "") -> dict | None:
        data = self._data()
        req = data["requests"].get(rid)
        if not req:
            return None
        req.update(status="denied", by=by, note=note, decided_at=time.time())
        self._save(data)
        return req

    def approved_for(self, user: str) -> list[dict]:
        """Unexpired approvals for this user, so the proxy can sync them into grants."""
        now = time.time()
        u = user.strip().lower()
        return [r for r in self._data()["requests"].values()
                if r.get("status") == "approved" and r["user"].strip().lower() == u
                and r.get("expires_at", 0) > now]

    def can_approve(self, identity: str, req: dict) -> bool:
        """Configured approvers, plus the clause owner named on the rule."""
        i = identity.strip().lower()
        return i in self.approvers or (req.get("owner") or "").strip().lower() == i

    # ---------- notification ----------

    def notify(self, req: dict, approve_hint: str) -> None:
        """Best effort, off the decision path: stderr always, a Slack-style webhook
        (`notify: {webhook: ${URL}}`) or a command (`notify: {command: [...]}`)."""
        line = (f"[approval] {req['id']}  {req['user']} needs approval under {req['rule_id']} "
                f"for {', '.join(req['tools'])}. {approve_hint}")
        print(line, file=sys.stderr)
        text = (f"*Aggrete approval requested*\n"
                f"• who: {req['user']}\n• rule: {req['rule_id']} ({req.get('owner') or 'no owner'})\n"
                f"• tool: {', '.join(req['tools'])}\n• clause: {req.get('clause') or '-'}\n"
                f"• approve: {approve_hint}")
        url = self.notify_cfg.get("webhook")
        if url:
            try:
                import httpx
                httpx.post(url, json={"text": text, "aggrete": req}, timeout=5.0)
            except Exception as e:  # never let a notifier break enforcement
                print(f"[approval] webhook failed: {e}", file=sys.stderr)
        cmd = self.notify_cfg.get("command")
        if cmd:
            try:
                import subprocess
                subprocess.run(list(cmd), input=json.dumps(req).encode(), timeout=10, check=False)
            except Exception as e:
                print(f"[approval] notify command failed: {e}", file=sys.stderr)


def from_config(cfg: dict, redis_client=None) -> Approvals:
    """`approvals:` block of proxy.config.yaml. Always returns a store, so a rule
    with `action: approve` works out of the box (file next to the config)."""
    a = cfg.get("approvals") or {}
    root = Path(cfg.get("_config_dir", "."))
    path = None
    if redis_client is None:
        path = str(root / a.get("file", DEFAULT_FILE))
    return Approvals(path=path, redis=redis_client, prefix=(cfg.get("store") or {}).get("prefix", "aggrete"),
                     ttl_s=parse_ttl(a.get("ttl")), notify=a.get("notify"), approvers=a.get("approvers"))


# ---------- CLI: aggrete approvals | approve <id> | deny <id> ----------

def cli(argv: list[str]) -> int:
    import argparse
    import yaml
    ap = argparse.ArgumentParser(prog="aggrete " + argv[0])
    ap.add_argument("--config", default="proxy.config.yaml")
    if argv[0] in ("approve", "deny"):
        ap.add_argument("id")
        ap.add_argument("--by", required=True, help="approver identity, e.g. hr-privacy@example.com")
        ap.add_argument("--note", default="")
        if argv[0] == "approve":
            ap.add_argument("--ttl", default=None, help="how long the approval lasts (4h, 30m, 1d)")
    ns = ap.parse_args(argv[1:])
    cfg = yaml.safe_load(Path(ns.config).read_text()) if Path(ns.config).exists() else {}
    cfg["_config_dir"] = str(Path(ns.config).parent)
    store = from_config(cfg)
    if argv[0] == "approvals":
        rows = store.pending()
        if not rows:
            print("no pending approvals"); return 0
        for r in rows:
            age = int(time.time() - r["requested_at"])
            print(f"{r['id']}  {r['user']:<28} {r['rule_id']:<14} {', '.join(r['tools'])}  ({age}s ago)")
        return 0
    req = store.get(ns.id)
    if not req:
        print(f"no request {ns.id}", file=sys.stderr); return 1
    if argv[0] == "approve":
        req = store.approve(ns.id, ns.by, parse_ttl(ns.ttl) if ns.ttl else None, ns.note)
        print(f"approved {req['id']} for {req['user']} under {req['rule_id']} by {ns.by}, "
              f"until {time.strftime('%Y-%m-%d %H:%M', time.localtime(req['expires_at']))}")
    else:
        store.deny(ns.id, ns.by, ns.note)
        print(f"denied {ns.id} by {ns.by}")
    return 0
