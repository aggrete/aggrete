"""Tamper-evident audit log.

Every row is chained: ``row["prev"]`` is the hash of the previous row and
``row["hash"] = sha256(prev + canonical(row without hash))``. Editing,
inserting or deleting any row breaks the chain from that point on, so an
after-the-fact change to what an assistant was allowed to see cannot be hidden.
``verify_chain()`` walks the file and reports the first broken line; the
``aggrete-audit`` console script wraps it.

This is the community's "table stakes for compliance" ask: an attributable,
integrity-checkable record, one JSON object per line.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time

GENESIS = "0" * 64


def _digest(prev: str, row: dict) -> str:
    body = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


def _last_hash(path: str) -> str:
    """Continue the chain across restarts by reading the final row's hash."""
    last = GENESIS
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line).get("hash", last)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return last


class Audit:
    """Every tool call, its labels, and the decision, written as one chained
    JSON line. Prompts tell you what was asked; this tells you what was handed
    over, and proves the record has not been altered."""

    def __init__(self, path: str | None, forward=None, metrics=None):
        self.path = path
        self.fh = open(path, "a") if path else None
        self.prev = _last_hash(path) if path else GENESIS
        self.forward = forward   # optional Forwarder: ships each row to a SIEM
        self.metrics = metrics   # optional Metrics: Prometheus counters from the same rows

    def emit(self, **row):
        row["ts"] = time.time()
        row["prev"] = self.prev
        row["hash"] = _digest(self.prev, {k: v for k, v in row.items() if k != "hash"})
        self.prev = row["hash"]
        line = json.dumps(row, default=str)
        print(f"[audit] {line}", file=sys.stderr)
        if self.fh:
            self.fh.write(line + "\n")
            self.fh.flush()
        if self.forward:
            self.forward.send(row)
        if self.metrics:
            try:
                self.metrics.observe(row)
            except Exception:
                pass


def verify_chain(path: str) -> tuple[bool, int | None, int]:
    """Return ``(ok, first_bad_line, rows_scanned)``.

    ``first_bad_line`` is the 1-indexed line where the chain first fails to
    verify (bad JSON, wrong ``prev``, or a hash that does not match the row),
    or ``None`` when the whole file is intact.
    """
    prev = GENESIS
    scanned = 0
    with open(path) as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            scanned += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                return (False, i, scanned)
            stored = row.get("hash")
            body = {k: v for k, v in row.items() if k != "hash"}
            if row.get("prev") != prev or _digest(prev, body) != stored:
                return (False, i, scanned)
            prev = stored
    return (True, None, scanned)


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(prog="aggrete-audit",
                                 description="Verify the hash chain of an audit.jsonl file.")
    ap.add_argument("path", help="path to the audit log")
    args = ap.parse_args()
    ok, bad, scanned = verify_chain(args.path)
    if ok:
        print(f"OK: {scanned} rows, chain intact")
        raise SystemExit(0)
    print(f"TAMPERED: chain breaks at line {bad} ({scanned} rows scanned)", file=sys.stderr)
    raise SystemExit(1)
