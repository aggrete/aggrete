"""Bundled mock connectors for `aggrete --demo`.

Stand-ins for Workday / Salesforce / on-call style systems, so the demo server
is fully self-contained: no external services, no credentials. Each tool returns
JSON with stable person identifiers, which is what the policy engine counts as
people. Run as an upstream of the demo proxy:

    python -m aggrete._mockco --profile hr

Not part of the public API; shape may change between releases.
"""

from __future__ import annotations

import argparse
import asyncio
import json

from mcp.server.mcpserver import MCPServer

PEOPLE = [
    ("alice.n@northwind.example", "E-1041"), ("bob.k@northwind.example", "E-1052"),
    ("carol.s@northwind.example", "E-1063"), ("dan.r@northwind.example", "E-1074"),
    ("erin.p@northwind.example", "E-1085"), ("frank.w@northwind.example", "E-1096"),
    ("gita.m@northwind.example", "E-1107"), ("hugo.b@northwind.example", "E-1118"),
    ("iris.t@northwind.example", "E-1129"), ("jack.l@northwind.example", "E-1130"),
]


def build(profile: str) -> MCPServer:
    server = MCPServer(f"mock-{profile}")

    if profile == "finance":
        @server.tool(description="Headcount plan totals for a team (no individuals).")
        def headcount_plan(team: str) -> str:
            return json.dumps({"team": team, "approved": 24, "filled": 21, "open": 3})

        @server.tool(description="Budget lines showing which roles are backfill-only.")
        def budget_roles(team: str) -> str:
            return json.dumps({"team": team, "lines": [
                {"role": "SRE II", "backfill_only": True, "owner_email": e}
                for e, _ in PEOPLE[:6]
            ]})

    elif profile == "hr":
        @server.tool(description="People who joined a team within N months.")
        def recent_joiners(team: str, months: int = 18) -> str:
            return json.dumps({"team": team, "joiners": [
                {"email": e, "employee_id": i, "start": "2025-06-01"} for e, i in PEOPLE
            ]})

        @server.tool(description="Leave and absence balances for one person.")
        def leave_balance(email: str) -> str:
            return json.dumps({"email": email, "days_remaining": 11})

    elif profile == "ops":
        @server.tool(description="Draft on-call rotation for a quarter.")
        def oncall_draft(team: str, quarter: str) -> str:
            return json.dumps({"team": team, "quarter": quarter, "shifts": [
                {"week": n + 1, "user_email": e} for n, (e, _) in enumerate(PEOPLE[4:])
            ]})

    return server


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True, choices=["hr", "finance", "ops"])
    args = ap.parse_args()
    asyncio.run(build(args.profile).run_stdio_async())


if __name__ == "__main__":
    main()
