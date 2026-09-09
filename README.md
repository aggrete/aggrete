# Aggrete

[![PyPI version](https://img.shields.io/pypi/v/aggrete)](https://pypi.org/project/aggrete/)
[![Python versions](https://img.shields.io/pypi/pyversions/aggrete)](https://pypi.org/project/aggrete/)
[![License](https://img.shields.io/pypi/l/aggrete)](https://github.com/aggrete/aggrete/blob/main/LICENSE)
[![Glama quality](https://glama.ai/mcp/servers/Aggrete/aggrete/badges/score.svg)](https://glama.ai/mcp/servers/Aggrete/aggrete)

**An MCP proxy that enforces a code-of-conduct document across connectors, with per-user memory that accumulates across calls.**

Four individually-authorized questions can assemble a layoff list — no single one is sensitive, so no guardrail fires. Aggrete is the layer that catches the *combination*: is this call, together with everything this person already pulled today, something the code of conduct forbids?

**[Try it live](https://try.aggrete.com)** — nothing to install · or `uvx aggrete --demo`

## Install

```bash
pip install aggrete                 # or: uv tool install aggrete
uvx aggrete --demo                  # the walkthrough — no config, auth, or network
aggrete --config proxy.config.yaml  # run it for real
```

## The one example

The `check` tool dry-runs a plan and returns the verdict **before anything is fetched**:

```
Plan check: REFUSED.
  1. hr__recent_joiners     [hr-personnel]  ->  allowed
  2. finance__budget_roles  [finance-comp]  ->  allowed
  3. ops__oncall_draft      [ops-rota]      ->  REFUSED   COC-HR-004
     Personnel, compensation, and operational rosters may not be combined to
     derive the planned departure of identifiable individuals.
```

Each call is fine alone. The third completes a forbidden set across three domains that overlap on the same people, so it's denied **before the upstream call** — the data is never fetched.

## What it does

- **Refuses before fetching**, using a YAML policy and per-user memory across calls and sessions — not single-call authorization.
- **Redacts** emails, SSNs, cards, and tokens from results before they reach the model; **hides** walled tools from users who can't call them.
- **Shields against prompt injection** — any write after a session reads untrusted content is refused — and against **tool poisoning**, flagging hidden instructions in tool descriptions.
- **Holds upstream credentials itself** (confused-deputy safe), with optional per-user on-behalf-of access.
- **Audits tamper-evidently** — every decision is one hash-chained JSON line (`aggrete-audit`), optionally forwarded to a SIEM.
- **Ask before you act** — `check` previews any sequence, `scenarios` lists things to try.

## Learn more

| | |
|---|---|
| **[Writing policy](docs/POLICY.md)** | The `coc.yaml` schema, rule types, `arg_match`, and generating a draft from your handbook with `aggrete-ingest` |
| **[Deploying](docs/DEPLOY.md)** | Architecture, the deploy matrix, HTTP + OAuth, connecting Claude, and per-user credentials |
| **[Building a connector](docs/CONNECTORS.md)** | Expose read/write tools and govern any system (Google Drive is the reference) |
| **[Roadmap](ROADMAP.md)** | Shipped, in progress, and planned |

## Honest limitations

- **Post-call denial redacts, it does not un-fetch** — prefer rules decidable pre-call.
- **stdio identity is advisory** — real enforcement needs streamable HTTP with OAuth and IdP-level blocking of direct connector grants, so the proxy is the only path.
- **Aggregation can only be narrowed, not solved** — a user who spaces requests beyond the window, or paraphrases across systems the proxy doesn't front, gets through. This raises the cost and creates the audit trail; it isn't a ceiling.
- **Not a gateway** — no multi-tenancy, token vault, or HA. For production, embed this engine in agentgateway or IBM ContextForge.

---

<sub>mcp-name: io.github.aggrete/aggrete</sub>
