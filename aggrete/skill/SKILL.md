---
name: aggrete
description: Set up and operate Aggrete, the open-source MCP policy proxy that enforces a code of conduct across AI assistants. Use when the user mentions Aggrete, coc.yaml, proxy.config.yaml, an MCP policy or governance layer, "govern what my assistant can reach", combining records across HR/finance/ops, prompt-injection shields on MCP writes, or wants to write, test, lint, or debug a policy rule, wire a connector, deploy over HTTP with OIDC, or read an aggrete audit log.
---

# Aggrete

Aggrete sits between MCP clients (Claude, Cursor, Codex) and MCP servers. Every
tool call is checked against `coc.yaml`, a code of conduct written as rules,
plus a per-user memory of what that person already pulled. Decisions are
deterministic, made **before** the upstream is contacted where possible, and
written as one hash-chained line in `audit.jsonl`. There is no model in the
decision path.

Two files matter:

| File | Owner | What it holds |
|---|---|---|
| `coc.yaml` | The clause owners (HR, Legal, Security) | Rules: clause text, enforcement, tests |
| `proxy.config.yaml` | Engineering | Upstreams, tool→domain map, auth, redaction, audit |

## Quick start

```bash
pip install aggrete            # or: uv tool install aggrete
aggrete --demo                 # terminal walkthrough, no config, no network
aggrete --config proxy.config.yaml                      # stdio, one developer
aggrete --config proxy.config.yaml --transport streamable-http --port 8080   # a team; needs auth:
```

Add to a client (`.mcp.json` / Claude Code):

```json
{"mcpServers": {"aggrete": {"command": "aggrete", "args": ["--config", "proxy.config.yaml"]}}}
```

Tools appear namespaced as `<upstream>__<tool>` (`hr__recent_joiners`). Two
built-in tools are always present: `aggrete__check` (dry-run a plan, nothing
fetched) and `aggrete__scenarios` (things to try on this deployment).

## The mental model

1. **Domains.** `proxy.config.yaml` maps tool-name patterns to domain names
   (`"hr__*": hr-personnel`). Rules talk about domains, never tool names.
   First match wins; unmapped tools land in `default_domain`.
2. **Reads vs writes.** A tool whose name matches `write_tools` (`*create*`,
   `*send*`, `*post*`, ...) is a write and is governed as egress.
3. **Memory.** The accumulator records, per user, which domains were read and
   which people appeared in the results, for a window. Rules like
   `domain_join` and `entity_budget` reason over that history. Over HTTP the
   user comes from the token, so one person's history is shared across clients.
4. **Two stages.** `pre_call` decides from the request alone (walls, blocks,
   flow, arg_match, most joins). `post_call` sees the result, extracts people,
   re-evaluates, and redacts. Prefer rules that are decidable pre-call: a
   post-call deny redacts, it cannot un-fetch.

## Writing a rule

Every rule needs a clause, an owner, an `enforce` list, and tests with at
least one `allow` and one `deny`/`alert` expectation. CI fails otherwise.

```yaml
rules:
  - rule_id: COC-HR-004
    pack: code-of-conduct
    title: Combining personnel, budget and rotation records
    clause: >
      Personnel records, compensation or budget records, and operational
      rosters may not be combined to derive the employment status,
      performance, or planned departure of identifiable individuals.
    owner: hr-privacy@example.com
    severity: high
    remediation: Request a purpose-bound session from HR Privacy.
    enforce:
      - layer: accumulation
        action: deny
        type: domain_join
        domains: [hr-personnel, finance-comp, ops-rota]
        require_entity_overlap: true
        scope: user
        window: 4h
    tests:
      - name: four_prompt_layoff_list
        expect: deny
        sequence:
          - {domain: finance-comp, entities: [p:alice, p:bob]}
          - {domain: hr-personnel, entities: [p:alice, p:bob, p:dan]}
          - {domain: ops-rota, entities: [p:alice, p:dan]}
      - name: two_domains_only_is_fine
        expect: allow
        sequence:
          - {domain: finance-comp, entities: [p:alice]}
          - {domain: ops-rota, entities: [p:alice]}
```

Start every new rule at `action: alert`, watch real traffic, then flip to
`deny`. A third action, `approve`, holds the call until the clause owner
approves it (`aggrete approve <id>`, `POST /approvals/<id>/approve`, or the
console); the approval is a time-limited, audited grant. Rules can be grouped
into `packs:` that an operator toggles as a unit.

### Which rule type

| The clause says | Type | Decided |
|---|---|---|
| These domains may not be combined (about the same people) | `domain_join` | pre-call |
| No more than N distinct people from a domain per window | `entity_budget` | post-call |
| Only these users may reach this domain (or: these may not), maybe until a date | `wall` | pre-call, tool hidden |
| Close a domain to some users, or open only to some, with `since`/`until` | `domain_block` | pre-call |
| Don't put my own record next to colleagues' | `self_comparison` | post-call |
| A figure about fewer than k people is individual data | `min_group` | post-call |
| No write after reading untrusted content | `flow` | pre-call |
| Allowed or not depending on the call's arguments | `arg_match` | pre-call |
| Any of the above, but a person must sign off first | same type, `action: approve` | held, then allowed |

Field-by-field reference for each type, test-format details, and `deny_when`
operators: [references/rule-types.md](references/rule-types.md).

## Test, lint, dry-run

```bash
pytest tests/test_coc.py                                  # runs every rule's own tests through the engine
aggrete-lint coc.yaml --config proxy.config.yaml          # fail-open cases tests miss; non-zero exit for CI
aggrete-ingest handbook.pdf --domains proxy.config.yaml -o coc.draft.yaml   # draft rules from a handbook (needs ANTHROPIC_API_KEY)
```

Lint catches: a high-severity rule that only alerts, a wall whose `until` has
passed, an enforce block missing a required field, and domains no tool maps to.

To answer "would this be allowed?" without fetching, call the built-in tool:

```json
{"tool": "aggrete__check", "args": {"tools": ["hr__recent_joiners", "finance__budget_roles", "ops__oncall_draft"]}}
{"tool": "aggrete__check", "args": {"tools": [{"tool": "crm__export", "args": {"scope": "all"}}]}}
```

It returns the decision, the rule, its clause, and the remediation for each
step, and stops at the first refusal.

## Wiring a connector

Any MCP server works as an upstream. Local: `{command: python3, args: [...]}`.
Remote: `{url: https://.../mcp, headers: {Authorization: "Bearer ${TOKEN}"}}`.
The proxy holds the credential; `${ENV}` keeps it out of YAML. Then map its
tools to a domain:

```yaml
upstreams:
  crm: {command: python3, args: [my_crm_connector.py]}
domains:
  "crm__export*": crm-export
  "crm__*": crm-accounts
```

Writing your own connector: use `aggrete.connectors.base.Connector`, decorate
reads with `@c.read` and writes with `@c.write` (it refuses a write tool whose
name has no write verb). Read tools should return JSON with `email` or `id`
keys so people can be extracted. Bundled connectors (Drive, Slack, GitHub,
Jira, Salesforce, Notion) run as `python -m aggrete.connectors.<name>`.

Per-user upstream access: mark the upstream `per_user: true` and supply an
`obo:` hook that prints `{"env": {...}}` or `{"headers": {...}}` per
(user, upstream). The caller's own token is still never forwarded.

## Deploying for a team or company

HTTP mode refuses to start without an `auth:` block. Pick one:

| `auth.mode` | When |
|---|---|
| `jwt` | You have an IdP. Set `issuer`, `audience`, `jwks_url`, `required_scopes`, `identity_claim` (default `email`) |
| `builtin` | No IdP yet. Small OAuth server inside the proxy, users and passcodes from env |
| `static` | Local development. Fixed tokens mapped to subjects |
| `anonymous` | Public demos on mock data only. Every caller collapses into one identity |

More than one replica needs `store: {redis_url: ${REDIS_URL}}` so the
accumulator is shared. Make the proxy the *only* MCP server your client
policies allow, and network-restrict connectors to the proxy hosts; a client
that keeps a native connector has a second road the policy never sees.

Run options: `uvx aggrete`, `docker run ghcr.io/aggrete/aggrete`,
`helm install aggrete deploy/helm/aggrete`, or embed `aggrete.plugin`
(`PolicyHook`, `AggreteMiddleware`) in an existing gateway. Full config
reference, including redaction, tool integrity, rate limits, inbound secret
scanning, and SIEM forwarding: [references/config.md](references/config.md).

## Reading the audit log

Each line in `audit.jsonl` is one decision, hash-chained to the previous line.
Common fields: `ts`, `user`, `tool`, `domain`, `stage` (`pre`, `post`,
`check`, `integrity`), `write`, `decision`, `rule`, and redaction counts on
post rows. Verify the chain and locate the first tampered line:

```bash
aggrete-audit audit.jsonl
```

To explain a refusal, find the `pre` or `post` row for that tool and user,
read `rule`, then open that `rule_id` in `coc.yaml` for the clause and
remediation. The Aggrete Console reads only `audit.jsonl` and `coc.yaml`.

Over HTTP, `/metrics` exposes the same decisions as Prometheus counters,
`/readyz` tells you whether every upstream is connected, and `audit_forward:
{otlp: ...}` streams rows to an OpenTelemetry collector.

## Honest limits

- A post-call denial redacts, it does not un-fetch. Prefer pre-call rules.
- Entity joins depend on stable IDs or emails in tool results.
- Aggregation is narrowed, not solved. A user who spaces requests past the
  window, or uses systems the proxy does not front, gets through. The proxy
  raises the cost and leaves a trail.
- stdio identity (`user:` in config) is advisory. Real enforcement is HTTP
  plus OAuth, with the proxy as the only allowed path.

Links: https://github.com/aggrete/aggrete · https://aggrete.com/guide ·
try it in a browser at https://try.aggrete.com
