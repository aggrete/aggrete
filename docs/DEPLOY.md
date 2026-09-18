# Deploying Aggrete

## How it works

```
client ──MCP──▶ proxy ──MCP──▶ hr / finance / ops connectors
                  ├─ pre_call   deny before fetching where already decidable
                  ├─ post_call  extract entities, record, re-evaluate, redact
                  └─ audit      what was handed over, not just what was asked
```

- `aggrete/policy.py` — deterministic evaluation, no model in this path.
- `aggrete/accumulator.py` — per-user state, TTL'd. `MemoryStore` for tests, `RedisStore` for deployment (state must be shared across clients).
- `aggrete/entities.py` — pulls stable person IDs out of tool results.
- `proxy.config.yaml` — maps tool-name patterns to the domains clauses refer to.

Upstreams are local stdio processes (`command:`) or remote MCP servers over streamable HTTP (`url:`). The proxy holds the upstream credential (`${ENV_VAR}` references keep tokens out of YAML), so the only path to a connector is through the proxy.

## Where to run it

| Who | How |
|---|---|
| One developer | `uvx aggrete --config proxy.config.yaml`, or the `.mcp.json` in this repo |
| A team | `docker run ghcr.io/aggrete/aggrete` with `/etc/aggrete` mounted, or `helm install aggrete deploy/helm/aggrete` (bundled Redis, JWT auth, Ingress) |
| A company | Helm/Docker behind your IdP, then make `https://aggrete.<corp>/mcp` the *only* MCP server your assistant policies allow, with connectors network-restricted to the Aggrete hosts |
| Existing gateway | Embed `aggrete.plugin` (`PolicyHook` / `AggreteMiddleware`) instead of running a second control plane |

## Serving a whole company

Run as a service and let identity come from the token:

```bash
python -m aggrete.proxy --config proxy.config.yaml --transport streamable-http --host 0.0.0.0 --port 8080
```

HTTP mode refuses to start without an `auth:` block (opt into `mode: anonymous` for a public mock-data demo). `jwt` mode validates bearer JWTs from your IdP (issuer, audience, expiry, JWKS signature, scopes) and derives the user from the `email` claim (configurable with `identity_claim`); `builtin` mode is a small OAuth server inside the proxy for teams with no IdP yet. The accumulator keys state on the token identity, so the same person from Claude Code, claude.ai and Cursor shares one history — which is the point.

## Connect Claude

1. claude.ai → **Settings → Connectors → Add custom connector**, URL `https://<host>/mcp`.
2. **Authentication:** pick **None** for the public demo (`https://try.aggrete.com/mcp` — anonymous, mock data); pick **Always required** for any real deployment. The accumulator keys on the token identity, so anonymous collapses every caller into one identity and the per-user memory stops meaning anything — OAuth is what makes the governance real.
3. **Turn it on in the chat** and ask for it explicitly the first time (e.g. *"using aggrete, call `scenarios`"*). Adding a connector doesn't enable it per conversation, and Claude won't reach for a new one on generic chat.

## The only path

A policy is a control only if the proxy is the only road to the connectors.
Three things make that true:

1. **Connectors accept traffic only from the proxy hosts** (network policy,
   allow-listed service accounts, the proxy's own credential).
2. **The proxy holds the upstream credentials.** People sign in to the proxy;
   the proxy signs in to the connectors. A caller's token is never forwarded.
3. **Clients are told which server they may use.** For Claude Code, ship a
   managed MCP file and lock it:

```json
// macOS: /Library/Application Support/ClaudeCode/managed-mcp.json
// Linux: /etc/claude-code/managed-mcp.json   Windows: C:\Program Files\ClaudeCode\managed-mcp.json
{"mcpServers": {"aggrete": {"type": "http", "url": "https://aggrete.corp.example/mcp"}}}
```

```json
// managed-settings.json (same directory)
{"allowManagedMcpServersOnly": true,
 "allowedMcpServers": [{"serverUrl": "https://aggrete.corp.example/mcp"}],
 "strictPluginOnlyCustomization": ["mcp"]}
```

With that in place `claude mcp add` is refused, project `.mcp.json` servers do
not load, and claude.ai connectors are suppressed unless you allow them. See
https://code.claude.com/docs/en/managed-mcp for the current keys. Claude
Desktop and Claude in Slack do not yet document an equivalent lock; for those,
item 1 is what holds. For gateways you already run, see [ADAPTERS.md](ADAPTERS.md).

## Per-user access (on-behalf-of)

By default the proxy holds one credential per upstream and every caller shares it. Mark an upstream `per_user: true` and each caller instead reaches it with their *own* credential, resolved per request through an `obo` hook you control (a vault or token-exchange script), so the upstream sees the actual person — not a shared robot account. The proxy still never puts the caller's own token on the wire.

```yaml
upstreams:
  drive:
    command: python3
    args: [-m, aggrete.connectors.drive, --credentials, /opt/aggrete/sa.json, --root, Northwind]
    per_user: true
    obo:
      command: [/opt/aggrete/obo.sh]   # prints {"env": {...}, "headers": {...}} per (user, upstream)
```

## Observability

Over HTTP the proxy serves three unauthenticated operational endpoints:

| Path | What |
|---|---|
| `/healthz` | liveness: `{"ok": true, "version": ...}` |
| `/readyz` | readiness: 200 when every configured upstream is connected, else 503 with the missing names |
| `/metrics` | Prometheus text: `aggrete_decisions_total{stage,decision,domain}`, `aggrete_rule_hits_total{rule,decision}`, `aggrete_alerts_total{rule}`, `aggrete_redactions_total{kind}`, `aggrete_upstream_seconds` histogram, `aggrete_build_info` |

Counters are derived from the same rows written to `audit.jsonl`, so the graphs and the record agree. Gate `/metrics` with `metrics: {token: "${METRICS_TOKEN}"}` (scrape with `Authorization: Bearer`), or turn it off with `metrics: {enabled: false}`. The Helm chart probes `/readyz` and `/healthz`; uncomment the `prometheus.io/*` pod annotations in `values.yaml` to be scraped.

Audit rows also stream to any OpenTelemetry collector as OTLP/HTTP JSON log records (no SDK, best-effort, off the hot path), next to the Splunk/Datadog HTTP and syslog forwarders:

```yaml
audit_forward:
  otlp: {endpoint: "http://otel-collector:4318/v1/logs", headers: {x-api-key: "${OTEL_KEY}"}}
```

Each record carries the row as its body and every field as an `aggrete.*` attribute, with `event.name=aggrete.decision` and severity WARN for `deny` and `hold`.

## The Console

`audit.jsonl` and `coc.yaml` are the only two files the Aggrete Console reads — it never touches the connectors and changes nothing the proxy enforces. Put it behind your SSO (or at minimum HTTP basic auth); it shows who asked what. Keep it on the same host or a shared volume as the proxy.
