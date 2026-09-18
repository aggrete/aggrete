# proxy.config.yaml reference

Engineering owns this file. It says which tool traffic corresponds to which
domain the clauses talk about, where the upstreams are, and how people
authenticate. Any string value may reference `${ENV_VAR}`.

```yaml
coc: coc.yaml                       # the policy file
user: someone@example.com           # stdio only; over HTTP identity comes from the token
audit_log: audit.jsonl              # hash-chained, one line per decision
audit_entities: true                # record which people appeared in each result
default_domain: unclassified        # for tools no `domains:` pattern matches
```

## Upstreams

```yaml
upstreams:
  hr:                               # tools appear as hr__<tool>
    command: python3
    args: [-m, my_hr_connector]
    env: {HR_TOKEN: "${HR_TOKEN}"}  # optional
  ops:                              # remote MCP server over streamable HTTP
    url: https://mcp.example.com/ops/mcp
    headers: {Authorization: "Bearer ${OPS_MCP_TOKEN}"}
  drive:                            # per-user (on-behalf-of) access
    command: python3
    args: [-m, aggrete.connectors.drive, --credentials, /opt/aggrete/sa.json, --root, Northwind]
    per_user: true
    obo:
      command: [/opt/aggrete/obo.sh]   # prints {"env": {...}} or {"headers": {...}} for (user, upstream)
      # users: {sam@corp: {env: {GOOGLE_DELEGATED_USER: sam@corp}}}   # or a static map
```

The proxy holds every upstream credential. The caller's own token is never
forwarded upstream, even with `per_user`.

## Domains, writes, hidden tools

```yaml
domains:                            # tool-name glob -> domain; first match wins
  "finance__pay_band": pay-aggregates
  "finance__*": finance-comp
  "hr__*": hr-personnel
  "corp__read_public_post": untrusted-web

write_tools:                        # governed as egress (prompt-injection shield, `applies: write`)
  - "*create*"
  - "*update*"
  - "*write*"
  - "*upload*"
  - "*delete*"
  - "*post*"
  - "*send*"
  - "*share*"

deny_tools:                         # never listed, never callable, for anyone
  - "*__export_all*"
```

## Authentication (required for `--transport streamable-http`)

```yaml
auth:
  mode: jwt                         # validate bearer JWTs from your IdP
  issuer: https://login.example.com/
  audience: https://aggrete.internal.example.com/mcp
  jwks_url: https://login.example.com/.well-known/jwks.json   # default: <issuer>/.well-known/jwks.json
  required_scopes: [mcp]
  identity_claim: email             # default order: email, preferred_username, sub
  resource_url: https://aggrete.internal.example.com/mcp      # publishes RFC 9728 metadata
```

```yaml
auth:
  mode: builtin                     # no IdP yet: OAuth server inside the proxy, /signin page
  issuer: https://mcp.example.com
  users: {alice@example.com: "${ALICE_PASSCODE}"}
  state: /var/lib/aggrete/signin.json
```

```yaml
auth:
  mode: static                      # development only
  tokens:
    dev-token-alice: {subject: alice@example.com}
```

```yaml
auth: {mode: anonymous}             # public mock-data demos only; every caller is one identity
```

Optional HTTP settings:

```yaml
http:
  allowed_hosts: [aggrete.internal.example.com]
  session_idle_timeout: 1800
store:
  redis_url: ${REDIS_URL}           # required for more than one replica
```

## Result handling

```yaml
redact: [email, ssn, credit_card, aws_key, api_key, bearer, ip]   # or `true` for the default set
```

Masks matches in results before they reach the model. Policy runs on the
original text first; each hit is counted in the audit row.

```yaml
scan_inbound: true                  # scan tool arguments for credential-shaped strings
scan_inbound_action: block          # block (default) or redact
```

## Approvals (human-in-the-loop)

```yaml
approvals:
  file: approvals.json              # next to the config; Redis is used when `store:` is set
  ttl: 4h                           # default length of an approval
  approvers: [security@example.com] # plus each rule's own `owner`
  wait: 0                           # seconds to hold the call open for a quick decision (max 45)
  notify: {webhook: "${SLACK_WEBHOOK}"}   # Slack-compatible; or command: [/path/to/notify.sh]
```

## Tool integrity

```yaml
tool_integrity:
  pins: /var/lib/aggrete/tool-pins.json   # trust on first use; fingerprints persisted here
  on_change: alert                  # a tool's description/schema changed (rug pull): alert | block
  on_poison: block                  # hidden instructions in a description (tool poisoning): alert | block
  scan_poison: true
```

## Rate limit

```yaml
rate_limit:
  max_calls: 120
  window: 1m                        # fixed window; s/m/h/d. Built-in tools exempt. Shared via Redis
```

## Audit forwarding

```yaml
audit_forward:
  http:
    url: "https://http-inputs.example.splunkcloud.com/services/collector/raw"
    headers: {Authorization: "Splunk ${HEC_TOKEN}"}
  # syslog: {host: siem.internal, port: 514, proto: udp}
```

```yaml
audit_forward:
  otlp: {endpoint: "http://otel-collector:4318/v1/logs"}   # any OpenTelemetry collector, no SDK
```

Best effort, off the hot path. The local hash-chained file stays the system of
record. Verify it with `aggrete-audit audit.jsonl`.

## Operations (HTTP mode)

`/healthz` (liveness), `/readyz` (503 until every upstream is connected), and
Prometheus `/metrics` (decisions, rule hits, alerts, redactions, upstream
latency histogram) are served without auth by default.

```yaml
metrics:
  token: "${METRICS_TOKEN}"   # require Authorization: Bearer on /metrics
  enabled: true
```

## What clients see

```yaml
instructions: >                     # advertised in the MCP handshake
  This proxy enforces the company code of conduct. Call aggrete__check to preview a plan.
scenarios: |                        # returned by aggrete__scenarios; `{user}` is replaced
  1. Call hr__leave_balance ...
brand:
  title: Aggrete
  website_url: https://aggrete.com
  icon_url: https://mcp.example.com/icon.svg
  icon_file: brand-icon.svg
  icon_mime: image/svg+xml
```

## Deploy shapes

| Who | How |
|---|---|
| One developer | `uvx aggrete --config proxy.config.yaml`, or `.mcp.json` in the repo |
| A team | `docker run ghcr.io/aggrete/aggrete` with `/etc/aggrete` mounted, or `helm install aggrete deploy/helm/aggrete` |
| A company | Helm/Docker behind the IdP; make `https://aggrete.<corp>/mcp` the only MCP server client policies allow; network-restrict connectors to the proxy hosts |
| Existing gateway | Embed `aggrete.plugin` (`PolicyHook`, `AggreteMiddleware`) |

Connecting claude.ai: Settings → Connectors → Add custom connector →
`https://<host>/mcp`, authentication "Always required" for anything real.
Enable it in the chat and ask for it by name the first time.
