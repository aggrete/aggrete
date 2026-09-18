# Adapter mode: run the engine inside the gateway you already have

Aggrete is a proxy, but the decisions do not have to live in a second hop. A
running Aggrete also serves as a policy decision point that gateways call per
tool call. Same rules, same per-person memory, same redaction, same audit
rows; the gateway keeps the connection.

Run it with no upstreams if you only want decisions:

```yaml
# proxy.config.yaml (decision-only)
coc: coc.yaml
audit_log: audit.jsonl
upstreams: {}
domains: {"hr__*": hr-personnel, "finance__*": finance-comp, "ops__*": ops-rota}
auth: {mode: jwt, issuer: ..., audience: ...}     # HTTP mode still needs auth
adapters:
  token: "${ADAPTER_TOKEN}"     # the gateway presents this as a bearer token
```

```bash
aggrete --config proxy.config.yaml --transport streamable-http --port 8080
```

Tool names must be the namespaced form the policy's `domains:` map expects
(`<upstream>__<tool>`). If your gateway exposes bare names, map them in
`domains:` the same way.

## The native endpoint

`POST /v1/decide`, bearer `adapters.token` (or an authenticated principal).

Request phase, before the tool runs:

```json
{"phase": "request", "subject": {"id": "alice@example.com"},
 "tool": "crm__export", "arguments": {"scope": "all"}, "gateway": "myproxy"}
```
```json
{"decision": "deny", "code": "PERMISSION_DENIED", "rule": "COC-DATA-010",
 "reason": "Blocked by COC-DATA-010. ...", "tool": "crm__export", "domain": "crm-customers", ...}
```

`decision` is `allow`, `deny`, `hold` (an approval request was opened; `approval`
carries its id), or `rewrite` (arguments were masked; use `arguments`).

Response phase, after the tool ran, so the people in the result are recorded
and the payload is redacted:

```json
{"phase": "response", "subject": {"id": "alice@example.com"}, "tool": "hr__recent_joiners",
 "result": {"content": [{"type": "text", "text": "[{\"email\": \"bob@example.com\"}]"}]}}
```
```json
{"decision": "rewrite", "result": "[{\"email\": \"[redacted:email]\"}]", "redacted": {"email": 1}, ...}
```

A `deny` in the response phase means the result must not reach the model
(post-call rules: small groups, self-comparison, budgets).

## OpenID AuthZEN

`POST /access/v1/evaluation` implements AuthZEN 1.0 with the COAZ-MCP default
mapping: `subject.id` is the person, `resource.id` the tool, arguments in
`resource.properties.arguments`. Allow/deny only, so redaction and holds
surface in `context`:

```json
{"subject": {"type": "user", "id": "alice@example.com"}, "action": {"name": "tools/call"},
 "resource": {"type": "tool", "id": "crm__export", "properties": {"arguments": {"scope": "all"}}}}
```
```json
{"decision": false, "context": {"reason": "...", "rule": "COC-DATA-010", "decision": "deny"}}
```

Any PEP that speaks AuthZEN (OPA-style gateways, Kong with a request-body
policy, Zuplo custom policies) can use this without knowing Aggrete.

## Docker MCP Gateway

Two `http` interceptors. `before` receives the tool call; an empty response
passes it through, a `CallToolResult` body is returned instead of calling the
tool. `after` receives the result and may replace it (redaction) or refuse it.

```bash
docker mcp gateway run \
  --interceptor "before:http:https://aggrete.internal/adapters/docker/before" \
  --interceptor "after:http:https://aggrete.internal/adapters/docker/after?tool=<name>"
```

The interceptor payload carries no caller identity, so run one gateway per
person or pass `X-Aggrete-User`. Set the bearer token on the interceptor's
request if your gateway version supports headers; otherwise put the endpoint
on a network only the gateway can reach.

## IBM ContextForge

Aggrete is an external plugin: an MCP server that answers
`get_plugin_config` and `invoke_hook` for `tool_pre_invoke` and
`tool_post_invoke`. Identity comes from ContextForge's `global_context.user`.

```yaml
# plugins/config.yaml
plugins:
  - name: aggrete
    kind: external
    mode: enforce
    priority: 50
    mcp:
      proto: STDIO
      cmd: ["python", "-m", "aggrete.adapters", "--config", "/etc/aggrete/proxy.config.yaml"]
```

A veto returns `continue_processing: false` with a violation whose `reason` is
the rule id; a redaction returns `modified_payload`.

## agentgateway

Not yet. agentgateway's ExtMCP hook is the best fit of all of these (request
and response phases, `tools/list` filtering, identity via CEL metadata), but
it is gRPC on a published proto. The adapter is on the roadmap; until then use
agentgateway's `extAuthz` with `includeRequestBody` pointed at
`/access/v1/evaluation` for allow/deny.

## What the gateway still has to do

Adapter mode governs what Aggrete is asked about. The gateway must make sure
every tool call is asked about, in both phases, with a stable subject id.
Nothing the gateway does not send can be governed.
