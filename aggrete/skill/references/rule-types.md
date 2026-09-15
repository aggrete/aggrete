# Rule types: field reference

Every rule in `coc.yaml` has this shape. `enforce` is a list, so one clause can
compile to several mechanisms.

```yaml
- rule_id: COC-XX-000        # unique; referenced from audit rows and remediation
  pack: code-of-conduct      # optional; groups rules an operator toggles together
  title: Short human title
  clause: >                  # the clause text, verbatim from the handbook
    ...
  owner: someone@example.com # the clause owner, not engineering
  severity: low | medium | high | critical
  remediation: >             # shown to the refused user; the path to a sanctioned exception
    ...
  enforce:
    - layer: retrieval | accumulation
      action: deny | alert
      type: <one of the types below>
      applies: read | write  # optional; default both. `write` targets egress tools only
      ...type-specific fields
  tests:
    - ...                    # at least one `expect: allow` and one `expect: deny` or `alert`
```

`layer: retrieval` blocks decide from the request alone (pre-call).
`layer: accumulation` blocks reason over the user's recent history.
`window` accepts `s`, `m`, `h`, `d` suffixes (`4h`, `24h`, `7d`). `scope: user`
is the only supported scope today.

## `domain_join`

Deny when a user's reads within `window` span every domain in `domains`. With
`require_entity_overlap: true`, only fires when the same person appears in the
results from each domain, which is what turns "budget + roster" into "budget
and roster about Alice".

```yaml
- layer: accumulation
  action: deny
  type: domain_join
  domains: [hr-personnel, finance-comp, ops-rota]
  require_entity_overlap: true
  scope: user
  window: 4h
```

Decided pre-call for the call that would complete the set, so the last
domain's data is never fetched.

## `entity_budget`

Cap the number of distinct people one user can pull from one domain per window.
Counted post-call from extracted entities.

```yaml
- layer: accumulation
  action: alert            # start here; flip to deny once the threshold is tuned
  type: entity_budget
  domain: crm-customers
  max_distinct: 12
  scope: user
  window: 24h
```

## `wall`

A domain reachable only by `allowed_users` (a privilege wall), or closed to
`blocked_users` (an embargo, or the subject of an investigation). Optional
`until: YYYY-MM-DD`. Tools in a walled domain are **hidden** from users who
could never call them, not just refused.

```yaml
- layer: retrieval
  action: deny
  type: wall
  domains: [restructuring-plan]
  allowed_users: [cfo@example.com, chro@example.com]
  until: 2026-12-31
```

Lint flags a wall whose `until` has already passed.

## `domain_block`

Close a domain outright, close it to `blocked_users`, or open it only to
`allowed_users`, with optional `since` / `until` dates. Use `applies: write`
to block only writes into a domain (e.g. no posting into a shared channel).

```yaml
- layer: retrieval
  action: deny
  type: domain_block
  domains: [legal-hold]
```

```yaml
- layer: retrieval
  action: deny
  type: domain_block
  domains: [shared-notes]
  applies: write
  blocked_users: [contractor@example.com]
```

## `self_comparison`

Refuse the requester's own record plus colleagues' records in the same domain
within the window. Decided post-call, because the colleague records have to be
seen to be counted. The requester is identified by their own email entity.

```yaml
- layer: accumulation
  action: deny
  type: self_comparison
  domain: timesheets
  scope: user
  window: 24h
```

## `min_group`

Pay-transparency style: a result describing fewer than `k` people is one
person's data. Post-call, from the entity count in the result.

```yaml
- layer: accumulation
  action: deny
  type: min_group
  domain: pay-aggregates
  k: 10
  scope: user
  window: 24h
```

## `flow`

The prompt-injection shield. Once a session has read from any `taint_domains`
domain, any call into `egress_domains`, and (by default) any write tool at all,
is refused until the session ends. Pre-call, no content inspection.

```yaml
- layer: retrieval
  action: deny
  type: flow
  taint_domains: [public-issues, untrusted-web]
  egress_domains: [private-repos, external-share]
  egress_on_write: true    # default; set false to govern only egress_domains
```

## `arg_match`

Decide from the call's **arguments**. `tools` is a list of glob patterns on the
namespaced tool name. `deny_when` is a list of conditions; the call is refused
when any condition matches.

```yaml
- layer: retrieval
  action: deny
  type: arg_match
  tools: ["*__export*", "*bulk_export*"]
  deny_when:
    - {arg: scope, in: [all, company, everyone]}
    - {arg: limit, gt: 500}
    - {arg: filter, missing: true}
```

Condition operators, one per condition: `equals`, `in`, `regex`, `gt`, `lt`,
`exists`, `missing`. Values are compared as strings for `equals`, as numbers
for `gt`/`lt`. Keep `regex` patterns anchored and simple; they run against
model-supplied input.

## Tests

Two forms. A **sequence** test replays reads through the real engine as one
user:

```yaml
tests:
  - name: four_prompt_layoff_list
    expect: deny                 # allow | deny | alert
    user: alice@example.com      # optional; defaults to the test user
    sequence:
      - {domain: finance-comp, entities: [p:alice, p:bob]}
      - {domain: hr-personnel, entities: [p:alice, p:bob, p:dan]}
      - {domain: ops-rota, entities: [p:alice, p:dan], write: false}
```

Entity ids are `p:<stable id>`; in production they are `p:<email>`. A step
may carry `write: true` to represent an egress call, or `tool` + `args` to
exercise an `arg_match` rule.

An **argument** test checks a single call:

```yaml
tests:
  - {name: team_scoped_export_is_fine, expect: allow, tool: crm__export, args: {scope: team}}
  - {name: company_wide_export_is_refused, expect: deny, tool: crm__export, args: {scope: all}}
```

`pytest tests/test_coc.py` runs every rule's tests and fails any rule missing
an allow or a deny/alert expectation.

## Packs

```yaml
packs:
  - id: code-of-conduct
    name: Code of conduct
    description: One sentence for the operator.
    example: "Budget + personnel + rota, refused before it forms."
    watches: [hr-personnel, finance-comp, ops-rota]
    enabled: true
```

A rule's `pack:` ties it to a pack; `enabled: false` switches every rule in the
pack off. Shipped packs: code-of-conduct, financial-info-barrier, hipaa,
secrets-dlp, prompt-injection, legal-hold, export-control, data-residency,
customer-data, pci-dss, insider-trading.

## Purpose binding

A permanent block gets routed around. `engine.grant_purpose(user, rule_id,
purpose, ttl_s)` opens a scoped exception and stamps every retrieval made under
it with the stated purpose. Wire it to an approval flow owned by the clause
owner named in `remediation`.
