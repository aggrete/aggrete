# Writing policy

`coc.yaml` holds the clause text written by its owner, its enforcement, and its tests. Engineering owns the compiler, not the policy.

```yaml
- rule_id: COC-HR-004
  clause: >
    Personnel, compensation or budget records, and operational rosters may not be
    combined to derive the employment status or planned departure of individuals.
  owner: hr-privacy@example.com
  enforce:
    - layer: accumulation
      action: deny
      type: domain_join
      domains: [hr-personnel, finance-comp, ops-rota]
      require_entity_overlap: true
      scope: user
      window: 4h
  tests:
    - {name: four_prompt_layoff_list, expect: deny, sequence: [...]}
```

CI fails any rule without both an allow and a deny test — clauses that compile to nothing are the parts of your code of conduct that were never enforceable. `aggrete-lint coc.yaml --config proxy.config.yaml` catches the fail-open cases tests don't (a high-severity rule that only alerts, a wall whose `until` date has passed, an enforce block missing a required field, domains no tool is mapped to) and exits non-zero for CI.

Actions are `deny`, `approve`, or `alert` — start everything at `alert`, tune against real traffic, then flip. `approve` is the human-in-the-loop gate: the call is held (nothing fetched), a request is recorded and an approver notified, and once approved the same call goes through for a limited time. See [Approvals](#approvals).

## Rule types

- `domain_join` — deny when calls span a set of domains that overlap on the same people (`require_entity_overlap`).
- `entity_budget` — cap how many distinct people one user can pull from a domain in a window.
- `domain_block` — close a domain to `blocked_users`, or open it only to `allowed_users`, with `since`/`until` scoping.
- `wall` — a domain reachable only by `allowed_users` (privilege) or closed to `blocked_users` (embargo, investigation subjects), optionally `until` a date. Walled tools are hidden from users who could never call them.
- `self_comparison` — the requester's own record plus colleagues' records in one domain; decided post-call, since the colleague records must be seen to be counted.
- `min_group` — pay-transparency: a result about fewer than *k* people is one person's data.
- `arg_match` — decide a call from its **arguments**, not just its type. The same tool is fine or forbidden depending on what it's asked to do.

```yaml
- rule_id: COC-DATA-010
  clause: "Bulk exports are limited to your own team."
  enforce:
    - type: arg_match
      tools: ["*__export*"]
      deny_when: [{arg: scope, in: [all, company]}]   # scope=team is fine
      action: deny
```

Operators for `deny_when`: `equals`, `in`, `regex`, `gt`, `lt`, `exists`, `missing`. The `regex` operator runs your pattern against model-supplied values, so keep patterns simple and anchored (avoid nested quantifiers) to sidestep catastrophic backtracking. The built-in `check` tool previews `arg_match` too — pass `{"tool": "crm__export", "args": {"scope": "all"}}` and the dry run reports the decision without fetching.

## Purpose binding

A permanent block gets routed around. `engine.grant_purpose(user, rule_id, purpose, ttl_s)` opens a scoped window and stamps every retrieval made under it with the stated purpose. Wire it to an approval workflow owned by the clause owner named in the rule.

## Start from the document you already have

`aggrete-ingest handbook.pdf --domains proxy.config.yaml -o coc.draft.yaml` turns a code-of-conduct document into a draft `coc.yaml` — clause text verbatim, every action forced to `alert`, each rule's own tests run through the real engine before the file is written (a draft that fails its tests is rejected). Clauses no data proxy can enforce (tone, harassment, expenses) are listed separately with the reason. PDFs go to the model as native document blocks; DOCX/Markdown/text as text. Model set by `AGGRETE_INGEST_MODEL`; needs `ANTHROPIC_API_KEY`. Sample handbooks (synthetic and public-domain) are in [`../samples/`](../samples/README.md).

## Approvals

A rule whose block has `action: approve` holds the call instead of refusing it. The assistant is told the request id and that nothing was fetched; the person retries after an approver grants it. An approval is a time-limited purpose grant for that person and rule, so every retrieval made under it is audited with the approver's name.

```yaml
- rule_id: COC-HR-040
  clause: "The restructuring plan may be read only with CHRO approval."
  owner: chro@example.com          # the clause owner may always approve their own rule
  enforce:
    - type: wall
      action: approve
      domains: [restructuring-plan]
      allowed_users: [cfo@example.com]
  tests:
    - {name: cfo_reads, expect: allow, user: cfo@example.com, sequence: [{domain: restructuring-plan, entities: []}]}
    - {name: others_are_held, expect: hold, sequence: [{domain: restructuring-plan, entities: []}]}
```

Test expectations for such rules are `hold`. Approve, list, or deny from the proxy host:

```bash
aggrete approvals --config proxy.config.yaml        # pending requests
aggrete approve <id> --by chro@example.com --ttl 4h
aggrete deny <id> --by chro@example.com --note "not now"
```

Over HTTP the same actions are `GET /approvals` and `POST /approvals/<id>/approve|deny` with the approver's own bearer token; configured `approvers` and the rule's `owner` may decide. Configure in `proxy.config.yaml`:

```yaml
approvals:
  file: approvals.json           # state next to the config; Redis is used when `store:` is set
  ttl: 4h                        # how long an approval lasts by default
  approvers: [security@example.com]
  wait: 0                        # seconds to hold the call open for a quick approval (max 45)
  notify: {webhook: "${SLACK_WEBHOOK}"}   # or command: [/opt/aggrete/notify.sh]
```
