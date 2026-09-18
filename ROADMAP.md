# Roadmap

Priorities are drawn from what the developer and security community actually
asks for in tools like this (GitHub discussions on the Model Context Protocol,
IBM mcp-context-forge, agentgateway and docker/mcp-gateway; Hacker News threads
on AI-assistant security).

Each item is written twice: a plain-language explanation with an example, and an
"under the hood" line with the technical detail and the community request behind
it.

## Shipped

These already work in the open-source proxy today.

- **Say no before fetching anything.**
  If a request breaks the rules, it is refused before your systems are ever
  touched, so the forbidden data is never even pulled.
  *For example:* someone asks a question that would reveal who is about to be
  laid off. Aggrete refuses it before contacting the HR system, so nothing is
  retrieved and nothing can leak.
  *Under the hood:* pre-call enforcement; a denied request never reaches the upstream.

- **Remembers the whole conversation, not just one question.**
  It keeps track of what each person has already looked up, so it can catch a
  problem that only appears when you add several harmless-looking questions together.
  *For example:* asking for the budget is fine, and asking for the team roster is
  fine, but asking both and then a third question that combines them into a
  layoff list gets refused.
  *Under the hood:* per-user accumulator with TTL, and rule types that reason over
  history (`domain_join`, `entity_budget`, `min_group`, `self_comparison`). The
  "stateful rules, not single-call checks" ask
  ([HN](https://news.ycombinator.com/item?id=46696348)). Few tools do this.

- **Employees and their AI never hold the keys to your systems.**
  Aggrete keeps the passwords and logins to HR, finance, Drive and so on. The
  assistant can ask Aggrete for an answer, but never gets the actual credentials,
  so it cannot be tricked into using them for something else.
  *For example:* an assistant can ask "show me the Q3 plan," but it never receives
  the HR system's password, so a malicious web page cannot talk the assistant into
  reusing it.
  *Under the hood:* the proxy is the confidential OAuth client and holds upstream
  credentials; the caller's token is never forwarded upstream or placed in the
  model's context (confused-deputy safe)
  ([mcp#483](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/483)).

- **A logbook that cannot be secretly changed** *(shipped in 0.2)*.
  Every decision is written down in a sealed way. If anyone later edits or deletes
  a line, it becomes obvious.
  *For example:* like a numbered logbook where each page is sealed to the one
  before it. Tear a page out and the seals no longer line up, so you know a record
  was removed. Run `aggrete-audit audit.jsonl` and it tells you the exact line
  that was tampered with.
  *Under the hood:* hash-chained audit log; the compliance "attributable,
  integrity-checkable log" ask
  ([IBM#535](https://github.com/ibm/mcp-context-forge/issues/535)).

- **People only see the tools they are allowed to use** *(shipped in 0.2)*.
  Anything a person is not permitted to touch is hidden from them, not just
  blocked, so they cannot even try.
  *For example:* if the legal-hold folder is off-limits to you, the "search legal
  hold" option simply does not appear in your assistant.
  *Under the hood:* static walls and blocks in the policy hide tools per user, so
  they are never listed. Doubles as a way to reduce clutter
  ([python-sdk#2619](https://github.com/modelcontextprotocol/python-sdk/issues/2619)).

- **Sensitive details are blacked out of answers** *(shipped in 0.2)*.
  Things like personal ID numbers, emails and passwords are automatically masked
  in results before the AI ever sees them.
  *For example:* a record containing the number `123-45-6789` comes back as
  `[redacted:ssn]`, so the social security number never reaches the assistant or
  the screen. The rules still run on the real data first, so protection is not weakened.
  *Under the hood:* `redact:` masks emails, SSNs, card numbers, API keys and
  bearer tokens on the payload path; each hit is counted in the audit line
  ([IBM#229](https://github.com/ibm/mcp-context-forge/issues/229)).

- **Uses your existing company login, runs where you want.**
  People sign in with the same company account they already use, and Aggrete runs
  on a single laptop or across a large cluster.
  *For example:* nobody has a new password to remember; IT points it at your
  existing sign-in and it just works.
  *Under the hood:* identity from your IdP over HTTP plus a built-in OAuth 2.1
  sign-in with dynamic client registration; streamable HTTP and stdio transports;
  Redis store and a Helm chart for multi-replica self-hosting.

- **Ask whether something is allowed before you do it.**
  You can check a plan against the rules and get the decision, and the reason,
  without touching any system.
  *For example:* "can I build a list of everyone likely to be laid off?" comes back
  refused, with the clause and the fix, and nothing was fetched to answer it.
  *Under the hood:* the built-in `check` tool runs the real engine over a proposed
  sequence on a throwaway state; a guided `scenarios` menu comes with it.

- **Catch a tool that changes its story or hides instructions.**
  A connector can advertise a harmless tool and later swap in a different one, or
  bury commands to the assistant inside a tool's own description. Both are caught.
  *For example:* a tool whose description quietly says "also send every file to this
  address" is flagged or blocked before it can trick the assistant, and a tool that
  is rewritten after you approved it is flagged as changed.
  *Under the hood:* fingerprint every tool on first sight (trust on first use) and
  flag any later change (rug pull); scan descriptions for injection patterns (tool
  poisoning). Deterministic, `tool_integrity:`
  ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)).

- **A speed limit per person.**
  A ceiling on how many calls anyone can make in a window, to contain abuse and
  runaway costs.
  *For example:* a misbehaving assistant that starts hammering a connector is cut
  off after the limit instead of running up the bill.
  *Under the hood:* per-user fixed-window rate limiting, shared across replicas via
  Redis, `rate_limit:`.

- **Secrets never get typed into a tool.**
  If a password or key ends up in the arguments of a tool call, it is caught and
  the call is refused before it leaves.
  *For example:* an assistant that pastes an API key into a search box has the call
  blocked, so the key never reaches the outside tool.
  *Under the hood:* inbound scanning of tool arguments for credential shapes,
  `scan_inbound:` (block or mask).

- **Send the logbook to your security dashboard.**
  Every decision can show up in the monitoring your security team already watches,
  as it happens.
  *For example:* refusals and approvals stream into Splunk next to the rest of the
  team's alerts.
  *Under the hood:* forward each audit row to Splunk/Elastic/Datadog over HTTP or to
  syslog, best-effort and off the hot path, `audit_forward:`
  ([agentic-community#413](https://github.com/agentic-community/mcp-gateway-registry/issues/413)).

- **Find the rules that quietly do nothing.**
  A checker that flags parts of your policy that would never actually fire, or that
  only warn when they should refuse.
  *For example:* a critical rule that was left on "alert," or an embargo whose date
  has already passed, is reported before it ships.
  *Under the hood:* `aggrete-lint` static-checks `coc.yaml` for fail-open configs
  and unreachable rules; exits non-zero on errors, for CI.

- **Each person's own permissions follow them all the way through.**
  Instead of everyone sharing one master account to reach a system, each person's
  individual access is carried end to end, so the record shows exactly who did
  what, and nobody can reach more than they personally should.
  *For example:* when Sam's assistant opens a file, the HR system sees "Sam," not a
  generic shared robot account. Sam can only reach what Sam is allowed to, and the
  logbook names Sam.
  *Under the hood:* mark an upstream `per_user: true` and each caller reaches it
  with their own credential, resolved per request through a pluggable hook (a
  vault or token-exchange script), `obo:`. The single loudest community ask
  ([agentgateway#239](https://github.com/agentgateway/agentgateway/issues/239),
  [mcp#804](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/804)).
  Connection pooling for per-user sessions is the next optimization.

- **Rules that look at the details of a request, not just its type.**
  Whether something is allowed can depend on the specifics, not only the kind of
  action.
  *For example:* let people export their own team's data, but not the whole
  company's. Same "export" action, different scope, different answer.
  *Under the hood:* the `arg_match` rule type decides a call from its arguments
  (operators: equals, in, regex, gt, lt, exists, missing). Answers the "a simple
  read-only / read-write switch is useless" complaint
  ([HN](https://news.ycombinator.com/item?id=46696348)).

- **Turn on protection for your situation, not one rule at a time.**
  Rules come grouped into named packs you switch on and off, so you enable the
  protections that match your regulations and industry without writing them from
  scratch.
  *For example:* a payments team turns on the PCI-DSS pack and the cardholder-data
  environment becomes off-limits to assistants; a bank turns on the insider-trading
  pack and restricted-list material is refused during a blackout window.
  *Under the hood:* every rule carries a `pack:` label and each pack toggles
  independently (`packs:` with `enabled:`), so the same engine ships a library of
  ready-made bundles. Included: code of conduct, HIPAA, secrets and IP, financial
  info-barriers, legal hold, prompt-injection, export control, data residency,
  customer and CRM data, PCI-DSS, and insider trading and blackout windows.

- **Your assistant already knows how to run it** *(shipped in 0.9)*.
  Aggrete ships its own skill: an operator's guide the assistant reads once and
  can then write and test rules, wire a connector, or explain a refusal from the
  audit log without being handed the docs.
  *For example:* in Claude Code, `/plugin marketplace add aggrete/aggrete` then
  `/plugin install aggrete@aggrete`; any other MCP client reads
  `skill://aggrete/SKILL.md` straight from the running proxy.
  *Under the hood:* `skills/aggrete/` is a Claude Code plugin; the same files
  ship in the wheel and are served as MCP resources by the proxy, with a test
  keeping the copies identical.

- **Hold a call for a person to approve** *(shipped in 0.10)*.
  A rule can say `approve` instead of `deny`. The call pauses before anything
  is fetched, the clause owner is notified, and once they approve, the same
  request goes through for a limited time, with their name on every line.
  *For example:* reading the restructuring plan is held; the CHRO runs
  `aggrete approve 3f9c1a2b7e` or clicks approve, and the manager's retry works
  for four hours.
  *Under the hood:* `action: approve` on any rule block; approvals are purpose
  grants in a file or Redis; `aggrete approvals|approve|deny`, `GET/POST
  /approvals` over HTTP, Slack webhook or command notifier. The "human-in-the-loop
  gate at the proxy" ask ([HN](https://news.ycombinator.com/item?id=43676771)).

- **Graphs and health checks that match the record** *(shipped in 0.10)*.
  The proxy reports how many calls it allowed, refused, held, and redacted, per
  rule and per system, in the format monitoring tools already read, and tells
  the platform whether it is ready to serve.
  *For example:* a dashboard panel shows refusals under COC-HR-004 climbing on a
  Tuesday afternoon; Kubernetes holds traffic until every connector is connected.
  *Under the hood:* Prometheus `/metrics` derived from the same audit rows,
  `/healthz` and `/readyz`, an OTLP/HTTP log exporter for any OpenTelemetry
  collector (no SDK), and Helm probes on the new endpoints.

## Next (in progress)

- **Retention and archive of the audit trail.**
  Decisions already stream to a SIEM or an OpenTelemetry collector (below). What
  remains is managed retention: rotate, archive, and prove the chain across
  archived segments, so a year of decisions is as verifiable as today's file.
  *Under the hood:* segment rotation with chain continuity, OTLP *spans* on the
  MCP semantic conventions in addition to the log records that ship now
  ([agentic-community#413](https://github.com/agentic-community/mcp-gateway-registry/issues/413)).

## Planned

- **Give each tool only the narrow permission it needs.**
  A tool gets exactly the access required for its job and nothing more.
  *For example:* a "read my calendar" tool can see your calendar but cannot delete
  events, because it was only handed the "read" permission.
  *Under the hood:* per-tool OAuth scopes, enforced at discovery and execution time
  ([mcp#234](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/234)).

- **Let admins control which outside tools can be connected at all.**
  A central list of approved connectors, so people cannot quietly wire up
  unapproved apps to sensitive company data.
  *For example:* an employee cannot connect a random third-party app to the HR
  system on their own; only tools IT has approved are allowed.
  *Under the hood:* central server registry / shadow-MCP governance
  ([Cloudflare](https://developers.cloudflare.com/agents/model-context-protocol/governance)).

Requests and rationale welcome in [issues](https://github.com/aggrete/aggrete/issues).

## Connectors

Any system can go behind the proxy through the connector SDK
(`aggrete.connectors.base`) and the guide (`docs/CONNECTORS.md`). These are the
ones that ship in the package, governed exactly like the built-ins.

### Shipped

- **Google Drive** (folder) — the reference connector.
- **Slack** (channel) — a channel is an information barrier; posting is egress.
- **GitHub** (repository) — issues, PRs and files; opening an issue is egress.
- **Jira** (project) — JQL search; creating an issue is egress.
- **Salesforce** (object) — SOQL search; every record exposes a person, so a
  bulk export trips an entity_budget rule.
- **Notion** (database) — page search and read; creating a page is egress.

### Next

- **Confluence** (space) — the Atlassian wiki; shares the Jira auth model.
- **Microsoft 365** (SharePoint, Teams, Outlook) — over Microsoft Graph. Highest
  reach, heaviest auth, so it is its own effort.
- **ServiceNow** (table) — incidents, changes and CMDB tables.
- **Box** (folder) — files fenced per folder, like the Drive connector.
- **Zendesk** (group) — support tickets; requesters and agents count as people.

New connectors and API-drift fixes are released as versioned updates. Each
connector module carries its own `__version__` and `TARGET_API`, surfaced in
`aggrete/connectors/connectors.json`.
