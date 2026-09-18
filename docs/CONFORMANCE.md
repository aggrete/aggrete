# Conformance

`aggrete conformance` is runnable evidence. Each check drives the real engine,
proxy call path, tool-integrity scanner, redaction, audit chain, approvals,
rate limiter and metrics against a bundled policy that has one rule per
mechanism, with a stand-in upstream that returns canned records. Nothing is
mocked in the decision path.

```bash
pip install aggrete
aggrete conformance                 # text
aggrete conformance --format md     # what auditors get
aggrete conformance --format json   # for CI; exit 1 on any failed check
```

The report maps sixteen checks onto four lists people actually ask about:

| Framework | Coverage |
|---|---|
| OWASP MCP Top 10 (2025, beta) | 7 pass, 2 partial, 1 not applicable |
| OWASP Top 10 for Agentic Applications (2026) | 6 pass, 2 partial, 2 not applicable |
| CoSAI MCP Security v2.0 threats (the 14 a proxy can address) | 13 pass, 1 partial |
| AIUC-1 (live control IDs, Sept 2026) | 16 pass, 2 partial |

"Partial" means the checks hold but the control is broader than a policy proxy;
the note on the row says what is out of scope. "Not applicable" is a server-side
or deployment property (for example, making the proxy the only permitted server,
covered in [DEPLOY.md](DEPLOY.md)). The mapping lives in
`aggrete/conformance/frameworks.yaml`; the checks in
`aggrete/conformance/__init__.py`; the policy they run against in
`aggrete/conformance/policy.yaml`.

The latest generated report is committed at
[conformance-report.md](conformance-report.md). Regenerate it with
`aggrete conformance --format md --out docs/conformance-report.md`.

What this is not: a black-box suite you can point at another gateway. That is
the next step (drive any MCP endpoint through the same scenarios with the mock
connectors), and it is on the roadmap.
