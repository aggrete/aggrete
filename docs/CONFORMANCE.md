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

## Black-box: score any gateway

The same scenarios run from the outside, over real MCP, against any endpoint.
Nothing in the suite knows how a gateway words a refusal: every fixture payload
carries a unique marker, and a scenario passes when the forbidden marker never
reaches the client.

```bash
# 1. front this fixture connector with the gateway under test (stdio MCP server)
python -m aggrete._mockco --profile fixture

# 2. run the scenarios against the gateway
aggrete conformance --url https://gateway.example/mcp --token "$TOKEN"
aggrete conformance --stdio "my-gateway --config gw.yaml"

aggrete conformance --self                 # Aggrete itself, as the reference
aggrete conformance --write-fixture ./fx   # the reference config and policy
```

| Scenario | What it tests |
|---|---|
| B01 | Budget, personnel and rota about the same people: the third read must not arrive |
| B02 | A write is allowed before an untrusted read and refused after it |
| B03 | An export is allowed for `scope=team` and refused for `scope=all` |
| B04 | An SSN in a result never reaches the client |
| B05 | A credential in the arguments never reaches the upstream |
| B06 | A tool with hidden instructions in its description is not usable |
| B07 | A tool this person may never call is hidden or refused |
| B08 | Refusals carry a readable reason, not a bare error |

Controls run in one session as one identity, in a fixed order, because several
are about memory across calls. Each has a control step so a target that simply
blocks everything scores "inconclusive", not "pass". The report maps scenarios
onto the same four frameworks; controls that cannot be seen from outside (audit
integrity, identity handling, approvals) are marked "not observable" rather
than guessed. The bare fixture with nothing in front of it fails B01 to B07,
which is the suite's own sanity check.
