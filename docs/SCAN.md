# aggrete scan: harden an existing MCP setup

`aggrete scan` is the first thing to run on a machine that already uses MCP.
It finds every server your clients are configured to use, connects to each,
and prints the findings no per-server scanner does.

```bash
pip install aggrete
aggrete scan                        # this machine's client configs
aggrete scan --dir ~/work/repo      # plus a project's .mcp.json, .cursor, .vscode
aggrete scan --format json          # exit 1 on any high-severity finding (CI)
aggrete scan --fix ./aggrete        # write the proxy config and policy that close them
```

## What it reads

Claude Code (user, project, local and managed), Claude Desktop, Cursor,
VS Code and Copilot, Windsurf, Gemini CLI, Codex, and any file passed with
`--config`. Nothing is modified. Pins for tool fingerprints are kept in
`~/.aggrete/scan-pins.json`.

## What it reports

| Finding | Severity | Why it matters |
|---|---|---|
| Personnel + budget + rota reachable | high | The layoff-list path: three allowed reads that add up |
| An untrusted reader next to a writer | high | The exfiltration path behind the 2025 GitHub MCP and 2026 Copilot invoice attacks |
| Untrusted content next to private code | high | Hidden instructions can point the assistant at private repositories |
| A secrets tool next to a writer | high | Credential exfiltration |
| Hidden instructions in a tool description | high | Tool poisoning; the user never sees descriptions, the model does |
| A credential in a client config | high | Anyone who reads the file holds it; every call carries it |
| A server reachable without the proxy | high | A policy is only a control if the proxy is the only path |
| A tool changed since last seen | medium | A rug pull: approved once, different now |
| A remote server with no Authorization header | medium | Unauthenticated, or signed in elsewhere; the scan cannot tell |
| A GitHub token with write scopes on a read-only server | medium | With `--check-scopes`; one harmless `GET /user` |

Combinations are detected across servers, not within one. Tools are mapped to
policy domains by name and description (hr, finance, rota, untrusted web,
private code, CRM, secrets, notes, chat, mail); the map is a heuristic, which
is why `--fix` writes the domain map out for you to review.

## The fix

`--fix DIR` writes `proxy.config.yaml` fronting the discovered servers, with
redaction, inbound secret scanning and tool-integrity pinning switched on, and
`coc.yaml` with rules for exactly the combinations found: a `domain_join` for
the layoff path, a `flow` rule for the exfiltration path, an `entity_budget`
for bulk customer extraction. Rules start at `alert`. Then:

```bash
aggrete --config ./aggrete/proxy.config.yaml
```

and point the clients at the proxy instead of at the servers directly
([the only path](DEPLOY.md#the-only-path)).

## What it does not do

It does not find servers it cannot read the config of, servers reachable only
from another network, or supply-chain problems inside a server's code (a
dependency scanner does that). Domain classification can miss a tool with an
unusual name; a scan with no findings is not a clean bill.
