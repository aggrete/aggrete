# What Aggrete does not stop

Credibility beats coverage. This page lists the classes of 2025 and 2026
incidents where a policy proxy is the wrong control, so nobody buys Aggrete for
a problem it does not solve. The full scored list is in the
[conformance report](conformance-report.md).

| Class | Examples | Why a proxy cannot help | The right control |
|---|---|---|---|
| Supply chain | A worm on the MCP Registry; plugin pins not verified; SDK transport flaws | The compromise is the install, before any call is made | Registry vetting, dependency scanning (FOSSA, Snyk), pinned installs |
| Host execution | Git hooks running when an agent touches a repository | No tool call is involved | The agent vendor's sandbox |
| Client-side exfiltration | A token leaked through a URL the client downloads itself | The client acts without an MCP call | The client vendor's fix |
| Client-side policy bugs | A deny rule that silently stops applying | A policy inside the client fails with the client | Enforce outside the process (which is what a proxy is), but it cannot patch the client |
| Memory poisoning | Persistent instructions planted in assistant memory | The memory is the assistant's; no proxy sees it | Assistant vendors; the flow rule only limits what a poisoned session can send out |
| Open ports | Servers listening on the internet with no authentication | Someone else's misconfiguration | `aggrete scan` flags configs with no auth; closing the port is theirs |
| Raw shells and credentials in files | A coding agent using a token it found on disk through a CLI | Not a tool call; the proxy never sees it | Secret scanning, least-privilege tokens, sandboxes |

What it does stop, with runnable evidence: the combination of allowed reads
that forms a leak, the write that follows an untrusted read, poisoned tool
descriptions and tools that change after approval, credentials in tool
arguments, results that describe too few people, bulk extraction, and any of
these under a rule that holds for a person's sign-off. See
[CONFORMANCE.md](CONFORMANCE.md).

The honest summary of the 2026 record: a proxy would have stopped or blunted
about a third of the widely discussed incidents, the third that passed every
permission check. The rest belong to scanners and vendors, and Aggrete should
sit next to them, not instead of them.
