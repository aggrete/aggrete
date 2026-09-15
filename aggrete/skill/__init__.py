"""The Aggrete skill, served over MCP as resources.

The same files ship in the repo at ``skills/aggrete/`` for the Claude Code
plugin; ``tests/test_skill.py`` keeps the two copies identical. A client that
reads ``skill://aggrete/SKILL.md`` gets an operator's guide to writing policy,
wiring connectors, deploying, and reading the audit log.
"""

from __future__ import annotations

from importlib import resources

import mcp.types as types

URI_PREFIX = "skill://aggrete/"
FILES = ("SKILL.md", "references/rule-types.md", "references/config.md")
_TITLES = {
    "SKILL.md": "Aggrete skill: set up and operate the policy proxy",
    "references/rule-types.md": "Aggrete rule types: field reference",
    "references/config.md": "Aggrete proxy.config.yaml reference",
}


def _root():
    return resources.files(__name__)


def read(path: str) -> str | None:
    """Return the text of one skill file by its path under the prefix, or None."""
    if path not in FILES:
        return None
    return _root().joinpath(path).read_text(encoding="utf-8")


def list_resources() -> list[types.Resource]:
    return [
        types.Resource(
            uri=URI_PREFIX + path,
            name=path,
            title=_TITLES[path],
            description=("Read this first: how to write coc.yaml rules, wire connectors, deploy, "
                         "and read the audit log." if path == "SKILL.md" else None),
            mime_type="text/markdown",
        )
        for path in FILES
    ]


def read_resource(uri: str) -> types.ReadResourceResult | None:
    uri = str(uri)
    if not uri.startswith(URI_PREFIX):
        return None
    text = read(uri[len(URI_PREFIX):])
    if text is None:
        return None
    return types.ReadResourceResult(
        contents=[types.TextResourceContents(uri=uri, mime_type="text/markdown", text=text)]
    )
