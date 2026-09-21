"""Who is calling. Over HTTP the answer comes from the bearer token, never from config.

Two verifiers:

- JWTVerifier. Production. Validates RS256/ES256 JWTs from your IdP (Okta,
                  Entra, Google, Auth0, Keycloak…) against its JWKS, checks
                  issuer/audience/expiry, and derives the user from a claim.
- StaticTokens. Development and tests. A fixed token → subject map.

The identity the policy engine sees is `identity_for(token)`: the configured
claim (default `email`, falling back to `sub`). Per-user state in the
accumulator is keyed on it, so pick a claim that is stable across sessions.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier

DEFAULT_IDENTITY_CLAIMS = ("email", "preferred_username", "sub")


class StaticTokens(TokenVerifier):
    """`auth: {mode: static, tokens: {<token>: {subject: ..., scopes: [...]}}}`."""

    def __init__(self, tokens: dict[str, dict[str, Any]]):
        self.tokens = tokens

    async def verify_token(self, token: str) -> AccessToken | None:
        spec = self.tokens.get(token)
        if not spec:
            return None
        return AccessToken(token=token, client_id=spec.get("client_id", "static"),
                           scopes=list(spec.get("scopes", [])), subject=spec["subject"],
                           claims={"email": spec.get("email", spec["subject"])})


class JWTVerifier(TokenVerifier):
    """`auth: {mode: jwt, issuer: ..., audience: ..., jwks_url: ... | public_key: ...}`."""

    def __init__(self, issuer: str, audience: str | list[str], *, jwks_url: str | None = None,
                 public_key: str | None = None, algorithms: list[str] | None = None,
                 required_scopes: list[str] | None = None, leeway: int = 30):
        if not (jwks_url or public_key):
            jwks_url = issuer.rstrip("/") + "/.well-known/jwks.json"
        self.issuer, self.audience = issuer, audience
        self.jwks = PyJWKClient(jwks_url, cache_keys=True) if jwks_url else None
        self.public_key = public_key
        self.algorithms = algorithms or ["RS256", "ES256", "RS384", "ES384", "RS512", "ES512"]
        self.required_scopes = required_scopes or []
        self.leeway = leeway

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            key = self.public_key or self.jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=self.algorithms, issuer=self.issuer,
                                audience=self.audience, leeway=self.leeway,
                                options={"require": ["exp", "iss", "sub"]})
        except jwt.PyJWTError:
            return None
        scopes = claims.get("scope", "")
        scopes = scopes.split() if isinstance(scopes, str) else list(scopes or [])
        if any(s not in scopes for s in self.required_scopes):
            return None
        return AccessToken(token=token, client_id=str(claims.get("client_id") or claims.get("azp") or claims.get("aud")),
                           scopes=scopes, expires_at=claims.get("exp"), subject=claims["sub"], claims=claims)


def build_verifier(auth_cfg: dict[str, Any]) -> TokenVerifier:
    mode = auth_cfg.get("mode", "jwt")
    if mode == "static":
        return StaticTokens(auth_cfg["tokens"])
    if mode == "jwt":
        return JWTVerifier(auth_cfg["issuer"], auth_cfg["audience"], jwks_url=auth_cfg.get("jwks_url"),
                           public_key=auth_cfg.get("public_key"), algorithms=auth_cfg.get("algorithms"),
                           required_scopes=auth_cfg.get("required_scopes"))
    raise ValueError(f"unknown auth mode {mode!r}")


def identity_for(token: AccessToken, claim: str | None = None) -> str:
    claims = token.claims or {}
    order = (claim,) if claim else DEFAULT_IDENTITY_CLAIMS
    for c in order:
        if c and claims.get(c):
            return str(claims[c])
    if token.subject:
        return token.subject
    raise ValueError("token carries no usable identity claim")


def agent_for(token: AccessToken, claim: str | None = None, labels: dict | None = None) -> str | None:
    """The agent (assistant application) a call came from, as distinct from the
    person it acts for. Order: a configured claim; the RFC 8693 actor claim
    (`act.sub`, set when an agent acts on a person's behalf via token exchange);
    the authorized party (`azp`) or `client_id` claim; the OAuth client id.
    `labels` maps raw ids to readable names (dynamic client ids are opaque)."""
    claims = token.claims or {}
    raw = None
    if claim and claims.get(claim):
        raw = claims[claim]
    elif isinstance(claims.get("act"), dict) and claims["act"].get("sub"):
        raw = claims["act"]["sub"]
    else:
        raw = claims.get("azp") or claims.get("client_id") or token.client_id
    if not raw or raw == "static":
        return None
    raw = str(raw)
    return str((labels or {}).get(raw, raw))


def unexpired(token: AccessToken) -> bool:
    return token.expires_at is None or token.expires_at > time.time()
