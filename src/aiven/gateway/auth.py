"""Who calls (plan Task 3.3; gateway-design section 4, AT-BYP-4).

The caller is the email of a Google-signed ID token in `Authorization: Bearer`, whose audience is
the gateway's URL and whose email is verified. Nothing else names a caller: no other header, no
field of a body. The control UI's account is the control API's caller; every other account is an
agent, which still needs a policy whose `principal` is its email (pipeline.py).

`GoogleTokenVerifier` checks the token's signature against Google's public certificates, which it
keeps for an hour (and fetches again for a key it does not know), its issuer, audience and expiry.
"""

import time
from collections.abc import Callable, Mapping
from typing import Any

from aiven.gateway.types import Caller

GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
ISSUERS = ("accounts.google.com", "https://accounts.google.com")
CERTS_KEPT_S = 3600

Verifier = Callable[[str, str], Mapping[str, Any]]


class GoogleTokenVerifier:
    """Verify a Google ID token for an audience; raises ValueError for any token that fails."""

    def __init__(self, fetch: Callable[[], dict[str, str]] | None = None) -> None:
        self._fetch = fetch or self._fetch_from_google
        self._certs: dict[str, str] = {}
        self._fetched = 0.0

    @staticmethod
    def _fetch_from_google() -> dict[str, str]:  # pragma: no cover - Google's certificates
        from google.auth.transport.requests import Request

        response = Request()(url=GOOGLE_CERTS_URL, method="GET")
        if response.status != 200:
            raise ValueError("Google's certificates could not be fetched")
        import json

        return json.loads(response.data)

    def _certificates(self, key_id: str | None) -> dict[str, str]:
        stale = time.monotonic() - self._fetched > CERTS_KEPT_S
        if stale or (key_id is not None and key_id not in self._certs):
            self._certs = self._fetch()
            self._fetched = time.monotonic()
        return self._certs

    def __call__(self, token: str, audience: str) -> Mapping[str, Any]:
        from google.auth import jwt

        header = jwt.decode_header(token)
        certs = self._certificates(header.get("kid"))
        claims = jwt.decode(token, certs=certs, audience=audience)
        if claims.get("iss") not in ISSUERS:
            raise ValueError("the token is not Google's")
        return claims


def caller_of(
    authorization: str | None, *, verifier: Verifier, audience: str, control_ui: str
) -> Caller | None:
    """The caller of a request with this Authorization header, or None (401)."""
    scheme, _, token = (authorization or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None
    try:
        claims = verifier(token, audience)
    except Exception:
        return None
    email = claims.get("email")
    if claims.get("email_verified") is not True or not isinstance(email, str) or not email:
        return None
    return Caller(email, "control" if email == control_ui else "agent")
