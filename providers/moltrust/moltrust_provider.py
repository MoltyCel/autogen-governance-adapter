"""MolTrust trust provider for the ``TrustProvider`` contract.

MolTrust (https://api.moltrust.ch, @MoltyCel) is a distinct project from
MoltBridge (SageMind AI). This provider implements the repo's ``TrustProvider``
Protocol against the MolTrust registry:

- ``fetch_trust_packet(did)`` reads the agent's AgentScore (0-100) from the live
  endpoint ``GET https://api.moltrust.ch/skill/trust-score/{did}``, normalizes it
  to [0.0, 1.0], and returns a ``TrustPacket`` signed with MolTrust's Ed25519
  registry key. ``issuer_did`` is ``did:web:api.moltrust.ch#key-1``.
- ``advertised_jwks()`` returns the JWKS whose ``kid == issuer_did`` so the packet
  signature verifies offline via ``verify_trust_packet``. The same public key is
  published at ``https://api.moltrust.ch/.well-known/jwks.json`` (kid
  ``did:web:api.moltrust.ch#key-1``), so a verifier can resolve it independently.

The signing key is injected, never hardcoded; in production it is MolTrust's
registry key (public part published at the JWKS above).
"""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional, Protocol

from autogen_governance_adapter.canonicalization import canonicalize, strip_signature
from autogen_governance_adapter.trust_provider import TrustPacket

MOLTRUST_BASE_URL = "https://api.moltrust.ch"
MOLTRUST_JWKS_URL = "https://api.moltrust.ch/.well-known/jwks.json"
MOLTRUST_ISSUER_DID = "did:web:api.moltrust.ch#key-1"
TRUST_CONTEXT = "behavioral_trust_v1"


class _SigningKey(Protocol):
    def sign(self, message: bytes) -> Any: ...
    @property
    def verify_key(self) -> Any: ...


class _HttpClient(Protocol):
    async def get(self, url: str) -> Any: ...


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MolTrustTrustProvider:
    """``TrustProvider`` backed by the MolTrust registry.

    Args:
        signing_key: Ed25519 signing key (``nacl.signing.SigningKey``) whose
            public key is published at the MolTrust JWKS under ``kid ==
            issuer_did``. Injected — never read from disk here.
        issuer_did: packet issuer and JWKS ``kid``. Default
            ``did:web:api.moltrust.ch#key-1`` (the published verification method).
        base_url / jwks_url: MolTrust endpoints.
        context: TrustPacket ``context`` label.
        http_client: optional async client with ``get(url)`` (injectable for
            tests). A short-lived ``httpx.AsyncClient`` is created per call when
            omitted.
        now: clock returning an ISO-8601 UTC string (injectable for tests).
    """

    def __init__(
        self,
        signing_key: _SigningKey,
        issuer_did: str = MOLTRUST_ISSUER_DID,
        base_url: str = MOLTRUST_BASE_URL,
        jwks_url: str = MOLTRUST_JWKS_URL,
        context: str = TRUST_CONTEXT,
        http_client: Optional[_HttpClient] = None,
        now: Callable[[], str] = _now_iso,
    ) -> None:
        self._sk = signing_key
        self._issuer_did = issuer_did
        self._base_url = base_url.rstrip("/")
        self._jwks_url = jwks_url
        self._context = context
        self._client = http_client
        self._now = now

    async def fetch_trust_packet(self, subject_did: str) -> TrustPacket:
        """Fetch the MolTrust score and return a signed ``TrustPacket``."""
        score = await self._fetch_score(subject_did)
        packet = TrustPacket(
            subject_did=subject_did,
            issuer_did=self._issuer_did,
            score=score,
            context=self._context,
            issued_at=self._now(),
            signature=b"",
            payload=b"",
        )
        canonical = canonicalize(strip_signature(packet.to_canonical_dict()))
        signature = self._sk.sign(canonical).signature
        return replace(packet, signature=signature)

    async def advertised_jwks(self) -> dict[str, Any]:
        """JWKS whose ``kid == issuer_did`` (single Ed25519 OKP key).

        Constructed from the configured signing key's public part. This is the
        same key published at ``MOLTRUST_JWKS_URL`` under the same ``kid``, so a
        verifier can resolve it independently and still get a byte-identical key.
        """
        public_key = bytes(self._sk.verify_key)
        return {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": self._issuer_did,
                    "x": _b64u(public_key),
                }
            ]
        }

    async def _fetch_score(self, subject_did: str) -> float:
        client = self._client
        owns_client = client is None
        if owns_client:
            import httpx

            client = httpx.AsyncClient()
        try:
            resp = await client.get(f"{self._base_url}/skill/trust-score/{subject_did}")
            resp.raise_for_status()
            data = resp.json()
        finally:
            if owns_client:
                await client.aclose()
        raw = data.get("trust_score")
        if raw is None:
            # Withheld / no score yet -> lowest trust. The hook denies closed
            # against min_trust_score; the packet stays valid and signed.
            return 0.0
        return max(0.0, min(1.0, float(raw) / 100.0))
