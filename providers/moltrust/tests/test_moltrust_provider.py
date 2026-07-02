"""MolTrust provider tests — offline, no live API calls.

Two layers:
1. Fixture-based, mirroring tests/test_trust_provider.py: a pre-signed packet
   verifies against its advertised JWKS; kid mismatch and tampered signatures
   fail closed.
2. Provider round-trip: a mocked ``/skill/trust-score`` response is fetched,
   normalized 0-100 -> [0,1], signed into a TrustPacket, and verified offline
   against ``advertised_jwks()``.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from nacl.signing import SigningKey

from autogen_governance_adapter.trust_provider import verify_trust_packet
from moltrust_provider import MolTrustTrustProvider

DID = "did:moltrust:0123456789abcdef"
ISSUER = "did:web:api.moltrust.ch#key-1"


def _key(seed: str = "moltrust/test/registry") -> SigningKey:
    return SigningKey(hashlib.sha256(seed.encode()).digest())


class _FakeResp:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    """Minimal httpx-like async client returning one canned trust-score body."""

    def __init__(self, payload: dict):
        self._payload = payload
        self.calls: list[str] = []

    async def get(self, url: str) -> _FakeResp:
        self.calls.append(url)
        return _FakeResp(self._payload)


def _provider(payload: dict, client: _FakeClient | None = None) -> MolTrustTrustProvider:
    return MolTrustTrustProvider(
        signing_key=_key(),
        http_client=client or _FakeClient(payload),
        now=lambda: "2020-01-01T00:00:00Z",
    )


# --- fixture-based (mirrors tests/test_trust_provider.py) -----------------

def test_fixture_packet_verifies(happy_path):
    assert verify_trust_packet(happy_path["trust_packet"], happy_path["provider_jwks"]) is True


def test_fixture_kid_mismatch_fails(happy_path):
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "did:web:api.moltrust.ch#wrong-key",
                "x": happy_path["provider_jwks"]["keys"][0]["x"],
            }
        ]
    }
    assert verify_trust_packet(happy_path["trust_packet"], jwks) is False


def test_fixture_tampered_signature_fails(happy_path):
    packet = happy_path["trust_packet"]
    tampered = replace(
        packet, signature=packet.signature[:-1] + bytes([packet.signature[-1] ^ 0x01])
    )
    assert verify_trust_packet(tampered, happy_path["provider_jwks"]) is False


def test_fixture_deny_below_threshold(deny_low_trust):
    # Packet is valid and signed; its score is below min_trust_score -> the hook
    # denies closed. The provider's job is to deliver a verifiable low score.
    assert verify_trust_packet(deny_low_trust["trust_packet"], deny_low_trust["provider_jwks"]) is True
    assert deny_low_trust["trust_packet"].score < deny_low_trust["min_trust_score"]


# --- provider round-trip (mocked score fetch) -----------------------------

@pytest.mark.asyncio
async def test_roundtrip_fetch_sign_verify():
    provider = _provider({"trust_score": 85, "grade": "B"})
    packet = await provider.fetch_trust_packet(DID)
    jwks = await provider.advertised_jwks()
    assert packet.subject_did == DID
    assert packet.issuer_did == ISSUER
    assert packet.score == 0.85
    assert verify_trust_packet(packet, jwks) is True


@pytest.mark.asyncio
async def test_score_normalized_0_100_to_0_1():
    provider = _provider({"trust_score": 60})
    assert (await provider.fetch_trust_packet(DID)).score == 0.6


@pytest.mark.asyncio
async def test_withheld_score_maps_to_zero():
    provider = _provider({"trust_score": None, "withheld": True})
    packet = await provider.fetch_trust_packet(DID)
    jwks = await provider.advertised_jwks()
    assert packet.score == 0.0
    assert verify_trust_packet(packet, jwks) is True


@pytest.mark.asyncio
async def test_fetch_hits_verified_score_endpoint():
    client = _FakeClient({"trust_score": 50})
    provider = _provider({}, client=client)
    await provider.fetch_trust_packet(DID)
    assert any(u.endswith(f"/skill/trust-score/{DID}") for u in client.calls)


@pytest.mark.asyncio
async def test_advertised_jwks_shape():
    provider = _provider({"trust_score": 10})
    key = (await provider.advertised_jwks())["keys"][0]
    assert key["kid"] == ISSUER and key["kty"] == "OKP" and key["crv"] == "Ed25519"


@pytest.mark.asyncio
async def test_roundtrip_kid_mismatch_fails():
    provider = _provider({"trust_score": 90})
    packet = await provider.fetch_trust_packet(DID)
    jwks = await provider.advertised_jwks()
    jwks["keys"][0]["kid"] = "did:web:api.moltrust.ch#other"
    assert verify_trust_packet(packet, jwks) is False
