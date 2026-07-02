"""Regenerate MolTrust provider test fixtures deterministically.

Run: python providers/moltrust/generate_fixtures.py

Mirrors scripts/generate_fixtures.py: keys from fixed SHA-256 seeds, JCS-canonical
Ed25519 signing over the signature-stripped packet, so fixtures are byte-identical
across runs. Self-contained (jcs + pynacl only); does not import the adapter core.

The fixture provider key is a deterministic TEST key — it is NOT MolTrust's real
registry key. It only demonstrates the signing/verification round-trip offline.
The real key's public part is published at
https://api.moltrust.ch/.well-known/jwks.json (kid did:web:api.moltrust.ch#key-1).
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import jcs
from nacl.signing import SigningKey

ISSUER_DID = "did:web:api.moltrust.ch#key-1"
SUBJECT_DID = "did:moltrust:0123456789abcdef"
CONTEXT = "behavioral_trust_v1"
ISSUED_AT = "2020-01-01T00:00:00Z"
MIN_TRUST_SCORE = 0.7


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _mkkey(seed: str) -> SigningKey:
    return SigningKey(hashlib.sha256(seed.encode()).digest())


def _sign(sk: SigningKey, obj: dict[str, Any]) -> str:
    stripped = {k: v for k, v in obj.items() if k != "signature"}
    return _b64u(sk.sign(jcs.canonicalize(stripped)).signature)


def _jwks_for(public_key: bytes, kid: str) -> dict[str, Any]:
    return {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": _b64u(public_key)}]}


def _trust_packet(sk: SigningKey, score: float) -> dict[str, Any]:
    packet = {
        "subject_did": SUBJECT_DID,
        "issuer_did": ISSUER_DID,
        "score": score,
        "context": CONTEXT,
        "issued_at": ISSUED_AT,
        "payload": _b64u(b""),
    }
    packet["signature"] = _sign(sk, packet)
    return packet


def _build(score: float) -> dict[str, Any]:
    provider_sk = _mkkey("moltrust/trust-provider/test-registry")
    provider_pk = provider_sk.verify_key.encode()
    return {
        "provider_jwks": _jwks_for(provider_pk, ISSUER_DID),
        "trust_packet": _trust_packet(provider_sk, score),
        "subject_did": SUBJECT_DID,
        "min_trust_score": MIN_TRUST_SCORE,
    }


def main() -> None:
    fixtures_dir = Path(__file__).resolve().parent / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    (fixtures_dir / "happy_path.json").write_text(
        json.dumps(_build(0.85), indent=2, sort_keys=True) + "\n"
    )
    (fixtures_dir / "deny_low_trust.json").write_text(
        json.dumps(_build(0.20), indent=2, sort_keys=True) + "\n"
    )
    print(f"wrote 2 fixtures to {fixtures_dir}")


if __name__ == "__main__":
    main()
