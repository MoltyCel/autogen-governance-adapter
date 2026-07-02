# providers/moltrust/

`MolTrustTrustProvider` — a `TrustProvider` backed by the MolTrust registry
(`api.moltrust.ch`, maintainer @MoltyCel).

> MolTrust is a distinct project from MoltBridge (SageMind AI). Different API,
> different keys, different namespace. This provider does not touch the
> MoltBridge slot.

## Contract

Implements `TrustProvider` from
[`src/autogen_governance_adapter/trust_provider.py`](../../src/autogen_governance_adapter/trust_provider.py):

- `async fetch_trust_packet(subject_did) -> TrustPacket`
- `async advertised_jwks() -> dict`

The packet signature verifies offline via `verify_trust_packet` — deny-closed on
any signature, `kid`, or key-match failure.

## How it maps to MolTrust

| Contract field / step | MolTrust source |
| --- | --- |
| `score` (0.0–1.0) | `GET https://api.moltrust.ch/skill/trust-score/{did}` → `trust_score` (0–100), normalized `/100`, clamped to [0,1]. `null`/withheld → `0.0`. |
| packet signature | Ed25519 over `canonicalize(strip_signature(packet))` (JCS / RFC 8785), signed with MolTrust's registry key. |
| `issuer_did` / JWKS `kid` | `did:web:api.moltrust.ch#key-1` |
| `advertised_jwks()` | single Ed25519 OKP key, `kid = did:web:api.moltrust.ch#key-1`. The **same** public key is published at `https://api.moltrust.ch/.well-known/jwks.json`, so a verifier can resolve it independently. |

Verified live endpoints used: **`GET /skill/trust-score/{did}`** (score) and the
published **`/.well-known/jwks.json`** (verification key). No other endpoints.

## Signing key

The signing key is **injected** into the constructor — never read from disk or
hardcoded here. In production it is MolTrust's registry key, whose public part is
the `did:web:api.moltrust.ch#key-1` entry in the published JWKS. Fixtures use a
deterministic **test** key (see `generate_fixtures.py`), not the real key.

## Usage

```python
from nacl.signing import SigningKey
from moltrust_provider import MolTrustTrustProvider

provider = MolTrustTrustProvider(signing_key=SigningKey(moltrust_registry_key_bytes))
# pass provider to governedToolCall(..., trust_provider=provider, min_trust_score=0.7)
```

## Tests / fixtures

```
python providers/moltrust/generate_fixtures.py            # regenerate fixtures
pytest providers/moltrust/tests                           # run provider tests
```

Fixtures (`tests/fixtures/happy_path.json`, `deny_low_trust.json`) mirror the
core `tests/` shape: a signed packet + its `provider_jwks`.

## Package layout

Provisional. The provider package/registration convention is being designed in
[issue #2](https://github.com/aeoess/autogen-governance-adapter/issues/2) for the
first provider PR (MoltBridge). This directory is self-contained and will be
realigned to whatever #2 settles — this PR does not claim the first-provider slot.
