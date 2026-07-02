"""Fixtures for the MolTrust provider tests.

Adds the provider directory to sys.path so ``moltrust_provider`` imports without
packaging assumptions (package layout is deferred to issue #2), and loads the
JSON fixtures into ``TrustPacket`` dataclasses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autogen_governance_adapter.trust_provider import TrustPacket  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def happy_path() -> dict:
    raw = _load("happy_path.json")
    return {
        "provider_jwks": raw["provider_jwks"],
        "trust_packet": TrustPacket.from_dict(raw["trust_packet"]),
        "subject_did": raw["subject_did"],
        "min_trust_score": raw["min_trust_score"],
    }


@pytest.fixture
def deny_low_trust() -> dict:
    raw = _load("deny_low_trust.json")
    return {
        "provider_jwks": raw["provider_jwks"],
        "trust_packet": TrustPacket.from_dict(raw["trust_packet"]),
        "subject_did": raw["subject_did"],
        "min_trust_score": raw["min_trust_score"],
    }
