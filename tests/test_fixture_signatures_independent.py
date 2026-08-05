"""Re-verify every fixture signature through a path that shares no code with them.

A green conformance run only proves that the fixtures and the checker agree, and both
were written by the same hand in the same sitting. This module imports nothing from
`agentrust_trace` and reuses no helper from the other test modules: it walks the
fixture directories, rebuilds each signing input from the JSON, and verifies with
`cryptography` directly.

That makes one class of failure detectable that a self-consistent suite cannot see: a
shared helper that canonicalizes or decodes wrongly, and fixtures generated through the
same helper, which agree with each other and with nothing else in the world.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXAMPLES = Path(__file__).parent.parent / "examples"


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify(signed: dict[str, Any], jwk: dict[str, str]) -> None:
    """Verify `signed["signature"]` over the JCS bytes of everything else."""
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"
    key = Ed25519PublicKey.from_public_bytes(_b64url(jwk["x"]))
    body = rfc8785.dumps({k: v for k, v in signed.items() if k != "signature"})
    key.verify(_b64url(signed["signature"]), body)


# (path, expectation) — "valid" or the reason it is deliberately not verifiable.
GAP_DIR = EXAMPLES / "action-receipts" / "conformance"
COMPAT_DIR = EXAMPLES / "verifier-compatibility"

GAP_FIXTURES = sorted(GAP_DIR.glob("1*.json"))
COMPAT_FIXTURES = sorted(COMPAT_DIR.glob("*.json"))


@pytest.mark.parametrize("path", GAP_FIXTURES, ids=lambda p: p.stem)
def test_gap_disclosure_signature_independently(path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    disclosure = fixture.get("gap_disclosure")
    if disclosure is None:
        pytest.skip("fixture carries no gap disclosure")

    jwk = fixture["trusted_issuer_keys"].get(disclosure["issuer_key_id"])
    expected = fixture["expected"]
    deliberately_bad = {"disclosure_signature_invalid", "disclosure_key_untrusted"}
    is_negative = bool(deliberately_bad & set(expected.get("failures", [])))

    if jwk is None:
        assert is_negative, (
            f"{path.name}: issuer key is not pinned, but the fixture does not expect a "
            "key or signature failure"
        )
        return

    try:
        _verify(disclosure, jwk)
    except InvalidSignature:
        assert is_negative, (
            f"{path.name}: signature does not verify through an independent path, and "
            "the fixture does not expect a signature failure"
        )
        return

    assert not is_negative, (
        f"{path.name}: the fixture expects a signature or key failure, but the "
        "signature verifies. The vector is not testing what it names."
    )


@pytest.mark.parametrize("path", COMPAT_FIXTURES, ids=lambda p: p.stem)
def test_verifier_compatibility_signature_independently(path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    # Every record in this set is signed correctly by design: these vectors test
    # profile handling, so a bad signature would let one pass for the wrong reason.
    _verify(fixture["record"], fixture["trusted_key"])


def test_both_fixture_sets_were_found() -> None:
    """Guard against the globs silently matching nothing after a directory move."""
    assert len(GAP_FIXTURES) == 8, f"expected 8 gap fixtures, found {len(GAP_FIXTURES)}"
    assert len(COMPAT_FIXTURES) == 7, (
        f"expected 7 compatibility fixtures, found {len(COMPAT_FIXTURES)}"
    )
