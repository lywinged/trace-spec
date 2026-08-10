"""Re-verify every fixture signature through a path that shares no code with them.

A green conformance run only proves that the fixtures and the checker agree, and both
were written by the same hand in the same sitting. This module walks the fixture
directories, rebuilds each signing input from the JSON, and verifies with `cryptography`
directly, importing nothing from `agentrust_trace` and reusing no helper from the other
test modules.

**Correction.** An earlier revision claimed independence while calling `rfc8785` — the
same canonicalizer the fixture generators call. A defect in that library would have been
invisible to both sides, so the one class of failure this module exists to catch was
precisely the one it could not see. The claim was true about the code it did not import
and false about the code it did.

It now canonicalizes through `coverage-report/scripts/jcs_minimal.py`, a second RFC 8785
serializer written from the RFC text with no dependencies. `check_canonicalizer.py`
compares the two over the whole corpus; this module uses only the independent one, so a
divergence surfaces here as a signature failure rather than as silent agreement.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO_ROOT = Path(__file__).parent.parent
EXAMPLES = REPO_ROOT / "examples"

# Deliberately not `rfc8785`: that is what the generators use, and a shared defect
# would be invisible to both sides. See the module docstring.
sys.path.insert(0, str(REPO_ROOT / "coverage-report" / "scripts"))
import jcs_minimal  # noqa: E402


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify(signed: dict[str, Any], jwk: dict[str, str]) -> None:
    """Verify `signed["signature"]` over the JCS bytes of everything else."""
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519"
    key = Ed25519PublicKey.from_public_bytes(_b64url(jwk["x"]))
    body = jcs_minimal.dumps({k: v for k, v in signed.items() if k != "signature"})
    key.verify(_b64url(signed["signature"]), body)


RECEIPT_DIR = EXAMPLES / "action-receipts" / "conformance"
COMPAT_DIR = EXAMPLES / "verifier-compatibility"

ALL_RECEIPT_FIXTURES = sorted(RECEIPT_DIR.rglob("*.json"))
COMPAT_FIXTURES = sorted(COMPAT_DIR.glob("*.json"))


def _has(key: str) -> list[Path]:
    """Select fixtures by what they contain, never by filename.

    A `1*.json` glob selected the gap fixtures until seven receipt fixtures numbered
    18 and 19 appeared and were silently pulled in. Selection by shape cannot drift
    when the set is renumbered.

    Presence means a non-null value: the explicit-null-receipt vector carries the
    `receipt` key precisely so that presence-checking implementations misread it,
    and this selector must not be one of them.
    """
    out = []
    for path in ALL_RECEIPT_FIXTURES:
        if json.loads(path.read_text(encoding="utf-8")).get(key) is not None:
            out.append(path)
    return out


GAP_FIXTURES = _has("gap_disclosure")
RECEIPT_FIXTURES = _has("receipt")

# Fixtures with nothing to verify, each with the reason. An entry is a claim that has
# to survive review; the alternative is a selector that quietly skips a fixture and a
# suite that reports full coverage it does not have.
SIGNATURE_FREE = {
    "03-missing-required-receipt.json": (
        "the absence of a receipt is the case under test, so there is no signature"
    ),
    "17-missing-receipt-explicit-null.json": (
        "the receipt is an explicit null — the same absence through a different "
        "door, and equally without a signature"
    ),
}


@pytest.mark.parametrize("path", GAP_FIXTURES, ids=lambda p: p.stem)
def test_gap_disclosure_signature_independently(path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    disclosure = fixture.get("gap_disclosure")
    if disclosure is None:
        pytest.skip("fixture carries no gap disclosure")

    jwk = fixture["trusted_issuer_keys"].get(disclosure["issuer_key_id"])
    expected = fixture["expected"]
    is_negative = "disclosure_signature_invalid" in expected.get("failures", [])

    if jwk is None:
        # An unpinned key cannot be checked here either. The fixture must say so:
        # unverified with the advisory, not a failure (spec section 3.3.1).
        assert "disclosure_key_unknown" in expected.get("warnings", []), (
            f"{path.name}: issuer key is not pinned, but the fixture does not expect "
            "the disclosure_key_unknown advisory"
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


@pytest.mark.parametrize("path", RECEIPT_FIXTURES, ids=lambda p: p.stem)
def test_receipt_signature_independently(path: Path) -> None:
    """The receipts, not only the gap disclosures, verified through the same path."""
    fixture = json.loads(path.read_text(encoding="utf-8"))
    receipt = fixture["receipt"]
    jwk = fixture["trusted_issuer_keys"].get(receipt["issuer_key_id"])
    is_negative = "signature_or_key_mismatch" in fixture["expected"].get("failures", [])

    if jwk is None:
        # An unpinned key cannot be checked here either. The fixture must say so:
        # unverified with the advisory, not a failure (spec section 3.3.1).
        assert "issuer_key_unknown" in fixture["expected"].get("warnings", []), (
            f"{path.name}: receipt key is not pinned, but the fixture does not expect "
            "the issuer_key_unknown advisory"
        )
        return

    try:
        _verify(receipt, jwk)
    except InvalidSignature:
        assert is_negative, (
            f"{path.name}: receipt signature does not verify through an independent "
            "path, and no signature failure is expected"
        )
        return

    assert not is_negative, (
        f"{path.name}: a signature or key failure is expected, but the receipt "
        "signature verifies. The vector is not testing what it names."
    )


def test_every_fixture_is_covered_by_some_independent_check() -> None:
    """No fixture may sit in the directory with its signature never re-derived.

    Selection is by shape, so a fixture carrying neither a receipt nor a disclosure
    would otherwise be skipped by both parametrizations without anything noticing.
    """
    covered = {p.name for p in GAP_FIXTURES} | {p.name for p in RECEIPT_FIXTURES}
    every = {p.name for p in ALL_RECEIPT_FIXTURES}
    uncovered = sorted(every - covered - set(SIGNATURE_FREE))
    assert not uncovered, (
        f"fixtures with no independently verifiable signature: {uncovered}. "
        "If one is signature-free by design, say so explicitly rather than letting "
        "the selectors skip it."
    )
    assert GAP_FIXTURES and RECEIPT_FIXTURES and COMPAT_FIXTURES, (
        "a selector matched nothing, so its checks would pass vacuously"
    )
