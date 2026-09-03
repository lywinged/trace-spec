"""Re-verify every fixture signature through a path that shares no code with them.

**Second correction.** This module said it walked the fixture directories and walked two
of them, `action-receipts/conformance/` and `verifier-compatibility/`. Fifty-seven of the
eighty-five signed fixtures under `examples/` were covered; twenty-eight were not, among
them the whole twenty-three-fixture `delegation-link/` set and the four
`canonicalization-boundary/` records. Those were verified elsewhere but not independently:
`test_delegation_vectors.py` imports nothing from `agentrust_trace` and canonicalizes with
`rfc8785`, which is the exact half-independence the correction below already describes, and
`test_canonicalization_boundary.py` calls `verify_record` and `rfc8785` both.

`test_every_fixture_is_covered_by_some_independent_check` could not see it, because its
universe was `ALL_RECEIPT_FIXTURES` rather than the fixture tree. A coverage test whose
universe is a hardcoded subset reports full coverage of the subset and says nothing about
the rest. The universe is discovered now.

A green conformance run only proves that the fixtures and the checker agree, and both
were written by the same hand in the same sitting. This module walks the fixture
directories, rebuilds each signing input from the JSON, and verifies with `cryptography`
directly, importing nothing from `agentrust_trace` and reusing no helper from the other
test modules.

**Correction.** An earlier revision claimed independence while calling `rfc8785`: the
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
DELEGATION_DIR = EXAMPLES / "delegation-link"
CANONICAL_DIR = EXAMPLES / "canonicalization-boundary"

GAP_DIR = EXAMPLES / "action-receipts" / "gap-disclosure"
BUNDLE_DIR = EXAMPLES / "revocation-bundle"

# The section 3.3.4 gap-disclosure vectors (#117) carry the same `gap_disclosure` and
# `trusted_issuer_keys` shape as the conformance set, so the same selector and the
# same independent check apply to them.
ALL_RECEIPT_FIXTURES = sorted(RECEIPT_DIR.rglob("*.json")) + sorted(GAP_DIR.glob("*.json"))
BUNDLE_FIXTURES = sorted(BUNDLE_DIR.glob("*.json"))
COMPAT_FIXTURES = sorted(COMPAT_DIR.glob("*.json"))
DELEGATION_FIXTURES = sorted(DELEGATION_DIR.glob("*.json"))
CANONICAL_FIXTURES = sorted(CANONICAL_DIR.glob("*.json"))


def _carries_a_signature(node: Any) -> bool:
    """A fixture is in scope if a signature appears anywhere inside it.

    By shape, not by path, for the same reason `_has` selects by shape: a directory
    list is a claim about the tree that stops being true when someone adds to it.
    """
    if isinstance(node, dict):
        if isinstance(node.get("signature"), str) and node["signature"]:
            return True
        return any(_carries_a_signature(value) for value in node.values())
    if isinstance(node, list):
        return any(_carries_a_signature(item) for item in node)
    return False


def _every_signed_fixture(root: Path = EXAMPLES) -> set[Path]:
    found = set()
    for path in root.rglob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if _carries_a_signature(payload):
            found.add(path)
    return found


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
# Files under examples/ that carry a `signature` string but are not fixtures with a
# record to re-verify. Declared rather than skipped by a path rule, so that adding one
# is a decision somebody made and not a selector quietly widening.
NOT_A_FIXTURE = {
    "action-receipts/acta/expected.json": (
        "an expectations file for the ACTA chain, not a record: it carries the signer "
        "key and the results table, and its `chain` entries are verified by the ACTA "
        "conformance tests against that key"
    ),
}

SIGNATURE_FREE = {
    "03-missing-required-receipt.json": (
        "the absence of a receipt is the case under test, so there is no signature"
    ),
    "17-missing-receipt-explicit-null.json": (
        "the receipt is an explicit null: the same absence through a different "
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
    except (InvalidSignature, ValueError):
        # A structurally malformed signature (fixture 10, 32 bytes) is the same
        # obligation as a cryptographic mismatch: it does not verify.
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


@pytest.mark.parametrize("path", DELEGATION_FIXTURES, ids=lambda p: p.stem)
def test_delegation_hop_signatures_independently(path: Path) -> None:
    """Every hop in every chain, verified without `rfc8785` and without the SDK.

    `test_delegation_vectors.py` already verifies these, and imports nothing from
    `agentrust_trace`, which is half of what independence means here. It canonicalizes
    with `rfc8785`, the library the generators use, so a defect there would have been
    invisible on both sides for the whole set.

    The two vectors that name a bad signature must fail here, and nothing else may.
    A negative vector whose signature actually verifies is not testing what it names.
    """
    fixture = json.loads(path.read_text(encoding="utf-8"))
    records = fixture["records"]
    assert records, f"{path.name}: no records to verify"

    expects_a_bad_signature = "record_signature_invalid" in fixture["expected"].get("codes", [])
    failed = []
    for index, record in enumerate(records):
        try:
            _verify(record, record["cnf"]["jwk"])
        except InvalidSignature:
            failed.append(index)

    if expects_a_bad_signature:
        assert failed, (
            f"{path.name} expects record_signature_invalid, but every hop verifies "
            "through an independent path. The vector is not testing what it names."
        )
    else:
        assert not failed, (
            f"{path.name}: hop(s) {failed} do not verify through an independent path, "
            "and the vector expects no signature failure"
        )


@pytest.mark.parametrize("path", CANONICAL_FIXTURES, ids=lambda p: p.stem)
def test_canonicalization_boundary_signatures_independently(path: Path) -> None:
    """These exist because two serializers can disagree, so verifying them with the
    one under test is the one arrangement that cannot detect the disagreement.

    `test_canonicalization_boundary.py` calls `verify_record` and `rfc8785`. Every
    record here is correctly signed by design: the vectors separate JCS from an ad-hoc
    serializer, so a bad signature would let one pass for the wrong reason.
    """
    fixture = json.loads(path.read_text(encoding="utf-8"))
    record = fixture.get("record", fixture)

    _verify(record, record["cnf"]["jwk"])


def _thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 thumbprint through the independent canonicalizer."""
    import hashlib
    digest = hashlib.sha256(
        jcs_minimal.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@pytest.mark.parametrize("path", BUNDLE_FIXTURES, ids=lambda p: p.stem)
def test_revocation_bundle_signatures_independently(path: Path) -> None:
    """Section 3.2.3 vectors: every record against the trusted key, and the bundle's
    own signature against the bundle key the caller trusts, both through the
    independent canonicalizer. What the fixture expects decides which outcome a
    non-verifying signature is allowed to have."""
    fixture = json.loads(path.read_text(encoding="utf-8"))
    context = fixture["context"]
    for record in fixture["records"]:
        _verify(record, context["trusted_key"])

    bundle = context.get("bundle")
    codes = set(fixture["expected"].get("codes", []))
    if bundle is None:
        assert "no_check_performed" in codes, (
            f"{path.name}: no bundle in the fixture, but it does not expect "
            "no_check_performed"
        )
        return
    sig = bundle.get("sig")
    if not isinstance(sig, dict) or sig.get("alg") != "ed25519":
        assert codes & {"bundle_signature_unsupported", "bundle_malformed"}, (
            f"{path.name}: bundle signature is not an Ed25519 one this check can "
            "re-derive, and the fixture does not say so"
        )
        return
    trusted = [
        jwk for jwk in context.get("trusted_bundle_keys", [])
        if bundle.get("bundle_key_id") in (jwk.get("kid"), _thumbprint(jwk))
    ]
    if not trusted:
        assert "bundle_key_untrusted" in codes, (
            f"{path.name}: bundle key is not among trusted_bundle_keys, and the "
            "fixture does not expect bundle_key_untrusted"
        )
        return
    unsigned = {k: v for k, v in bundle.items() if k != "sig"}
    key = Ed25519PublicKey.from_public_bytes(_b64url(trusted[0]["x"]))
    try:
        key.verify(_b64url(sig["value"]), jcs_minimal.dumps(unsigned))
    except (InvalidSignature, ValueError):
        # A bundle the schema refuses (3b in check_bundle) never reaches the signature
        # step, so a vector built by deleting a field after signing expects
        # bundle_malformed, not a signature code.
        assert codes & {"bundle_signature_invalid", "bundle_malformed"}, (
            f"{path.name}: bundle signature does not verify through an independent "
            "path, and the fixture expects neither bundle_signature_invalid nor "
            "bundle_malformed"
        )
        return
    assert "bundle_signature_invalid" not in codes, (
        f"{path.name}: the fixture expects a bundle signature failure, but the "
        "signature verifies. The vector is not testing what it names."
    )


def test_the_universe_is_discovered_and_not_listed() -> None:
    """The walk has to find more than the directories named above, or the coverage
    test below is checking a set against itself."""
    found = _every_signed_fixture()
    assert len(found) >= 80, f"only {len(found)} signed fixtures found under examples/"
    named = set(ALL_RECEIPT_FIXTURES) | set(COMPAT_FIXTURES)
    assert found - named, "the walk found nothing outside the originally named directories"


def test_the_walk_finds_a_fixture_in_a_directory_nobody_named(tmp_path: Path) -> None:
    """The discovery is the point, and the coverage test alone does not prove it works.

    Reverting the universe to the old hardcoded `ALL_RECEIPT_FIXTURES` leaves the suite
    green, because the selectors above happen to cover everything today, so nothing is
    uncovered either way. The discovered universe earns its place only when a signed
    fixture appears somewhere no selector names, which is the case it exists for and the
    one a mutation of the current tree cannot reach. So it is put there.
    """
    novel = tmp_path / "a-directory-added-next-year"
    novel.mkdir()
    (novel / "some-new-vector.json").write_text(
        json.dumps({"record": {"iat": 1, "signature": "AAAA"}}), encoding="utf-8"
    )
    (novel / "not-signed.json").write_text(json.dumps({"iat": 1}), encoding="utf-8")

    found = _every_signed_fixture(tmp_path)

    assert {p.name for p in found} == {"some-new-vector.json"}, (
        "the walk did not find a signed fixture in an unnamed directory, so the "
        "coverage test's universe is effectively the hardcoded list it replaced"
    )


def test_every_fixture_is_covered_by_some_independent_check() -> None:
    """No fixture may sit in the directory with its signature never re-derived.

    Selection is by shape, so a fixture carrying neither a receipt nor a disclosure
    would otherwise be skipped by both parametrizations without anything noticing.
    """
    covered = (
        set(GAP_FIXTURES) | set(RECEIPT_FIXTURES) | set(COMPAT_FIXTURES)
        | set(DELEGATION_FIXTURES) | set(CANONICAL_FIXTURES) | set(BUNDLE_FIXTURES)
    )
    every = _every_signed_fixture()
    uncovered = sorted(
        p.relative_to(EXAMPLES).as_posix()
        for p in every - covered
        if p.name not in SIGNATURE_FREE
        and p.relative_to(EXAMPLES).as_posix() not in NOT_A_FIXTURE
    )
    assert not uncovered, (
        f"fixtures with no independently verifiable signature: {uncovered}. "
        "If one is signature-free by design, say so explicitly rather than letting "
        "the selectors skip it."
    )
    assert (
        GAP_FIXTURES and RECEIPT_FIXTURES and COMPAT_FIXTURES
        and DELEGATION_FIXTURES and CANONICAL_FIXTURES and BUNDLE_FIXTURES
    ), "a selector matched nothing, so its checks would pass vacuously"
