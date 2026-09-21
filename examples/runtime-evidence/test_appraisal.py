"""Execute the draft rules with the external verifier and genuine captured quotes.

Run explicitly in the runtime-evidence CI job; the ordinary TRACE test suite does
not depend on agent-manifest. Missing verifier code or captures fail this job instead
of silently skipping the evidence checks. No hardware verification is mocked.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import generate as rules

VECTOR_DIR = Path(__file__).resolve().parent / "vectors"
VECTORS = sorted(VECTOR_DIR.glob("*.json"))
REJECTION_REASONS = {
    "reject-collateral-required": "collateral 'required' disagrees with tdx-quote-v4",
    "reject-forged-quote": "evidence signature or PCK chain did not verify",
    "reject-measurement-mismatch": "runtime.measurement .* is not the MRTD",
    "reject-evidence-swapped-after-signing": "record envelope failed: InvalidSignature",
    "reject-platform-not-the-evidence": "platform 'amd-sev-snp' is not what this evidence roots",
}


def _record(name: str) -> dict:
    return json.loads((VECTOR_DIR / f"{name}.json").read_text(encoding="utf-8"))["record"]


@pytest.mark.parametrize("path", VECTORS, ids=lambda path: path.stem)
def test_appraisal_matches_committed_expectation(path: Path) -> None:
    vector = json.loads(path.read_text(encoding="utf-8"))
    record, expected = vector["record"], vector["expected"]
    if expected["grade"] == "reject":
        with pytest.raises(rules.Reject, match=REJECTION_REASONS[path.stem]):
            rules.appraise(record)
        return
    grade = rules.appraise(record)
    assert grade == expected["grade"]
    assert rules.grade_model_claim(record, grade) == expected["model_claim"]


@pytest.mark.parametrize(
    "name", ["downgrade-evidence-by-reference", "downgrade-unsupported-format"]
)
def test_collateral_does_not_override_unverified_evidence(name: str) -> None:
    record = _record(name)
    record["runtime"]["evidence"]["collateral"] = "required"
    key = Ed25519PrivateKey.from_private_bytes(rules.PUBLISHED_TEST_KEY)
    record = rules.sign_record(rules._unsigned(record), key)
    assert rules.appraise(record) == "unattested"


def test_matching_commitment_uses_the_unchanged_genuine_quote() -> None:
    accept = _record("accept-real-quote-platform-attested")
    record = _record("commitment-cannot-attest-model")
    quote = record["runtime"]["evidence"]["quote"]
    assert quote == accept["runtime"]["evidence"]["quote"]
    assert record["model"]["weights_digest"] == (
        "sha256:" + rules.parse_tdx_quote(rules.unb64u(quote)).report_data[:32].hex()
    )
    grade = rules.appraise(record)
    assert grade == "platform-attested"
    assert rules.grade_model_claim(record, grade) == "model claim: self-reported"


@pytest.mark.parametrize("grade", ["unattested", "platform-attested", "attested"])
def test_model_claim_does_not_inherit_the_record_grade(grade: str) -> None:
    # This checks the claim-grading policy with a supplied record grade. It does not
    # claim a captured quote reaches `attested`; no capture here binds the cnf key.
    record = _record("commitment-cannot-attest-model")
    assert rules.grade_model_claim(record, grade) == "model claim: self-reported"
    absent = copy.deepcopy(record)
    del absent["model"]["weights_digest"]
    assert rules.grade_model_claim(absent, grade) == "model claim: absent"


def test_regeneration_matches_committed_vectors(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(Path(rules.__file__)), "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    generated = sorted(tmp_path.glob("*.json"))
    assert {path.name for path in generated} == {path.name for path in VECTORS}
    for path in generated:
        assert path.read_bytes() == (VECTOR_DIR / path.name).read_bytes(), path.name


def _jwk_identity(jwk: dict) -> tuple[object, object, object]:
    return (jwk.get("kty"), jwk.get("crv"), jwk.get("x"))


def test_embedded_signer_is_not_established_by_external_context() -> None:
    vector = json.loads(
        (VECTOR_DIR / "context-embedded-key-not-trusted.json").read_text(encoding="utf-8")
    )
    record = vector["record"]
    rules.check_envelope(record)
    assert rules.appraise(record) == "platform-attested"

    external_keys = vector["context"]["trusted_root_keys"]
    assert external_keys, "the trust context must be non-empty or this case is vacuous"

    embedded = _jwk_identity(record["cnf"]["jwk"])
    configured = {_jwk_identity(jwk) for jwk in external_keys}
    assert embedded not in configured

    # The distinction is cryptographic, not just metadata: the record verifies under
    # its embedded key, while the relying party's configured trusted key does not
    # authenticate this signature.
    signature = rules.unb64u(record["signature"])
    body = rules._canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    for trusted_jwk in external_keys:
        with pytest.raises(InvalidSignature):
            rules._pubkey_from_jwk(trusted_jwk).verify(signature, body)

    assert vector["expected"]["signer_trust"] == "not-established"


# ---------------------------------------------------------------------------
# The document and the pre-image it names
# ---------------------------------------------------------------------------

RFC = (Path(__file__).resolve().parents[2] / "docs/rfcs/runtime-evidence-profile.md").read_text(
    encoding="utf-8"
)


def test_the_rfc_names_the_pre_image_the_grader_actually_hashes() -> None:
    """Section 7.2 is the only place in the RFC that gives a construction for the binding.

    Section 5.2 settles what to bind and stops, and rule 6 says the guest-controlled
    field is compared against the record's `cnf` key. So this one sentence is what a
    second implementation copies, and its two readings are not interchangeable:
    `cnf.jwk.x` is a base64url string, and the grader hashes the key bytes that
    string encodes. An implementation that hashes the member's value instead
    produces a record whose quote verifies, whose signature verifies, and whose
    binding check says no, which is the hardest kind of disagreement to find across
    two repositories.

    This pins the sentence to `generate.py`'s own helper rather than to a copy of it.
    It does not exercise rule 6 end to end: that needs a quote whose REPORT_DATA
    commits to a key under test, and minting one needs the hardware. What it
    establishes is that the grader decodes before it hashes, and that the document
    names the reading the grader takes.
    """
    raw = bytes(range(32))
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    # The load-bearing half: the grader's own helper decodes, so the digest it takes
    # is over the key rather than over its encoding. This fails if unb64u changes.
    assert rules.unb64u(x) == raw
    from_bytes = hashlib.sha256(rules.unb64u(x)).digest()
    assert from_bytes == hashlib.sha256(raw).digest()

    # A statement about SHA-256 rather than about this repository, kept because it is
    # the reason the sentence has to be exact. It cannot fail without a collision.
    assert from_bytes != hashlib.sha256(x.encode()).digest()

    assert "`base64url-decode(cnf.jwk.x)`" in RFC, (
        "section 7.2 no longer names the decode, so the only construction the RFC "
        "gives is the reading that does not verify"
    )
    assert "`sha256(cnf.jwk.x)`" not in RFC, (
        "section 7.2 states the digest over the member's value; the grader hashes "
        "the key bytes it encodes, see the key-binding rule in generate.py"
    )
