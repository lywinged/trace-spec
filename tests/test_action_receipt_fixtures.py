"""Conformance checks for the informative action-receipt fixture set."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "action-receipts" / "conformance"
ACTION_REF_FIELDS = ("agent_id", "action_type", "action_scope", "action_timestamp")


@dataclass(frozen=True)
class ReceiptResult:
    status: str
    controller_outcome: str
    failures: list[str]
    warnings: list[str]
    consecutive_disclosures: int = 1
    """Run length of back-to-back disclosures with no receipt between them.

    One disclosed gap is an incident; nine in a row is a different claim about the
    deployment, and collapsing them loses the part a relying party acts on."""


def _load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_jcs(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _decode_base64url(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise ValueError("fixture value is not valid base64url") from exc


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verify_signature(receipt: dict[str, Any], trusted_jwk: dict[str, str]) -> None:
    if trusted_jwk.get("kty") != "OKP" or trusted_jwk.get("crv") != "Ed25519":
        raise ValueError("fixture key must be an Ed25519 OKP JWK")
    public_key = Ed25519PublicKey.from_public_bytes(_decode_base64url(trusted_jwk["x"]))
    signing_input = {key: value for key, value in receipt.items() if key != "signature"}
    public_key.verify(_decode_base64url(receipt["signature"]), rfc8785.dumps(signing_input))


def _verify_gap_disclosure(
    fixture: dict[str, Any], disclosure: dict[str, Any]
) -> ReceiptResult:
    """Evaluate a GapDisclosure covering receipts that were never emitted.

    A disclosed gap is distinct from ``receipt_chain_gap``: the latter is a present
    receipt whose predecessor hash does not match, while a disclosure accounts for
    receipts that do not exist.
    """
    chain = fixture["context"]["chain"]
    failures: list[str] = []

    trusted_jwk = fixture["trusted_issuer_keys"].get(disclosure["issuer_key_id"])
    if trusted_jwk is None:
        failures.append("disclosure_key_untrusted")
    else:
        try:
            _verify_signature(disclosure, trusted_jwk)
        except (InvalidSignature, ValueError):
            failures.append("disclosure_signature_invalid")

    # Issuer binding is read off the chain, not supplied out of band: the disclosure
    # must be signed by whoever signed the element it links back to, or an ancestor.
    # That element is present by construction, so its key is knowable.
    permitted = {chain["predecessor_issuer_key_id"], *chain["permitted_ancestor_key_ids"]}
    if disclosure["issuer_key_id"] not in permitted:
        failures.append("disclosure_issuer_not_chain_key")

    # Sealed from both directions, or not sealed. The disclosure links back to a
    # present element, and the next element links back to the disclosure. A
    # disclosure attached at one end can be minted later and slid over any gap.
    if disclosure["previous_receipt_hash"] != chain["predecessor_hash"] or not chain[
        "predecessor_present"
    ]:
        failures.append("disclosure_predecessor_absent")
    if (
        chain["successor_present"]
        and chain["successor_previous_receipt_hash"] != _sha256_jcs(disclosure)
    ):
        failures.append("disclosure_not_sealed_by_successor")

    if chain["claimed_absent_but_present"]:
        failures.append("disclosure_contradicted")

    # receipts_lost_estimate is deliberately not checked. The receipts it counts are
    # absent by definition, so nothing here corroborates it, and its type is the
    # schema's business rather than the verifier's. An earlier revision validated it;
    # the completeness suite then reported the rule as load-bearing for no vector, and
    # the attempt to justify it failed. Left as evidence that the rule was considered.

    if failures:
        return ReceiptResult(
            status="receipt_invalid",
            controller_outcome="unknown",
            failures=failures,
            warnings=[],
        )

    # Coverage is structural under the splice model: the chain is linear and unbroken,
    # so there is nowhere else the missing receipts could have been. Nothing to compare.
    return ReceiptResult(
        status="receipt_gap_disclosed",
        controller_outcome="unknown",
        failures=[],
        warnings=["receipt_gap_disclosed"],
        consecutive_disclosures=chain["consecutive_disclosures"],
    )


def _verify_fixture(fixture: dict[str, Any]) -> ReceiptResult:
    context = fixture["context"]
    action = fixture["action"]
    receipt = fixture.get("receipt")

    if receipt is None:
        if not context["require_receipt"]:
            raise AssertionError("the conformance set has no optional missing-receipt case")
        disclosure = fixture.get("gap_disclosure")
        if disclosure is not None:
            return _verify_gap_disclosure(fixture, disclosure)
        return ReceiptResult(
            status="receipt_missing_required",
            controller_outcome="unknown",
            failures=["receipt_missing"],
            warnings=[],
        )

    failures: list[str] = []
    warnings: list[str] = []

    action_preimage = {field: action[field] for field in ACTION_REF_FIELDS}
    expected_action_ref = _sha256_jcs(action_preimage)
    if action["action_ref"] != expected_action_ref:
        failures.append("action_ref_invalid")
    if receipt["action_ref"] != action["action_ref"]:
        failures.append("action_ref_mismatch")

    if receipt["linked_call_id"] != context["call_id"]:
        failures.append("call_id_mismatch")
    if receipt["session_id"] != context["session_id"]:
        failures.append("session_id_mismatch")

    evidence = fixture["evidence"]
    if receipt["evidence_hash"] != _sha256_jcs(evidence):
        failures.append("evidence_hash_mismatch")

    trusted_jwk = fixture["trusted_issuer_keys"].get(receipt["issuer_key_id"])
    if trusted_jwk is None:
        failures.append("issuer_key_untrusted")
    else:
        try:
            _verify_signature(receipt, trusted_jwk)
        except (InvalidSignature, ValueError):
            failures.append("signature_or_key_mismatch")

    receipt_age = _parse_timestamp(context["verification_time"]) - _parse_timestamp(
        receipt["issued_at"]
    )
    if receipt_age.total_seconds() > context["max_receipt_age_seconds"]:
        failures.append("receipt_stale")
    if receipt_age.total_seconds() < 0:
        failures.append("receipt_from_future")

    if receipt["previous_receipt_hash"] != context["expected_previous_receipt_hash"]:
        failures.append("receipt_chain_gap")

    if evidence["physical_completion_claim"] != "none":
        failures.append("unsupported_physical_completion_claim")

    if receipt["issuer_independence"] == "gateway_self_report":
        warnings.append("issuer_not_independent")

    decision = receipt["decision"]
    if decision not in {"accepted", "rejected"}:
        failures.append("decision_invalid")

    if failures:
        return ReceiptResult(
            status="receipt_invalid",
            controller_outcome="unknown",
            failures=failures,
            warnings=warnings,
        )

    status = "receipt_valid_accepted" if decision == "accepted" else "receipt_valid_rejected"
    return ReceiptResult(
        status=status,
        controller_outcome=evidence["terminal_state"],
        failures=[],
        warnings=warnings,
    )


FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))


def test_fixture_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-valid-controller-accepted.json",
        "02-valid-controller-rejected.json",
        "03-missing-required-receipt.json",
        "04-signature-key-mismatch.json",
        "05-action-ref-mismatch.json",
        "06-stale-receipt.json",
        "07-receipt-chain-gap.json",
        "08-same-party-self-report.json",
        "09-unsupported-physical-completion.json",
        "10-gap-disclosed-valid.json",
        "11-gap-disclosure-dangling-predecessor.json",
        "12-gap-disclosure-successor-does-not-link.json",
        "13-gap-disclosure-contradicted.json",
        "14-gap-disclosure-foreign-key.json",
        "15-gap-disclosed-parent-key-null-estimate.json",
        "16-gap-disclosure-untrusted-key.json",
        "17-gap-disclosure-tampered.json",
        # 18-24 close the receipt rules that had no vector at all. Each was a check a
        # conforming implementation could have omitted entirely while passing this
        # suite; `test_vector_completeness.py` is what found them.
        "18-action-ref-not-recomputable.json",
        "19-call-id-mismatch.json",
        "20-session-id-mismatch.json",
        "21-evidence-hash-mismatch.json",
        "22-receipt-issuer-key-untrusted.json",
        "23-receipt-from-future.json",
        "24-decision-not-in-enum.json",
    ]


@pytest.mark.parametrize("fixture_path", FIXTURE_PATHS, ids=lambda path: path.stem)
def test_action_receipt_conformance_fixture(fixture_path: Path) -> None:
    fixture = _load_fixture(fixture_path)
    assert fixture["profile"] == "trace.action_receipt.conformance.v0"
    result = _verify_fixture(fixture)

    assert result.status == fixture["expected"]["status"]
    assert result.controller_outcome == fixture["expected"]["controller_outcome"]
    assert result.failures == fixture["expected"]["failures"]
    assert result.warnings == fixture["expected"]["warnings"]
    if "consecutive_disclosures" in fixture["expected"]:
        assert result.consecutive_disclosures == fixture["expected"]["consecutive_disclosures"]
