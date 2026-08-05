"""Regenerate the gap-disclosure fixtures under the splice model.

A disclosure is a chain element, not a description of a range. See
proposals/117-gap-disclosure-design.md. Deterministic keys; public JWKs only.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path("examples/action-receipts/conformance")
PROFILE = "trace.action_receipt.conformance.v0"
SESSION = "trace-session-2026-07-06T15:22:11Z"
ISSUER = "did:web:factory.example:safety-controller"

# The key that signed the element before the gap. Under the splice model this is the
# only key entitled to disclose, together with its ancestors.
KEY_ID = f"{ISSUER}#ed25519-2026q3"
PARENT_KEY_ID = f"{ISSUER}#ed25519-workload-attestation"
FOREIGN_KEY_ID = f"{ISSUER}#ed25519-unrelated-but-trusted"

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PARENT = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
FOREIGN = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"trace-spec#117 unrelated trusted key").digest()
)

PREDECESSOR_HASH = "sha256:" + "a1" * 32


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64u(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
    }


def digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def sign(disclosure: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    body = {k: v for k, v in disclosure.items() if k != "signature"}
    return {**disclosure, "signature": b64u(key.sign(rfc8785.dumps(body)))}


TRUSTED = {KEY_ID: jwk(KEY), PARENT_KEY_ID: jwk(PARENT), FOREIGN_KEY_ID: jwk(FOREIGN)}


def base_disclosure() -> dict[str, Any]:
    return {
        "type": "GapDisclosure/1.0",
        "previous_receipt_hash": PREDECESSOR_HASH,
        "session_id": SESSION,
        "issuer_key_id": KEY_ID,
        "cause": "crash",
        "receipts_lost_estimate": 3,
    }


def base_context(**over: Any) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "session_id": SESSION,
        "require_receipt": True,
        "verification_time": "2026-07-06T15:24:00Z",
        "max_receipt_age_seconds": 300,
        "expected_previous_receipt_hash": PREDECESSOR_HASH,
        "chain": {
            # The element the disclosure links back to, and whether it is in the chain.
            "predecessor_hash": PREDECESSOR_HASH,
            "predecessor_present": True,
            # Who signed it. Issuer binding is derived from this, not supplied.
            "predecessor_issuer_key_id": KEY_ID,
            "permitted_ancestor_key_ids": [PARENT_KEY_ID],
            # What the next emitted element links back to. Filled in per fixture once
            # the disclosure has been signed and its digest is known.
            "successor_previous_receipt_hash": None,
            "successor_present": True,
            # Elements the disclosure implicitly claims are absent but which are in
            # fact present in the chain.
            "claimed_absent_but_present": [],
            "consecutive_disclosures": 1,
        },
    }
    ctx["chain"].update(over)
    return ctx


def fixture(
    name: str,
    description: str,
    disclosure: dict[str, Any],
    expected: dict[str, Any],
    context: dict[str, Any],
    *,
    link_successor: bool = True,
) -> dict[str, Any]:
    if link_successor and context["chain"]["successor_previous_receipt_hash"] is None:
        context["chain"]["successor_previous_receipt_hash"] = digest(disclosure)
    return {
        "name": name,
        "description": description,
        "profile": PROFILE,
        "proposal": {
            "issue": "agentrust-io/trace-spec#117",
            "design": "proposals/117-gap-disclosure-design.md",
            "status": "under review — not accepted normative text",
        },
        "context": context,
        "action": {
            "agent_id": "spiffe://factory.example/agent/ros2-fibonacci/dev",
            "action_type": "ros2.action.example_interfaces/Fibonacci",
            "action_scope": "/abort_fibonacci_process",
            "action_timestamp": "2026-07-06T15:22:13Z",
            "action_ref": "sha256:" + "e3" * 32,
        },
        "trusted_issuer_keys": TRUSTED,
        "gap_disclosure": disclosure,
        "expected": expected,
    }


def ok(consecutive: int = 1) -> dict[str, Any]:
    return {
        "status": "receipt_gap_disclosed",
        "controller_outcome": "unknown",
        "failures": [],
        "warnings": ["receipt_gap_disclosed"],
        "consecutive_disclosures": consecutive,
    }


def bad(*failures: str) -> dict[str, Any]:
    return {
        "status": "receipt_invalid",
        "controller_outcome": "unknown",
        "failures": list(failures),
        "warnings": [],
        "consecutive_disclosures": 1,
    }


def main() -> None:
    out: list[tuple[str, dict[str, Any]]] = []

    out.append(("10-gap-disclosed-valid.json", fixture(
        "gap-disclosed-valid",
        "A disclosure spliced into the chain: it links back to a present element and "
        "the next element links back to it. Coverage is structural, so nothing is "
        "asserted about a range.",
        sign(base_disclosure(), KEY), ok(), base_context())))

    out.append(("11-gap-disclosure-dangling-predecessor.json", fixture(
        "gap-disclosure-dangling-predecessor",
        "The disclosure links back to an element that is not in the chain. Half a "
        "splice is not a splice: it fixes nothing in place.",
        sign(base_disclosure(), KEY),
        bad("disclosure_predecessor_absent"),
        base_context(predecessor_present=False))))

    out.append(("12-gap-disclosure-successor-does-not-link.json", fixture(
        "gap-disclosure-successor-does-not-link",
        "The next element after resumption links past the disclosure to the element "
        "before the gap, leaving the disclosure attached at one end only. A disclosure "
        "no successor names can be minted later and slid over any gap.",
        sign(base_disclosure(), KEY),
        bad("disclosure_not_sealed_by_successor"),
        base_context(successor_previous_receipt_hash=PREDECESSOR_HASH),
        link_successor=False)))

    out.append(("13-gap-disclosure-contradicted.json", fixture(
        "gap-disclosure-contradicted",
        "Elements the disclosure implies are absent are present in the chain. A "
        "self-contradictory disclosure impeaches the emitter rather than excusing it.",
        sign(base_disclosure(), KEY),
        bad("disclosure_contradicted"),
        base_context(claimed_absent_but_present=["sha256:" + "c9" * 32]))))

    out.append(("14-gap-disclosure-foreign-key.json", fixture(
        "gap-disclosure-foreign-key",
        "Signed by a key the verifier trusts, but which is neither the key that signed "
        "the linked element nor an ancestor of it. A gap is where introducing an "
        "unrelated key is most useful and least distinguishable from recovery.",
        sign({**base_disclosure(), "issuer_key_id": FOREIGN_KEY_ID}, FOREIGN),
        bad("disclosure_issuer_not_chain_key"), base_context())))

    out.append(("15-gap-disclosed-parent-key-null-estimate.json", fixture(
        "gap-disclosed-parent-key-null-estimate",
        "Signed by the hierarchical parent, because the crash took the session key "
        "with it, and the count of lost receipts is not bounded. The estimate is an "
        "unverifiable self-report either way; the chain links are what hold.",
        sign({**base_disclosure(), "issuer_key_id": PARENT_KEY_ID,
              "receipts_lost_estimate": None}, PARENT),
        ok(consecutive=3), base_context(consecutive_disclosures=3))))

    out.append(("16-gap-disclosure-untrusted-key.json", fixture(
        "gap-disclosure-untrusted-key",
        "The named key is the one that signed the linked element, but the verifier "
        "does not hold it. Chain position does not confer trust.",
        sign({**base_disclosure(), "issuer_key_id": f"{ISSUER}#ed25519-2027q1"}, KEY),
        bad("disclosure_key_untrusted"),
        # The chain names the same key, so issuer binding is satisfied and only trust
        # fails. Otherwise this fixture would fire two rules and stop isolating one.
        base_context(predecessor_issuer_key_id=f"{ISSUER}#ed25519-2027q1"))))

    tampered = sign(base_disclosure(), KEY)
    tampered["cause"] = "shutdown"  # altered after signing
    out.append(("17-gap-disclosure-tampered.json", fixture(
        "gap-disclosure-tampered",
        "Altered after signing, so the signature no longer covers its contents.",
        tampered, bad("disclosure_signature_invalid"), base_context())))

    for name, doc in out:
        (OUT / name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print("wrote", name)

    stale = OUT / "11-gap-disclosure-range-mismatch.json"
    if stale.exists():
        stale.unlink()
        print("removed 11-gap-disclosure-range-mismatch.json (range coverage is no "
              "longer expressible)")
    stale = OUT / "12-gap-disclosure-unbound.json"
    if stale.exists():
        stale.unlink()
        print("removed 12-gap-disclosure-unbound.json (replaced by the successor-link case)")
    stale = OUT / "15-gap-disclosed-null-estimate.json"
    if stale.exists():
        stale.unlink()
        print("removed 15-gap-disclosed-null-estimate.json (folded into the parent-key case)")


if __name__ == "__main__":
    main()
