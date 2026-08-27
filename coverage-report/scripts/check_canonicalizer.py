"""Close section 6.4(a): re-derive every fixture signature without `rfc8785`, and
differentially test the two canonicalizers against each other.

Two checks, and they answer different questions.

**Differential.** For every JSON value in the corpus, does `jcs_minimal.dumps` produce the
same bytes as `rfc8785.dumps`? A disagreement is a canonicalization defect in one of them,
and the audited suite cannot see it because both of its paths call the same one.

**Signatures through the naive path.** Does each signature verify when the signing input is
rebuilt with `jcs_minimal` instead? This is the check the suite believes it is already
doing. If the differential above is clean the two are equivalent, but they are not the
same statement: the differential covers the whole corpus, while this covers exactly the
bytes that were signed.

Run: python check_canonicalizer.py [path-to-trace-spec]
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import jcs_minimal

TRACE_SPEC = Path(
    sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_SPEC", os.path.expanduser("~/trace-spec"))
)
EXAMPLES = TRACE_SPEC / "examples"

if not EXAMPLES.is_dir():
    sys.exit(
        f"corpus not found: {EXAMPLES}\n"
        "Pass the trace-spec checkout as argv[1] or set TRACE_SPEC. Exiting non-zero "
        "rather than comparing nothing: a differential check that reports success over "
        "an empty corpus is the failure mode this script exists to catch."
    )


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _every_value(node: Any):
    """Every dict and list in the corpus, not only the signed bodies.

    Canonicalization defects live in the shape of the data: key ordering, escaping,
    nesting, so the widest input set is the useful one.
    """
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _every_value(value)
    elif isinstance(node, list):
        for value in node:
            yield from _every_value(value)


def differential() -> tuple[int, list[str]]:
    """Compare the two canonicalizers on every value in every fixture."""
    compared = 0
    disagreements: list[str] = []
    for path in sorted(EXAMPLES.rglob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        for value in _every_value(document):
            if not isinstance(value, (dict, list)):
                continue
            try:
                naive = jcs_minimal.dumps(value)
            except jcs_minimal.NotCanonicalizable as exc:
                disagreements.append(f"{path.name}: refused by jcs_minimal: {exc}")
                continue
            reference = rfc8785.dumps(value)
            compared += 1
            if naive != reference:
                disagreements.append(
                    f"{path.name}: canonicalizers disagree\n"
                    f"    jcs_minimal: {naive[:200]!r}\n"
                    f"    rfc8785:     {reference[:200]!r}"
                )
    return compared, disagreements


def _verify_naive(signed: dict[str, Any], jwk: dict[str, str]) -> None:
    """Verify a signature with the signing input rebuilt by the naive canonicalizer."""
    if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
        raise AssertionError(f"unexpected key type {jwk!r}")
    key = Ed25519PublicKey.from_public_bytes(_b64url(jwk["x"]))
    body = jcs_minimal.dumps({k: v for k, v in signed.items() if k != "signature"})
    key.verify(_b64url(signed["signature"]), body)


def _reconcile_against_the_registry(codes: set[str]) -> set[str]:
    """Refuse to run if any code here is one the verifier does not register.

    A name in this set that nothing emits does not fail loudly on its own: the check
    simply never matches it, the negative class it stands for stops being recognised,
    and the vectors carrying it are reported as problems. That is what happened, and it
    survived a rename because nothing tied the two together.

    The verifier's `RULES` registry is that tie. If it cannot be imported the set is
    returned unchecked, since this script is also run against trees that predate the
    registry, and a reconciliation that cannot run is not a reason to refuse the rest.
    """
    sys.path.insert(0, str(TRACE_SPEC / "tests"))
    try:
        import test_action_receipt_fixtures as verifier
    except Exception:
        return codes
    registered = {rule.code for rule in getattr(verifier, "RULES", ())}
    if not registered:
        return codes
    unknown = sorted(codes - registered)
    if unknown:
        raise SystemExit(
            f"check_canonicalizer: {len(unknown)} code(s) in `deliberately_bad` are not "
            f"registered by the verifier: {unknown}. The negative classes they name are "
            "invisible until the names match, and the vectors carrying them are reported "
            "as defects. Update the set."
        )
    return codes


def _signed_bodies(document: dict[str, Any]) -> list[tuple[str, dict, dict]]:
    """Return (label, signed_object, trusted_key_map) for each signature in a fixture."""
    found = []
    keys = document.get("trusted_issuer_keys", {})
    for field in ("receipt", "gap_disclosure"):
        obj = document.get(field)
        if isinstance(obj, dict) and "signature" in obj:
            found.append((field, obj, keys))
    record = document.get("record")
    if isinstance(record, dict) and "signature" in record:
        found.append(("record", record, {"__single__": document.get("trusted_key", {})}))
    return found


def signatures() -> tuple[int, int, list[str]]:
    """Re-verify every signature through the naive path.

    A vector that expects a signature or key failure must fail to verify, and one that
    expects anything else must verify. Checking a biconditional rather than a signature is
    what makes the negative cases meaningful: a vector expecting `receipt_stale` whose
    signature does not verify is not a passing negative case, it is a vector that has
    stopped testing what it names.
    """
    verified = 0
    negatives = 0
    problems: list[str] = []
    # Codes that mean the signing key is deliberately not resolvable, or the signature
    # deliberately wrong. Two of these read `issuer_key_untrusted` and
    # `disclosure_key_untrusted` until this change, and nothing has emitted those names
    # since they were renamed to `_unknown`: zero occurrences under `src/`, `tests/`,
    # `examples/` and `schema/`. For as long as that stood, the two classes they name were
    # invisible to the check below, and the four vectors that carry them were reported as
    # defects rather than recognised as the negative cases they are.
    deliberately_bad = _reconcile_against_the_registry({
        "signature_or_key_mismatch",
        "issuer_key_unknown",
        "disclosure_signature_invalid",
        "disclosure_key_unknown",
    })

    for path in sorted(EXAMPLES.rglob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        expected = document.get("expected", {})
        # Both lists. Two of the four codes are registered `warning` rather than `failure`,
        # and which severity the verifier assigns is orthogonal to why this check cares:
        # the question here is whether the vector meant the key to be unresolvable, not
        # what the verdict does about it. Membership of the set above is what keeps this
        # narrow; reading only `failures` is what made it wrong.
        declared = set(expected.get("failures", [])) | set(expected.get("warnings", []))
        is_negative = bool(deliberately_bad & declared)

        for label, signed, keymap in _signed_bodies(document):
            jwk = (
                keymap.get("__single__")
                if "__single__" in keymap
                else keymap.get(signed.get("issuer_key_id"))
            )
            if not jwk:
                if not is_negative:
                    problems.append(
                        f"{path.name} [{label}]: signing key is not pinned, but no key or "
                        "signature failure is expected"
                    )
                else:
                    negatives += 1
                continue
            try:
                _verify_naive(signed, jwk)
            except InvalidSignature:
                if not is_negative:
                    problems.append(
                        f"{path.name} [{label}]: signature does not verify through the "
                        "naive canonicalizer, and no signature failure is expected"
                    )
                else:
                    negatives += 1
                continue
            if is_negative:
                problems.append(
                    f"{path.name} [{label}]: a signature or key failure is expected, but "
                    "the signature verifies. The vector is not testing what it names."
                )
            else:
                verified += 1
    return verified, negatives, problems


def main() -> int:
    print(f"corpus: {EXAMPLES}")
    print()

    compared, disagreements = differential()
    print(f"[differential] compared {compared} JSON values through both canonicalizers")
    if disagreements:
        print(f"[differential] {len(disagreements)} DISAGREEMENT(S):")
        for line in disagreements:
            print("  " + line)
    else:
        print("[differential] byte-identical on every value")
    print()

    verified, negatives, problems = signatures()
    print(
        f"[signatures] {verified} verified through the naive path, "
        f"{negatives} correctly refused (negative vectors)"
    )
    if problems:
        print(f"[signatures] {len(problems)} PROBLEM(S):")
        for line in problems:
            print("  " + line)
    else:
        print("[signatures] every signature behaves as its vector declares")

    return 1 if (disagreements or problems) else 0


if __name__ == "__main__":
    raise SystemExit(main())
