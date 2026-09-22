"""Completeness checks over the webauthn-approval vectors.

`test_webauthn_approval_vectors.py` asks whether the vectors are *correct*. This module
asks whether they are *complete*, by the questions `test_delegation_completeness.py` asks
of the delegation-link corpus and against the same floor: two load-bearing vectors per
rule, and at least one declared implementation defect that tells the two apart (#124).

Mutation targets named rule hooks. A rule is deleted by rebuilding the registry without
its entry, or weakened by substituting its check; source text is never pattern-matched,
so a mutation cannot drift away from the code under test. `DEFECTS` is fail-closed:
registering a rule without declaring what its second vector adds fails this suite.

Every defect below is a near miss, an implementation a competent reviewer could write and
read as correct, and never the original rule reverted. Three are readings that look right and
that the WebAuthn Level 3 text rules out: comparing the challenge as decoded bytes, checking
BS without BE only where the registry recorded eligibility, and reporting a counter only when
it goes down. `test_the_rfc_states_the_figures_this_suite_measures` names their vectors. A
fourth, holding the client data to the members WebAuthn defines, is stricter than the rule it
weakens, so it fails a valid vector and none of the rule's own.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import pytest
import rfc8785

from tests.test_webauthn_approval_vectors import (
    ARTIFACT_SCHEMA,
    BE,
    BS,
    EDDSA,
    ES256,
    OUTCOMES,
    PROFILE,
    RULES,
    UP,
    UV,
    VECTOR_PATHS,
    Rule,
    View,
    _ArtifactValidator,
    _b64u,
    _b64u_decode,
    _jcs_digest,
    _malformed,
    _verifies,
    expected_challenge,
    verify_approval,
)

TESTS_DIR = Path(__file__).parent
VERIFIER_MODULE = TESTS_DIR / "test_webauthn_approval_vectors.py"
MARGINS_FILE = TESTS_DIR / "webauthn_approval_margins.json"

RULE_CODES = tuple(rule.code for rule in RULES)
VECTORS = [json.loads(path.read_text(encoding="utf-8")) for path in VECTOR_PATHS]
NAMES = [path.stem for path in VECTOR_PATHS]


# ---------------------------------------------------------------------------
# Declared defects: one weakened check per rule, minimum
# ---------------------------------------------------------------------------

Check = Callable[[View], bool]


def _without_keywords(schema: Any, keywords: frozenset[str]) -> Any:
    """The profile's schema with every occurrence of `keywords` removed."""
    if isinstance(schema, dict):
        return {
            k: _without_keywords(v, keywords) for k, v in schema.items() if k not in keywords
        }
    if isinstance(schema, list):
        return [_without_keywords(v, keywords) for v in schema]
    return schema


_OPEN_VALIDATOR = _ArtifactValidator(
    _without_keywords(ARTIFACT_SCHEMA, frozenset({"additionalProperties"}))
)
_ANY_NONCE_SCHEMA = json.loads(json.dumps(ARTIFACT_SCHEMA))
_ANY_NONCE_SCHEMA["properties"]["approval"]["properties"]["nonce"]["pattern"] = "^[A-Za-z0-9_-]+$"
_ANY_NONCE_VALIDATOR = _ArtifactValidator(_ANY_NONCE_SCHEMA)
_UNBOUNDED_VALIDATOR = _ArtifactValidator(
    _without_keywords(ARTIFACT_SCHEMA, frozenset({"minimum", "maximum"}))
)


def _profile_family_only(view: View) -> bool:
    """Accept any version of the profile: match the identifier up to its version suffix."""
    family = PROFILE.rsplit("-", 1)[0]
    return not str(view.artifact.get("profile", "")).startswith(family)


def _open_objects(view: View) -> bool:
    """Validate every member the profile defines and ignore the rest."""
    return _malformed(view, _OPEN_VALIDATOR)


def _integer_range_unchecked(view: View) -> bool:
    """Check that the times are integers and not that they fit the canonical range."""
    return _malformed(view, _UNBOUNDED_VALIDATOR)


def _nonce_length_unchecked(view: View) -> bool:
    """Check that the nonce is base64url and not that it is long enough to matter."""
    return _malformed(view, _ANY_NONCE_VALIDATOR)


def _window_order_unchecked(view: View) -> bool:
    """Check each time on its own and leave their order to the window rule, whose tolerance
    admits an inverted window whose ends lie within it."""
    return _malformed(view, ordered=False)


_CLIENT_DATA_MEMBERS = frozenset(
    {"type", "challenge", "origin", "crossOrigin", "topOrigin", "tokenBinding"}
)


def _client_data_closed(view: View) -> bool:
    """Hold the client data to the members WebAuthn defines, as the artifact's own objects
    are held to theirs. WebAuthn requires the opposite of its parsers."""
    return _malformed(view) or bool(set(view.client_data) - _CLIENT_DATA_MEMBERS)


def _profile_prefix_match(view: View) -> bool:
    """Accept any identifier that begins with this verifier's own."""
    return not str(view.artifact.get("profile", "")).startswith(PROFILE)


def _case_insensitive_lookup(view: View) -> bool:
    """'Be liberal in what you accept', applied to bytes written in base64url."""
    wanted = view.approval["credential_id"].lower()
    return not any(cid.lower() == wanted for cid in view.context["credentials"])


def _supported_set_read_through_aliases(view: View) -> bool:
    """Look the registry's algorithm up in the declared set through RFC 9864's aliases."""
    credential = view.credential
    assert credential is not None
    return _FULLY_SPECIFIED.get(credential["alg"], credential["alg"]) not in (
        view.context["supported_algorithms"]
    )


def _supported_set_hardcoded(view: View) -> bool:
    """Decide support from a list written into the code rather than from the declared set,
    which is what a build that lacks one of those algorithms would still claim."""
    credential = view.credential
    assert credential is not None
    return credential["alg"] not in (ES256, EDDSA)


def _either_preimage_accepted(view: View) -> bool:
    """Accept a challenge over `{profile, approval}` or over the approval alone: liberal
    about which of two readings of the pre-image, and so accepting both."""
    alone = _b64u(hashlib.sha256(rfc8785.dumps(view.approval)).digest())
    return view.client_data.get("challenge") not in (expected_challenge(view.artifact), alone)


def _canonical_form_escapes_non_ascii(view: View) -> bool:
    """Derive the challenge with Python's `json.dumps(sort_keys=True)`, which escapes every
    character outside ASCII where RFC 8785 writes it as UTF-8."""
    preimage = {"profile": view.artifact["profile"], "approval": view.approval}
    serialized = json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode()
    return view.client_data.get("challenge") != _b64u(hashlib.sha256(serialized).digest())


def _challenge_skipped_when_cited(view: View) -> bool:
    """Skip the challenge when a record cites the artifact, on the reading that the
    record's digest already fixes what the artifact says."""
    if view.citation is not None:
        return False
    return view.client_data.get("challenge") != expected_challenge(view.artifact)


def _compares_decoded_bytes(view: View) -> bool:
    """Decode the challenge and compare bytes, which accepts every spelling of them."""
    sent = view.client_data.get("challenge")
    if not isinstance(sent, str):
        return True
    try:
        received = _b64u_decode(sent)
    except ValueError:
        return True
    return received != _b64u_decode(expected_challenge(view.artifact))


def _type_checked_only_when_present(view: View) -> bool:
    client_data = view.client_data
    return "type" in client_data and client_data["type"] != "webauthn.get"


def _payment_confirmation_accepted(view: View) -> bool:
    """Accept Secure Payment Confirmation's client data type beside the plain one."""
    return view.client_data.get("type") not in ("webauthn.get", "payment.get")


def _cross_origin_flag_only(view: View) -> bool:
    """Read `crossOrigin` and trust it to say whether `topOrigin` matters."""
    return view.client_data.get("crossOrigin") is True


def _registry_only(view: View) -> bool:
    """Accept any origin the credential is registered for, whatever the approval says."""
    credential = view.credential
    assert credential is not None
    return view.client_data.get("origin") not in credential["origins"]


def _host(origin: Any) -> str | None:
    return urlsplit(origin).hostname if isinstance(origin, str) else None


def _host_only(view: View) -> bool:
    """Compare origins by host, as if the scheme were decoration."""
    credential = view.credential
    assert credential is not None
    host = _host(view.client_data.get("origin"))
    return host not in {_host(o) for o in credential["origins"]} or host != _host(
        view.approval["origin"]
    )


def _origin_prefix_match(view: View) -> bool:
    """Accept an origin that begins with a registered one and with the approval's."""
    credential = view.credential
    assert credential is not None
    origin = str(view.client_data.get("origin", ""))
    return not any(origin.startswith(o) for o in credential["origins"]) or not (
        origin.startswith(view.approval["origin"])
    )


def _rp_id_taken_from_the_artifact(view: View) -> bool:
    """Check the hash against the RP ID the approval names, not the one registered."""
    return view.authenticator_data[:32] != hashlib.sha256(
        view.approval["rp_id"].encode()
    ).digest()


def _case_insensitive_approver(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    return bool(view.approval["approver"].lower() != credential["approver"].lower())


def _approver_registered_anywhere(view: View) -> bool:
    """Accept any approver the registry knows, rather than this credential's."""
    known = {entry["approver"] for entry in view.context["credentials"].values()}
    return view.approval["approver"] not in known


def _presence_implied_by_verification(view: View) -> bool:
    """Treat a verified user as a present one."""
    return not view.flags & (UP | UV)


def _verification_required_for_allow_only(view: View) -> bool:
    """Require user verification for approvals and ignore what the policy says of denials."""
    return view.approval["decision"] == "allow" and not view.flags & UV


def _only_against_recorded_eligibility(view: View) -> bool:
    """Check BS against what the registry recorded rather than against the BE bit."""
    credential = view.credential
    return bool(view.flags & BS) and credential is not None and (
        credential.get("backup_eligible") is False
    )


def _backup_state_checked_for_allows_only(view: View) -> bool:
    """Check BS without BE on the approvals that matter, and let a refusal through."""
    return view.approval["decision"] == "allow" and not view.flags & BE and bool(view.flags & BS)


def _unrecorded_eligibility_read_as_false(view: View) -> bool:
    """Read eligibility the registry never recorded as recorded false."""
    credential = view.credential
    assert credential is not None
    return bool(view.flags & BE) != bool(credential.get("backup_eligible", False))


def _one_direction_only(view: View) -> bool:
    """Notice a credential losing backup eligibility and not one gaining it."""
    credential = view.credential
    assert credential is not None
    return credential.get("backup_eligible") is True and not view.flags & BE


def _compared_only_when_supported(view: View) -> bool:
    """Compare the artifact's algorithm with the registry's only when it is one the
    verifier recognises, and otherwise skip the comparison."""
    credential = view.credential
    assert credential is not None
    alg = view.assertion["alg"]
    return alg in view.context["supported_algorithms"] and alg != credential["alg"]


_FULLY_SPECIFIED = {-9: -7, -19: -8, -51: -35}
"""RFC 9864's identifiers, mapped to the WebAuthn identifiers they mean within WebAuthn."""


def _fully_specified_identifiers_aliased(view: View) -> bool:
    """Treat each RFC 9864 identifier as the WebAuthn identifier it corresponds to."""
    credential = view.credential
    assert credential is not None
    alias = lambda alg: _FULLY_SPECIFIED.get(alg, alg)  # noqa: E731
    return bool(alias(view.assertion["alg"]) != alias(credential["alg"]))


def _either_signature_encoding_accepted(view: View) -> bool:
    """Accept an ECDSA signature in DER, or as the fixed-length r and s JOSE uses."""
    credential = view.credential
    assert credential is not None
    signature = _b64u_decode(view.assertion["signature"])
    message = view.authenticator_data + hashlib.sha256(view.client_data_json).digest()
    candidates = [signature]
    if credential["alg"] in (ES256, -35) and len(signature) in (64, 96):
        half = len(signature) // 2
        candidates.append(encode_dss_signature(
            int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")))
    return not any(
        _verifies(credential["public_key"], credential["alg"], s, message) for s in candidates
    )


def _client_data_reserialized(view: View) -> bool:
    """Hash the client data as re-serialized from what was parsed, not as received."""
    credential = view.credential
    assert credential is not None
    signature = _b64u_decode(view.assertion["signature"])
    again = json.dumps(view.client_data, separators=(",", ":")).encode()
    message = view.authenticator_data + hashlib.sha256(again).digest()
    return not _verifies(credential["public_key"], credential["alg"], signature, message)


def _either_message_accepted(view: View) -> bool:
    """Accept a signature over the hashed client data or over the client data itself, the
    second being what a verifier that forgot the hash step would check."""
    credential = view.credential
    assert credential is not None
    signature = _b64u_decode(view.assertion["signature"])
    hashed = view.authenticator_data + hashlib.sha256(view.client_data_json).digest()
    raw = view.authenticator_data + view.client_data_json
    return not any(
        _verifies(credential["public_key"], credential["alg"], signature, message)
        for message in (hashed, raw)
    )


def _expiry_only(view: View) -> bool:
    """Half a validity window. The half everyone remembers."""
    skew = view.context["clock_skew_seconds"]
    return not view.context["now"] < view.approval["expires_at"] + skew


def _closed_interval(view: View) -> bool:
    """`<=` at the expiry, so an approval stays usable for the second it expires."""
    skew, now = view.context["clock_skew_seconds"], view.context["now"]
    return not (
        view.approval["issued_at"] - skew <= now <= view.approval["expires_at"] + skew
    )


def _unusable_at_issuance(view: View) -> bool:
    """`<` at the start, so an approval is not yet usable in the second it is issued."""
    skew, now = view.context["clock_skew_seconds"], view.context["now"]
    return not (
        view.approval["issued_at"] - skew < now < view.approval["expires_at"] + skew
    )


def _tolerance_ignored(view: View) -> bool:
    """Judge the window on the verifier's own clock as if it were the relying party's."""
    now = view.context["now"]
    return not view.approval["issued_at"] <= now < view.approval["expires_at"]


def _tolerance_at_the_start_only(view: View) -> bool:
    """Forgive a clock that runs slow and not one that runs fast."""
    skew, now = view.context["clock_skew_seconds"], view.context["now"]
    return not view.approval["issued_at"] - skew <= now < view.approval["expires_at"]


def _identity_is_enough_when_cited(view: View) -> bool:
    """Once a record cites the artifact, take it as the approval the record says it is."""
    return view.approval["decision"] != "allow" and view.citation is None


def _decision_reported_only_when_otherwise_sound(view: View) -> bool:
    """Report a refusal only for an artifact whose flags are in order, on the reading that
    a broken refusal is simply broken."""
    flags_wrong = view.flags & UP == 0 or (view.flags & BS and not view.flags & BE)
    return view.approval["decision"] != "allow" and not flags_wrong and view.flags & UV != 0


def _digest_skipped_when_challenge_holds(view: View) -> bool:
    """Skip the citation's digest when the challenge checks out, on the reading that the
    challenge already binds the approval."""
    if view.client_data.get("challenge") == expected_challenge(view.artifact):
        return False
    citation = view.citation
    assert citation is not None
    if "digest" not in citation:
        return False
    return bool(citation["digest"] != _jcs_digest(view.artifact, "sha256"))


def _either_digest_accepted(view: View) -> bool:
    """Accept a reference digest over the whole artifact or over the challenge pre-image,
    the part of it the approver's key covers."""
    citation = view.citation
    assert citation is not None
    if "digest" not in citation:
        return False
    algorithm = citation["digest"].split(":", 1)[0]
    signed = {"profile": view.artifact["profile"], "approval": view.approval}
    return citation["digest"] not in (
        _jcs_digest(view.artifact, algorithm), _jcs_digest(signed, algorithm)
    )


def _whole_jwk_compared(view: View) -> bool:
    """Compare the two JWK objects, advisory members included."""
    credential = view.credential
    assert view.record is not None
    return credential is not None and credential["public_key"] == view.record["cnf"]["jwk"]


def _identifier_not_resolved(view: View) -> bool:
    """Compare the approver identifier with the subject without resolving it."""
    assert view.record is not None
    return bool(view.approval["approver"] == view.record["subject"])


def _presence_read_as_resolution(view: View) -> bool:
    """Take an identifier the directory has an entry for as resolved, whatever the entry
    says, which is how a deprovisioned account keeps passing."""
    assert view.record is not None
    approver = view.approval["approver"]
    return approver not in view.context["identity"] and approver != view.record["subject"]


def _null_counter_read_as_state(view: View) -> bool:
    """Read a present `sign_count` member as stored state, even when it is null."""
    credential = view.credential
    assert credential is not None
    return "sign_count" not in credential and view.sign_count != 0


def _zero_read_as_no_counter(view: View) -> bool:
    """Take a reported count of zero to mean an authenticator with no counter."""
    credential = view.credential
    assert credential is not None
    stored = credential.get("sign_count")
    if stored is None or view.sign_count == 0:
        return False
    return view.sign_count <= stored


def _strictly_lower_only(view: View) -> bool:
    """Report a counter that went down, and not one that stood still."""
    credential = view.credential
    assert credential is not None
    stored = credential.get("sign_count")
    if stored is None or (stored == 0 and view.sign_count == 0):
        return False
    return view.sign_count < stored


DEFECTS: dict[str, dict[str, Check]] = {
    "profile_not_supported": {
        "profile_family_only": _profile_family_only,
        "profile_prefix_match": _profile_prefix_match,
    },
    "artifact_malformed": {
        "open_objects": _open_objects,
        "integer_range_unchecked": _integer_range_unchecked,
        "window_order_unchecked": _window_order_unchecked,
        "nonce_length_unchecked": _nonce_length_unchecked,
        "client_data_closed": _client_data_closed,
    },
    "credential_unknown": {"case_insensitive_lookup": _case_insensitive_lookup},
    "challenge_mismatch": {
        "either_preimage_accepted": _either_preimage_accepted,
        "compares_decoded_bytes": _compares_decoded_bytes,
        "canonical_form_escapes_non_ascii": _canonical_form_escapes_non_ascii,
        "challenge_skipped_when_cited": _challenge_skipped_when_cited,
    },
    "client_data_type": {
        "type_checked_only_when_present": _type_checked_only_when_present,
        "payment_confirmation_accepted": _payment_confirmation_accepted,
    },
    "cross_origin_not_expected": {"cross_origin_flag_only": _cross_origin_flag_only},
    "user_not_present": {"presence_implied_by_verification": _presence_implied_by_verification},
    "user_not_verified": {
        "verification_required_for_allow_only": _verification_required_for_allow_only
    },
    "backup_state_inconsistent": {
        "only_against_recorded_eligibility": _only_against_recorded_eligibility,
        "backup_state_checked_for_allows_only": _backup_state_checked_for_allows_only,
    },
    "outside_validity_window": {
        "expiry_only": _expiry_only,
        "closed_interval": _closed_interval,
        "tolerance_ignored": _tolerance_ignored,
        "tolerance_at_the_start_only": _tolerance_at_the_start_only,
        "unusable_at_issuance": _unusable_at_issuance,
    },
    "decision_not_allow": {
        "identity_is_enough_when_cited": _identity_is_enough_when_cited,
        "decision_reported_only_when_otherwise_sound": _decision_reported_only_when_otherwise_sound,
    },
    "origin_not_expected": {
        "registry_only": _registry_only,
        "host_only": _host_only,
        "origin_prefix_match": _origin_prefix_match,
    },
    "rp_id_mismatch": {"rp_id_taken_from_the_artifact": _rp_id_taken_from_the_artifact},
    "approver_not_registered": {
        "case_insensitive_approver": _case_insensitive_approver,
        "approver_registered_anywhere": _approver_registered_anywhere,
    },
    "backup_eligibility_changed": {
        "one_direction_only": _one_direction_only,
        "unrecorded_eligibility_read_as_false": _unrecorded_eligibility_read_as_false,
    },
    "algorithm_mismatch": {
        "compared_only_when_supported": _compared_only_when_supported,
        "fully_specified_identifiers_aliased": _fully_specified_identifiers_aliased,
    },
    "algorithm_unsupported": {
        "supported_set_hardcoded": _supported_set_hardcoded,
        "supported_set_read_through_aliases": _supported_set_read_through_aliases,
    },
    "counter_not_checked": {"null_counter_read_as_state": _null_counter_read_as_state},
    "counter_not_increasing": {
        "strictly_lower_only": _strictly_lower_only,
        "zero_read_as_no_counter": _zero_read_as_no_counter,
    },
    "signature_invalid": {
        "either_message_accepted": _either_message_accepted,
        "either_signature_encoding_accepted": _either_signature_encoding_accepted,
        "client_data_reserialized": _client_data_reserialized,
    },
    "reference_digest_mismatch": {
        "either_digest_accepted": _either_digest_accepted,
        "digest_skipped_when_challenge_holds": _digest_skipped_when_challenge_holds,
    },
    "approval_key_is_record_key": {"whole_jwk_compared": _whole_jwk_compared},
    "approver_is_record_subject": {"identifier_not_resolved": _identifier_not_resolved},
    "approver_unresolved": {"presence_read_as_resolution": _presence_read_as_resolution},
}


# ---------------------------------------------------------------------------
# Mutation machinery
# ---------------------------------------------------------------------------


def _outcomes(rules: tuple[Rule, ...]) -> list[tuple[str, str, tuple[str, ...], str | None]]:
    out = []
    for name, vector in zip(NAMES, VECTORS, strict=True):
        result = verify_approval(vector, rules)
        out.append((name, result.outcome, tuple(result.codes), result.credential_attestation))
    return out


DECLARED = [
    (
        name,
        vector["expected"]["outcome"],
        tuple(sorted(vector["expected"]["codes"])),
        vector["expected"]["credential_attestation"],
    )
    for name, vector in zip(NAMES, VECTORS, strict=True)
]


def _without(code: str) -> tuple[Rule, ...]:
    return tuple(rule for rule in RULES if rule.code != code)


def _weakened(code: str, check: Check) -> tuple[Rule, ...]:
    return tuple(replace(rule, check=check) if rule.code == code else rule for rule in RULES)


def _deviating(rules: tuple[Rule, ...]) -> set[str]:
    """Vector names whose outcome under `rules` departs from their declared block."""
    return {
        was[0] for was, now in zip(DECLARED, _outcomes(rules), strict=True) if was != now
    }


def _margin(code: str) -> set[str]:
    """Vectors whose result, the outcome or the codes, changes when `code` is deleted."""
    return _deviating(_without(code))


def _outcome_deviating(rules: tuple[Rule, ...]) -> set[str]:
    """Vector names whose four-valued outcome under `rules` departs from the declared one."""
    return {
        name
        for name, vector in zip(NAMES, VECTORS, strict=True)
        if verify_approval(vector, rules).outcome != vector["expected"]["outcome"]
    }


def _outcome_margin(code: str) -> set[str]:
    """Vectors whose four-valued outcome changes when `code` is deleted."""
    return _outcome_deviating(_without(code))


# ---------------------------------------------------------------------------
# 0. Guards on the instrument itself
# ---------------------------------------------------------------------------


def test_the_unmutated_registry_agrees_with_every_declaration() -> None:
    """Without this, every mutation below measures deviation from a baseline that already
    deviates, and a registry that agrees with nothing passes them all."""
    assert _deviating(RULES) == set()


def test_registry_is_well_formed() -> None:
    assert VECTORS, "no vectors found"
    assert len(RULES) == 24, "the registry gained or lost an entry; update the RFC's table"
    assert len(set(RULE_CODES)) == len(RULE_CODES), "duplicate rule codes"
    assert {rule.klass for rule in RULES} == {"invalid", "unverifiable", "decision", "advisory"}
    assert {rule.stage for rule in RULES} == {
        "profile", "shape", "lookup", "artifact", "credential", "signature", "record",
    }


def test_no_emission_outside_the_registry() -> None:
    """The registry is the inventory *because* `_evaluate` is the only place a code is
    emitted. This walks the verifier's source and fails on an append to a code list
    anywhere outside that function, or a literal code passed as `codes=`."""
    tree = ast.parse(VERIFIER_MODULE.read_text(encoding="utf-8"))

    enclosing: dict[ast.AST, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                enclosing.setdefault(child, node.name)

    offenders: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"append", "extend", "insert"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"codes", "emitted"}
            and enclosing.get(node) != "_evaluate"
        ):
            offenders.append(f"{enclosing.get(node, '<module>')}:{node.lineno}")
        if isinstance(node, ast.keyword) and node.arg == "codes":
            if isinstance(node.value, ast.List):
                for element in node.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        offenders.append(
                            f"{enclosing.get(node, '<module>')}: literal {element.value!r}"
                        )

    assert not offenders, (
        "codes emitted outside the registry, which would make the rule inventory "
        f"incomplete without failing anything: {offenders}"
    )


def test_registry_codes_are_literals() -> None:
    """A code built from a variable or an f-string is invisible to every reader and to the
    RFC's rule table."""
    tree = ast.parse(VERIFIER_MODULE.read_text(encoding="utf-8"))
    constructions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Rule"
    ]
    assert len(constructions) == len(RULES), (
        "the registry is not built from literal Rule(...) constructions in the verifier"
    )
    assert all(
        node.args and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        for node in constructions
    ), "a rule code is not a string literal"


# ---------------------------------------------------------------------------
# 1-2. Dead expectations, unexercised rules, unreached outcomes
# ---------------------------------------------------------------------------


def test_no_vector_expects_a_code_the_registry_cannot_emit() -> None:
    declared = {code for vector in VECTORS for code in vector["expected"]["codes"]}
    unknown = sorted(declared - set(RULE_CODES))
    assert not unknown, f"vectors expect codes no rule emits: {unknown}"


def test_every_registered_rule_is_exercised_by_some_vector() -> None:
    declared = {code for vector in VECTORS for code in vector["expected"]["codes"]}
    idle = sorted(set(RULE_CODES) - declared)
    assert not idle, f"registered rules no vector exercises: {idle}"


def test_every_declared_outcome_is_reached_by_some_vector() -> None:
    reached = {vector["expected"]["outcome"] for vector in VECTORS}
    assert reached == OUTCOMES, f"outcomes no vector produces: {sorted(OUTCOMES - reached)}"


# ---------------------------------------------------------------------------
# 3-4. Margin and independence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", RULE_CODES)
def test_each_rule_is_load_bearing_for_two_vectors(code: str) -> None:
    """Deleting an obligation must change at least two vectors' outcomes.

    One is existence; two is margin. With a single load-bearing vector, any change that
    weakens or retires that vector silently removes the rule's coverage.
    """
    margin = _margin(code)
    assert len(margin) >= 2, (
        f"removing rule {code!r} changed {len(margin)} vector outcome(s) "
        f"({sorted(margin)}). Two independent vectors are required per rule."
    )


@pytest.mark.parametrize("code", [rule.code for rule in RULES if rule.klass != "advisory"])
def test_each_deciding_rule_changes_two_outcomes(code: str) -> None:
    """The margin above counts a vector whose codes change and whose outcome does not: vector
    49 fails both W-4 and W-21, so deleting either changes its codes and leaves it invalid.
    Every rule that can decide an outcome is also held to two vectors whose outcome changes
    when it is deleted, so that the floor is met on what the verifier concludes and not
    only on what it reports."""
    changed = _outcome_margin(code)
    assert len(changed) >= 2, (
        f"removing rule {code!r} changed the outcome of {len(changed)} vector(s) "
        f"({sorted(changed)}); two are required per deciding rule."
    )


@pytest.mark.parametrize("code", [rule.code for rule in RULES if rule.klass == "advisory"])
def test_advisory_rules_decide_nothing(code: str) -> None:
    """An advisory is reported and changes no outcome, which is what the RFC says of the
    counter. Deleting one changes codes only."""
    assert _margin(code) and not _outcome_margin(code)


def test_every_rule_declares_a_defect() -> None:
    missing = sorted(set(RULE_CODES) - set(DEFECTS))
    assert not missing, f"registered rules with no declared defect variant: {missing}"
    stale = sorted(set(DEFECTS) - set(RULE_CODES))
    assert not stale, f"defects declared for rules that no longer exist: {stale}"


@pytest.mark.parametrize("code", RULE_CODES)
def test_vectors_for_each_rule_are_independent(code: str) -> None:
    """#124's criterion, executed: some single defect separates the rule's vectors."""
    bearing = _margin(code)
    if len(bearing) < 2:
        pytest.fail(f"rule {code!r} lacks two load-bearing vectors; the margin test covers this")

    separations = {}
    for name, weakened_check in DEFECTS[code].items():
        caught = _deviating(_weakened(code, weakened_check)) & bearing
        if 0 < len(caught) < len(bearing):
            separations[name] = sorted(caught)

    assert separations, (
        f"no declared defect separates the vectors for {code!r}: every weakening either "
        f"fools all of {sorted(bearing)} or none of them. Author a vector that catches a "
        "defect the others miss, or declare a defect that tells them apart."
    )


@pytest.mark.parametrize(
    "code, defect",
    [(code, name) for code, defects in DEFECTS.items() for name in defects],
)
def test_every_declared_defect_is_caught_by_the_corpus(code: str, defect: str) -> None:
    """A defect nothing catches is a defect the corpus would certify. Every one declared
    here fails at least one vector, so none of them is a description of a verifier that
    passes the set."""
    caught = _deviating(_weakened(code, DEFECTS[code][defect]))
    assert caught, f"{code}/{defect} deviates on no vector: the corpus would certify it"


# ---------------------------------------------------------------------------
# The RFC states what this suite measures
# ---------------------------------------------------------------------------

RFC = TESTS_DIR.parent / "docs" / "rfcs" / "webauthn-approval-profile.md"


def test_the_rfc_rule_table_is_the_registry() -> None:
    """The RFC's table is what a reader takes the rules to be, and nothing else reads it.
    Each row is held to the registry: its number is the rule's position, its code and class
    are the rule's, and its vectors are exactly the ones deleting the rule changes."""
    rows = [
        line for line in RFC.read_text(encoding="utf-8").splitlines() if line.startswith("| W-")
    ]
    assert len(rows) == len(RULES), "the RFC's table and the registry differ in length"
    for position, (row, rule) in enumerate(zip(rows, RULES, strict=True), 1):
        number, code, klass, _, vectors = (cell.strip() for cell in row.strip("|").split("|"))
        assert number == f"W-{position}", row
        assert code == f"`{rule.code}`", row
        assert klass == rule.klass, row
        assert vectors == ", ".join(sorted(name[:2] for name in _margin(rule.code))), row


_WORDS = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight",
          9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}


def _listed(items: list[str]) -> str:
    """`a`, `a and b`, `a, b and c`: the way the RFC writes a list."""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _numbers(names: set[str]) -> str:
    return _listed(sorted(name[:2] for name in names))


def _unsplit_pairs() -> dict[str, list[tuple[str, str]]]:
    """Per rule with more than two vectors: the pairs of its vectors no declared defect
    tells apart, which #124's criterion does not require and the RFC names."""
    out = {}
    for i, rule in enumerate(RULES, 1):
        bearing = sorted(_margin(rule.code))
        caught = [_deviating(_weakened(rule.code, check)) for check in DEFECTS[rule.code].values()]
        pairs = [
            (a[:2], b[:2]) for n, a in enumerate(bearing) for b in bearing[n + 1:]
            if not any((a in c) != (b in c) for c in caught)
        ]
        if pairs:
            out[f"W-{i}"] = pairs
    return out


def test_the_pairs_no_declared_defect_separates_are_the_ones_the_rfc_names() -> None:
    """#124 asks for one defect that splits a rule's vectors, not one per pair. The pairs
    left unsplit are recorded, and each is a vector listed under the rule only for its
    codes, whose outcome another rule decides."""
    unsplit = _unsplit_pairs()
    assert unsplit == {"W-11": [("31", "33"), ("31", "66"), ("33", "66")]}, unsplit
    text = " ".join(RFC.read_text(encoding="utf-8").split())
    assert "no declared defect separates 31, 33 and 66 from one another under W-11" in text


_NEAR_MISS_ROW = re.compile(r"^\| (?P<vector>\d\d) \| .* \| (?P<defects>`[^|]*`) \|$")


def test_each_near_miss_vector_closes_a_shortcut_the_ones_before_it_let_through() -> None:
    """The RFC's table of vectors 61 to 72: for each, the declared defects that take the
    shortcut it names fail it and pass every vector numbered below 61, and every defect
    that does so for a vector is in its row."""
    rows = {}
    for line in RFC.read_text(encoding="utf-8").splitlines():
        match = _NEAR_MISS_ROW.match(line)
        if match:
            rows[match["vector"]] = re.findall(r"`([a-z_]+)`", match["defects"])
    assert sorted(rows) == [f"{n}" for n in range(61, 73)], sorted(rows)
    closing: dict[str, list[str]] = {}
    for code, named in DEFECTS.items():
        for name, check in named.items():
            caught = {vector[:2] for vector in _deviating(_weakened(code, check))}
            if all(int(vector) >= 61 for vector in caught):
                for vector in caught:
                    closing.setdefault(vector, []).append(name)
    assert {vector: sorted(names) for vector, names in rows.items()} == {
        vector: sorted(closing.get(vector, [])) for vector in rows
    }


def test_the_rfc_states_the_figures_this_suite_measures() -> None:
    """Every count the RFC gives, recomputed. A figure no test reads is the one that is
    still wrong when everything is green."""
    text = " ".join(RFC.read_text(encoding="utf-8").split())
    outcomes = [vector["expected"]["outcome"] for vector in VECTORS]
    defects = [(code, name) for code, named in DEFECTS.items() for name in named]
    klass = {rule.code: rule.klass for rule in RULES}
    number = {rule.code: f"W-{i}" for i, rule in enumerate(RULES, 1)}
    deciding = [(code, name) for code, name in defects if klass[code] != "advisory"]
    advisory = [(code, name) for code, name in defects if klass[code] == "advisory"]
    codes_only = []
    for code, name in deciding:
        weakened = _weakened(code, DEFECTS[code][name])
        if _deviating(weakened) != _outcome_deviating(weakened):
            assert not _outcome_deviating(weakened), (code, name)
            codes_only.append((name, _deviating(weakened)))
    for code, name in advisory:
        assert not _outcome_deviating(_weakened(code, DEFECTS[code][name])), (code, name)
    local = [
        (code, name) for code, name in defects
        if _deviating(_weakened(code, DEFECTS[code][name])) <= _margin(code)
    ]
    stricter = [pair for pair in defects if pair not in local]
    valid = {n for n, v in zip(NAMES, VECTORS, strict=True)
             if v["expected"]["outcome"] == "approval-valid"}

    wider: dict[int, list[str]] = {}
    for code in RULE_CODES:
        size = len(_margin(code))
        if size > 2:
            wider.setdefault(size, []).append(number[code])
    groups = [
        f"{_listed(names)} {_WORDS[size]}" + (" each" if len(names) > 1 else "")
        for size, names in sorted(wider.items(), reverse=True)
    ]
    carried = sum(len(names) for names in wider.values())

    changed_codes_only: dict[str, set[str]] = {}
    for code in RULE_CODES:
        only = _margin(code) - _outcome_margin(code)
        if only and klass[code] != "advisory":
            changed_codes_only[number[code]] = only
    shared = set().union(*changed_codes_only.values())

    expected = [
        f"`examples/webauthn-approval/`: {len(VECTORS)} vectors",
        f"{len(RULES)} rules, each with a stable code",
        f"For each of the {sum(klass[c] != 'advisory' for c in RULE_CODES)} rules that can "
        "decide an outcome, at least two of its vectors change outcome",
        f"Of the {len(VECTORS)}, {outcomes.count('approval-valid')} are valid, "
        f"{outcomes.count('not-an-approval')} are refusals, "
        f"{outcomes.count('approval-unverifiable')} are unverifiable and "
        f"{outcomes.count('approval-invalid')} are invalid, and "
        f"{sum('record' in vector for vector in VECTORS)} carry a citing record",
        f"{len(defects)} implementation defects are declared",
        f"Of the {len(deciding)} on rules that can decide an outcome, "
        f"{len(deciding) - len(codes_only)} change the outcome of every vector they fail, as the "
        f"suite measures it, and {len(codes_only)} change only the codes of vectors whose "
        "outcome another rule decides",
        f"the {_WORDS[len(advisory)]} on the counter rules change codes only",
        f"{len(local)} of the {len(defects)} fail only vectors",
        f"The other {len(stricter)} are stricter than their rule and fail only valid controls",
        f"{_WORDS[carried]} rules carry more: " + ", ".join(groups[:-1]) + ", and " + groups[-1],
        f"On {_WORDS[len(shared)]} vectors a deletion changes the codes and not the outcome",
    ]
    for code, name in stricter:
        caught = _deviating(_weakened(code, DEFECTS[code][name]))
        assert caught <= valid, (code, name, caught)
        expected.append(f"`{name}` fails {_numbers(caught)}")
    for name, caught in codes_only:
        expected.append(f"`{name}` on {_numbers(caught)}")
    for rule in changed_codes_only:
        code = RULE_CODES[int(rule[2:]) - 1]
        decides = _outcome_margin(code)
        expected.append(f"{rule} alone decides are {_numbers(decides)}"
                        if rule == "W-11" else f"{rule}'s are {_numbers(decides)}")
    for code, defect, reading in (
        ("challenge_mismatch", "compares_decoded_bytes",
         "comparing the challenge as decoded bytes"),
        ("backup_state_inconsistent", "only_against_recorded_eligibility",
         "treating BS without BE as policy"),
        ("counter_not_increasing", "strictly_lower_only",
         "reporting a counter only when it goes down"),
    ):
        (caught,) = _deviating(_weakened(code, DEFECTS[code][defect]))
        expected.append(f"{reading} (vector {caught[:2]})")
    missing = [phrase for phrase in expected if phrase not in text]
    assert not missing, f"the RFC does not state these measured figures: {missing}"


# ---------------------------------------------------------------------------
# 5. The ratchet
# ---------------------------------------------------------------------------


def test_margins_have_not_thinned() -> None:
    """A ratchet above the floor. The floor is two."""
    current = {code: len(_margin(code)) for code in RULE_CODES}

    if not MARGINS_FILE.exists():
        MARGINS_FILE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip(f"recorded initial margins to {MARGINS_FILE.name}; re-run to enforce")

    recorded: dict[str, int] = json.loads(MARGINS_FILE.read_text(encoding="utf-8"))
    thinned = {
        key: (recorded[key], current[key])
        for key in recorded
        if key in current and current[key] < recorded[key]
    }
    assert not thinned, (
        "coverage thinned for: "
        + ", ".join(f"{k} {was}->{now}" for k, (was, now) in sorted(thinned.items()))
        + ". Lowering a recorded margin is a decision to make on purpose, in this commit, "
        "with a reason."
    )
