"""Run the webauthn-approval corpus through a reference verifier for the proposed profile.

An approval artifact pairs an approval object with a WebAuthn authentication assertion
whose challenge is derived from it, and `docs/rfcs/webauthn-approval-profile.md` proposes
what a verifier does with one. This module is that proposal executed: every rule below is
a numbered rule in the RFC, and every vector under `examples/webauthn-approval/` declares
its expected outcome in its own file, written by the generator's case table before this
code reads it.

The shape is `test_delegation_vectors.py`'s, for the same reason: a check that is not
registered never runs, so it cannot exist outside the inventory that
`test_webauthn_approval_completeness.py` mutates. Nothing here is exported from
`agentrust_trace`: the package gains no public API for rules that are not normative.

Three orderings carry weight:

  The gate runs first and ends the evaluation. A verifier reads no further into an
  artifact whose profile it does not implement, and no further into a malformed one:
  every later rule decodes something, and the gate is what establishes that it decodes.
  The profile is asked before the shape, because another version's artifact is not
  malformed for having another version's shape.

  The credential and signature stages run only when the registry holds the credential,
  and the signature stage only when the verifier can compute the registry's algorithm.
  Whether a stage runs is a structural fact asked directly, never derived from which rules
  fired, so removing a rule under mutation changes what is reported and never what is read.

  A contradiction outranks an inability to check: an artifact that is unverifiable in one
  respect and contradicted in another is invalid. `not-an-approval` ranks below both,
  because a refusal is a valid refusal only when nothing else is wrong with it.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from agentrust_trace import verify_record
from agentrust_trace.validate import iter_errors

VECTOR_DIR = Path(__file__).resolve().parents[1] / "examples" / "webauthn-approval"
PROFILE = "tag:agentrust-io.com,2026:webauthn-approval-v1"

OUTCOMES = frozenset(
    {"approval-valid", "not-an-approval", "approval-invalid", "approval-unverifiable"}
)
"""Every outcome the verifier can return. `unverifiable` is kept apart from `invalid` for
the reason spec section 3.3.2 gives receipts: a check the verifier could not run is not a
finding against the artifact. `not-an-approval` is kept apart from both, because a validly
signed refusal is neither broken nor unreadable."""

ES256, EDDSA, ES384 = -7, -8, -35
IMPLEMENTED = frozenset({ES256, EDDSA, ES384})
UP, UV, BE, BS = 0x01, 0x04, 0x08, 0x10


@dataclass(frozen=True)
class ApprovalResult:
    outcome: str
    codes: list[str]
    credential_attestation: str | None

    def __post_init__(self) -> None:
        assert self.outcome in OUTCOMES, f"undeclared outcome {self.outcome!r}"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_THUMBPRINT_MEMBERS: dict[str, tuple[str, ...]] = {
    "EC": ("crv", "kty", "x", "y"),  # RFC 7638 section 3.2
    "RSA": ("e", "kty", "n"),  # RFC 7638 section 3.2
    "OKP": ("crv", "kty", "x"),  # RFC 8037 section 2
    "AKP": ("alg", "kty", "pub"),  # RFC 9964 section 6
}
"""The members a JWK thumbprint is taken over, by key type: the key, and nothing advisory."""


def _key_material(jwk: dict[str, Any]) -> tuple[Any, ...]:
    """A key's identity: the members its JWK thumbprint is taken over, so `kid` and the
    other advisory members do not count. For a key type none of those specifications
    covers, which members are the key is not known, and the whole JWK is compared."""
    members = _THUMBPRINT_MEMBERS.get(jwk.get("kty", ""))
    if members is None:
        return tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in jwk.items()))
    return tuple((member, jwk.get(member)) for member in members)


def _verifies(jwk: dict[str, Any], alg: int, signature: bytes, message: bytes) -> bool:
    """Does `signature` verify over `message` under `jwk` as COSE algorithm `alg`?

    ES256 and ES384 signatures are ASN.1 DER, as WebAuthn requires of ECDSA assertion
    signatures; EdDSA signatures are the raw 64 bytes. A key whose type does not match
    the algorithm does not verify anything.
    """
    try:
        if alg == EDDSA:
            if (jwk.get("kty"), jwk.get("crv")) != ("OKP", "Ed25519"):
                return False
            Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"])).verify(signature, message)
            return True
        if alg == ES256:
            curve, crv, digest = ec.SECP256R1(), "P-256", hashes.SHA256()
        elif alg == ES384:
            curve, crv, digest = ec.SECP384R1(), "P-384", hashes.SHA384()
        else:
            return False
        if (jwk.get("kty"), jwk.get("crv")) != ("EC", crv):
            return False
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64u_decode(jwk["x"]), "big"),
            int.from_bytes(_b64u_decode(jwk["y"]), "big"),
            curve,
        )
        numbers.public_key().verify(signature, message, ec.ECDSA(digest))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


# ---------------------------------------------------------------------------
# The artifact's shape
# ---------------------------------------------------------------------------

_B64U: dict[str, Any] = {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"}
_SAFE_TIME: dict[str, Any] = {"type": "integer", "minimum": 0, "maximum": 9007199254740991}

ARTIFACT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["profile", "approval", "assertion"],
    "properties": {
        "profile": {"type": "string"},
        "approval": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "approval_id", "decision", "approver", "credential_id", "rp_id", "origin",
                "subject_kind", "subject_digest", "nonce", "issued_at", "expires_at",
            ],
            "properties": {
                "approval_id": {"type": "string", "minLength": 1},
                "decision": {"enum": ["allow", "deny"]},
                "approver": {"type": "string", "minLength": 1},
                "credential_id": _B64U,
                "rp_id": {"type": "string", "minLength": 1},
                "origin": {"type": "string", "minLength": 1},
                "subject_kind": {"type": "string", "minLength": 1},
                "subject_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "nonce": {"type": "string", "pattern": "^[A-Za-z0-9_-]{22,}$"},
                "issued_at": _SAFE_TIME,
                "expires_at": _SAFE_TIME,
            },
        },
        "assertion": {
            "type": "object",
            "additionalProperties": False,
            "required": ["authenticator_data", "client_data_json", "signature", "alg"],
            "properties": {
                "authenticator_data": _B64U,
                "client_data_json": _B64U,
                "signature": _B64U,
                "alg": {
                    "type": "integer",
                    "minimum": -9007199254740991,
                    "maximum": 9007199254740991,
                },
            },
        },
    },
}
"""The profile's shape. Every object is closed, so a member this version does not define
cannot carry a meaning a verifier silently ignores, which is the PIC/TRACE bridge's rule.
Every time is in the RFC 8785 safe-integer range, for spec section 3.2.2's reason: the
artifact is digested over canonical bytes, and beyond that range two values share them. The
client data is not held to a closed set: it is WebAuthn's structure, not this profile's, and
WebAuthn requires a parser to be tolerant of members it does not know."""


def _ecma_pattern(
    validator: Any, pattern: str, instance: Any, schema: Any
) -> Iterator[jsonschema.ValidationError]:
    """ECMA-262 `$` matches only at the end of the input; Python's also matches before a
    final newline. Every pattern above uses `$` once, as its last character."""
    if validator.is_type(instance, "string") and not re.search(
        pattern.replace("$", r"\Z"), instance
    ):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


_ArtifactValidator = jsonschema.validators.extend(
    jsonschema.Draft202012Validator, {"pattern": _ecma_pattern}
)
VALIDATOR = _ArtifactValidator(ARTIFACT_SCHEMA)


# ---------------------------------------------------------------------------
# What a rule may read
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class View:
    """The artifact, the relying party's configuration, and the citing record if any.

    Every derived property decodes on demand. Nothing past the gate reads one before the
    gate has established that it decodes."""

    artifact: dict[str, Any]
    context: dict[str, Any]
    record: dict[str, Any] | None = None

    @property
    def approval(self) -> dict[str, Any]:
        return self.artifact["approval"]

    @property
    def assertion(self) -> dict[str, Any]:
        return self.artifact["assertion"]

    @property
    def credential(self) -> dict[str, Any] | None:
        """Exact lookup. A credential id is bytes written in base64url; there is no
        case-insensitive form of bytes."""
        return self.context["credentials"].get(self.approval["credential_id"])

    @property
    def authenticator_data(self) -> bytes:
        return _b64u_decode(self.assertion["authenticator_data"])

    @property
    def client_data_json(self) -> bytes:
        return _b64u_decode(self.assertion["client_data_json"])

    @property
    def client_data(self) -> Any:
        # WebAuthn's own step: UTF-8 decode, a leading byte order mark stripped, then parse.
        return json.loads(self.client_data_json.decode("utf-8-sig"))

    @property
    def flags(self) -> int:
        return self.authenticator_data[32]

    @property
    def sign_count(self) -> int:
        return int.from_bytes(self.authenticator_data[33:37], "big")

    @property
    def citation(self) -> dict[str, Any] | None:
        """The record's `approval-outcome` entry naming this approval, if it has one."""
        if self.record is None:
            return None
        for entry in self.record.get("references", []):
            if entry.get("rel") == "approval-outcome" and (
                entry.get("id") == self.approval["approval_id"]
            ):
                return dict(entry)
        return None


def _malformed(view: View, validator: Any = VALIDATOR, ordered: bool = True) -> bool:
    """Not the profile's shape: a schema error, a validity window that closes before it
    opens, or a member that does not decode into what the rules read, which is
    authenticator data of at least 37 bytes and client data that is a JSON object.

    The order is a shape check rather than part of the window rule because no clock can
    make an inverted window mean anything, and because the window rule's tolerance would
    otherwise admit one whose ends lie within the tolerance of the verifier's clock."""
    if any(validator.iter_errors(view.artifact)):
        return True
    if ordered and view.approval["expires_at"] <= view.approval["issued_at"]:
        return True
    try:
        authenticator_data = view.authenticator_data
        client_data = view.client_data
        _b64u_decode(view.assertion["signature"])
    except ValueError:
        return True
    return len(authenticator_data) < 37 or not isinstance(client_data, dict)


def expected_challenge(artifact: dict[str, Any]) -> str:
    """The profile's challenge: SHA-256 over the RFC 8785 form of both members, in
    base64url without padding, which is the encoding WebAuthn puts in `clientDataJSON`."""
    preimage = {"profile": artifact["profile"], "approval": artifact["approval"]}
    return _b64u(hashlib.sha256(rfc8785.dumps(preimage)).digest())


def _jcs_digest(value: Any, algorithm: str) -> str:
    return f"{algorithm}:" + hashlib.new(algorithm, rfc8785.dumps(value)).hexdigest()


# ---------------------------------------------------------------------------
# The rule registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """One named obligation. ``check`` returns True when the defect it guards against is
    observed: True means the code is emitted."""

    code: str
    klass: str  # "invalid" | "unverifiable" | "decision" | "advisory"
    stage: str  # "profile" | "shape" | "lookup" | "artifact" | "credential" | ...
    #             "signature" | "record", in the order `verify_approval` runs them
    check: Callable[[View], bool] = field(compare=False)


def _profile_not_supported(view: View) -> bool:
    return view.artifact.get("profile") != PROFILE


def _artifact_malformed(view: View) -> bool:
    return _malformed(view)


def _credential_unknown(view: View) -> bool:
    return view.credential is None


def _challenge_mismatch(view: View) -> bool:
    return view.client_data.get("challenge") != expected_challenge(view.artifact)


def _client_data_type(view: View) -> bool:
    return view.client_data.get("type") != "webauthn.get"


def _cross_origin_not_expected(view: View) -> bool:
    # WebAuthn checks each of these on its own; an approval page is not framed.
    client_data = view.client_data
    return client_data.get("crossOrigin") is True or "topOrigin" in client_data


def _user_not_present(view: View) -> bool:
    return not view.flags & UP


def _user_not_verified(view: View) -> bool:
    required = view.approval["decision"] == "allow" or view.context["policy"][
        "require_uv_for_deny"
    ]
    return bool(required) and not view.flags & UV


def _backup_state_inconsistent(view: View) -> bool:
    return not view.flags & BE and bool(view.flags & BS)


def _outside_validity_window(view: View) -> bool:
    skew, now = view.context["clock_skew_seconds"], view.context["now"]
    return not (
        view.approval["issued_at"] - skew <= now < view.approval["expires_at"] + skew
    )


def _decision_not_allow(view: View) -> bool:
    return view.approval["decision"] != "allow"


def _origin_not_expected(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    origin = view.client_data.get("origin")
    return origin not in credential["origins"] or origin != view.approval["origin"]


def _rp_id_mismatch(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    registered = credential["rp_id"]
    return view.approval["rp_id"] != registered or (
        view.authenticator_data[:32] != hashlib.sha256(registered.encode()).digest()
    )


def _approver_not_registered(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    return view.approval["approver"] != credential["approver"]


def _backup_eligibility_changed(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    recorded = credential.get("backup_eligible")
    return recorded is not None and recorded != bool(view.flags & BE)


def _algorithm_mismatch(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    return view.assertion["alg"] != credential["alg"]


def _algorithm_unsupported(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    return credential["alg"] not in view.context["supported_algorithms"]


def _counter_not_checked(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    return credential.get("sign_count") is None and view.sign_count != 0


def _counter_not_increasing(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    stored = credential.get("sign_count")
    if stored is None or (stored == 0 and view.sign_count == 0):
        return False
    return view.sign_count <= stored


def _signature_invalid(view: View) -> bool:
    credential = view.credential
    assert credential is not None
    message = view.authenticator_data + hashlib.sha256(view.client_data_json).digest()
    signature = _b64u_decode(view.assertion["signature"])
    return not _verifies(credential["public_key"], credential["alg"], signature, message)


def _reference_digest_mismatch(view: View) -> bool:
    citation = view.citation
    assert citation is not None
    if "digest" not in citation:
        # A citation with no digest is an open question in the RFC, not a finding here.
        return False
    algorithm = citation["digest"].split(":", 1)[0]
    if algorithm not in {"sha256", "sha384"}:
        # The two names the references schema admits; any other cannot be the digest.
        return True
    return bool(citation["digest"] != _jcs_digest(view.artifact, algorithm))


def _approval_key_is_record_key(view: View) -> bool:
    credential = view.credential
    assert view.record is not None
    if credential is None:
        return False
    return _key_material(credential["public_key"]) == _key_material(view.record["cnf"]["jwk"])


def _principal(view: View) -> str | None:
    """The approver as the verifier's identity policy resolves it: the approver identifier
    itself where it is the record's subject verbatim, which needs no directory to compare,
    and otherwise what the directory returns for it. None where the directory returns
    nothing, whether it has no entry or an entry that resolves to no one."""
    assert view.record is not None
    approver = view.approval["approver"]
    if approver == view.record["subject"]:
        return str(approver)
    resolved = view.context["identity"].get(approver)
    return resolved if isinstance(resolved, str) else None


def _approver_is_record_subject(view: View) -> bool:
    assert view.record is not None
    return _principal(view) == view.record["subject"]


def _approver_unresolved(view: View) -> bool:
    return _principal(view) is None


RULES: tuple[Rule, ...] = (
    # -- the gate: read nothing further if either fires ----------------------------------
    Rule("profile_not_supported", "unverifiable", "profile", _profile_not_supported),
    Rule("artifact_malformed", "invalid", "shape", _artifact_malformed),
    # -- the registry lookup ---------------------------------------------------------------
    Rule("credential_unknown", "unverifiable", "lookup", _credential_unknown),
    # -- the artifact and the relying party's policy ---------------------------------------
    Rule("challenge_mismatch", "invalid", "artifact", _challenge_mismatch),
    Rule("client_data_type", "invalid", "artifact", _client_data_type),
    Rule("cross_origin_not_expected", "invalid", "artifact", _cross_origin_not_expected),
    Rule("user_not_present", "invalid", "artifact", _user_not_present),
    Rule("user_not_verified", "invalid", "artifact", _user_not_verified),
    Rule("backup_state_inconsistent", "invalid", "artifact", _backup_state_inconsistent),
    Rule("outside_validity_window", "invalid", "artifact", _outside_validity_window),
    Rule("decision_not_allow", "decision", "artifact", _decision_not_allow),
    # -- against the registered credential -------------------------------------------------
    Rule("origin_not_expected", "invalid", "credential", _origin_not_expected),
    Rule("rp_id_mismatch", "invalid", "credential", _rp_id_mismatch),
    Rule("approver_not_registered", "invalid", "credential", _approver_not_registered),
    Rule("backup_eligibility_changed", "invalid", "credential", _backup_eligibility_changed),
    Rule("algorithm_mismatch", "invalid", "credential", _algorithm_mismatch),
    Rule("algorithm_unsupported", "unverifiable", "credential", _algorithm_unsupported),
    Rule("counter_not_checked", "advisory", "credential", _counter_not_checked),
    Rule("counter_not_increasing", "advisory", "credential", _counter_not_increasing),
    # -- the signature, when the verifier can compute it ----------------------------------
    Rule("signature_invalid", "invalid", "signature", _signature_invalid),
    # -- the record that cites the artifact ------------------------------------------------
    Rule("reference_digest_mismatch", "invalid", "record", _reference_digest_mismatch),
    Rule("approval_key_is_record_key", "invalid", "record", _approval_key_is_record_key),
    Rule("approver_is_record_subject", "invalid", "record", _approver_is_record_subject),
    Rule("approver_unresolved", "unverifiable", "record", _approver_unresolved),
)


def _evaluate(view: View, rules: Sequence[Rule], stage: str) -> list[str]:
    """The single point where rule codes are emitted.

    Everything the verifier reports flows through this loop, which is what makes the
    registry authoritative. `test_webauthn_approval_completeness` asserts by AST that no
    other function in this module appends to a code list.
    """
    codes: list[str] = []
    for rule in rules:
        if rule.stage == stage and rule.check(view):
            codes.append(rule.code)
    return codes


def _result(
    codes: list[str], rules: Sequence[Rule], attestation: str | None
) -> ApprovalResult:
    emitted = sorted(set(codes))
    classes = {rule.klass for rule in rules if rule.code in emitted}
    if "invalid" in classes:
        outcome = "approval-invalid"
    elif "unverifiable" in classes:
        outcome = "approval-unverifiable"
    elif "decision" in classes:
        outcome = "not-an-approval"
    else:
        outcome = "approval-valid"
    return ApprovalResult(outcome=outcome, codes=emitted, credential_attestation=attestation)


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------


def verify_approval(vector: dict[str, Any], rules: Sequence[Rule] = RULES) -> ApprovalResult:
    """Judge `vector["artifact"]` under `vector["context"]`, with its citing record if any.

    `credential_attestation` reports the grade the registry holds for the credential, and
    decides nothing: whether a self-asserted credential is enough is the relying party's
    policy, and the verifier's job is to say which it was.
    """
    view = View(vector["artifact"], vector["context"], vector.get("record"))
    declared = set(view.context["supported_algorithms"])
    if not declared <= IMPLEMENTED:
        raise ValueError(
            f"the configuration declares algorithms this verifier cannot compute: "
            f"{sorted(declared - IMPLEMENTED)}"
        )

    codes = _evaluate(view, rules, "profile")
    if view.artifact.get("profile") != PROFILE:
        return _result(codes, rules, None)
    codes += _evaluate(view, rules, "shape")
    if _malformed(view):
        return _result(codes, rules, None)

    codes += _evaluate(view, rules, "lookup")
    codes += _evaluate(view, rules, "artifact")
    credential = view.credential
    if credential is not None:
        codes += _evaluate(view, rules, "credential")
        if credential["alg"] in view.context["supported_algorithms"]:
            codes += _evaluate(view, rules, "signature")
    if view.citation is not None:
        codes += _evaluate(view, rules, "record")
    return _result(codes, rules, None if credential is None else credential["attestation"])


# ---------------------------------------------------------------------------
# The conformance run
# ---------------------------------------------------------------------------

VECTOR_PATHS = sorted(VECTOR_DIR.glob("*.json"))
CITED_PATHS = [p for p in VECTOR_PATHS if "record" in json.loads(p.read_text(encoding="utf-8"))]


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _vector(number: int) -> dict[str, Any]:
    (path,) = VECTOR_DIR.glob(f"{number:02d}-*.json")
    return _load(path)


def test_vector_set_is_complete() -> None:
    """A glob that silently loses a file passes every test parametrised on it."""
    assert [path.name for path in VECTOR_PATHS] == [
        "01-valid-es256.json",
        "02-valid-eddsa-no-counter.json",
        "03-valid-synced-passkey.json",
        "04-valid-cited-by-a-record.json",
        "05-valid-counter-zero-zero.json",
        "06-profile-next-version.json",
        "07-profile-of-another-artifact.json",
        "08-credential-not-registered.json",
        "09-credential-id-case-differs.json",
        "10-algorithm-not-supported-es384.json",
        "11-algorithm-outside-declared-set.json",
        "12-extra-member-carrying-a-key.json",
        "13-subject-digest-in-uppercase.json",
        "14-expiry-past-the-safe-integer-range.json",
        "15-window-inverted.json",
        "16-challenge-over-the-approval-alone.json",
        "17-approval-rewritten-after-the-ceremony.json",
        "18-challenge-with-padding.json",
        "19-type-is-create.json",
        "20-type-absent.json",
        "21-client-data-with-an-extra-member.json",
        "22-cross-origin-true.json",
        "23-top-origin-present.json",
        "24-origin-scheme-differs.json",
        "25-registered-origin-not-the-approved-one.json",
        "26-rp-id-not-registered.json",
        "27-rp-id-hash-of-another-domain.json",
        "28-approver-registered-to-another-credential.json",
        "29-approver-case-differs.json",
        "30-verified-but-not-present.json",
        "31-deny-with-no-flags.json",
        "32-allow-without-verification.json",
        "33-deny-without-verification-under-policy.json",
        "34-backup-state-with-eligibility-recorded-false.json",
        "35-backup-state-with-eligibility-unrecorded.json",
        "36-backup-eligibility-lost.json",
        "37-backup-eligibility-gained.json",
        "38-algorithm-differs-from-the-registry.json",
        "39-artifact-names-rs256.json",
        "40-signed-over-unhashed-client-data.json",
        "41-signed-by-another-credential.json",
        "42-at-expiry.json",
        "43-issued-in-the-future.json",
        "44-issued-within-the-clock-tolerance.json",
        "45-expired-within-the-clock-tolerance.json",
        "46-deny.json",
        "47-deny-cited-as-approval-outcome.json",
        "48-citation-digest-over-the-signed-approval.json",
        "49-approval-altered-after-issue.json",
        "50-resolver-holds-another-approval-under-the-id.json",
        "51-approval-key-is-the-record-key.json",
        "52-approval-key-is-the-record-key-with-kid.json",
        "53-approver-resolves-to-the-subject.json",
        "54-approver-is-the-subject.json",
        "55-approver-not-in-the-directory.json",
        "56-approver-deprovisioned-in-the-directory.json",
        "57-counter-state-absent.json",
        "58-counter-state-null.json",
        "59-counter-equal.json",
        "60-counter-lower.json",
        "61-profile-with-a-version-suffix.json",
        "62-nonce-shorter-than-16-bytes.json",
        "63-approval-id-outside-ascii.json",
        "64-type-is-payment-get.json",
        "65-origin-extends-the-registered-one.json",
        "66-deny-with-backup-state-and-no-eligibility.json",
        "67-registry-holds-the-fully-specified-identifier.json",
        "68-ecdsa-signature-in-raw-form.json",
        "69-client-data-with-insignificant-whitespace.json",
        "70-at-issuance.json",
        "71-synced-passkey-with-eligibility-unrecorded.json",
        "72-counter-reset-to-zero.json",
    ]


def test_vector_ids_match_their_filenames() -> None:
    for path in VECTOR_PATHS:
        vector = _load(path)
        number, name = path.stem.split("-", 1)
        assert vector["id"] == f"TRACE-WAPR-{int(number):03d}", path.name
        assert vector["name"] == name, path.name


def test_every_expected_block_is_declared_in_full() -> None:
    """Three members, codes sorted, and an outcome and grade drawn from the closed sets.
    A block that omitted the grade would pass a comparison that only reads the other two."""
    for path in VECTOR_PATHS:
        expected = _load(path)["expected"]
        assert set(expected) == {"outcome", "codes", "credential_attestation"}, path.name
        assert expected["outcome"] in OUTCOMES, path.name
        assert expected["codes"] == sorted(expected["codes"]), path.name
        assert expected["credential_attestation"] in {"attested", "self-asserted", None}


@pytest.mark.parametrize("path", VECTOR_PATHS, ids=lambda p: p.stem)
def test_vector_reaches_its_declared_outcome(path: Path) -> None:
    vector = _load(path)
    result = verify_approval(vector)
    expected = vector["expected"]
    observed = {
        "outcome": result.outcome,
        "codes": result.codes,
        "credential_attestation": result.credential_attestation,
    }
    assert observed == expected, f"{vector['id']} ({vector['name']})"


def test_the_corpus_exercises_every_outcome() -> None:
    produced = {verify_approval(_load(path)).outcome for path in VECTOR_PATHS}
    assert produced == OUTCOMES, f"never produced: {sorted(OUTCOMES - produced)}"


def test_only_the_five_shape_vectors_fail_the_shape() -> None:
    """Every artifact under this profile is schema-valid, decodes and has an ordered window,
    except the five built to fail the shape. A rule elsewhere must not be passing only
    because its vector is malformed in some louder way the gate would catch first."""
    malformed = {
        path.name
        for path in VECTOR_PATHS
        if _load(path)["artifact"].get("profile") == PROFILE
        and _malformed(View(_load(path)["artifact"], _load(path)["context"]))
    }
    assert malformed == {
        "12-extra-member-carrying-a-key.json",
        "13-subject-digest-in-uppercase.json",
        "14-expiry-past-the-safe-integer-range.json",
        "15-window-inverted.json",
        "62-nonce-shorter-than-16-bytes.json",
    }


@pytest.mark.parametrize("path", CITED_PATHS, ids=lambda p: p.stem)
def test_every_citing_record_is_a_valid_trust_record(path: Path) -> None:
    """Spec section 3.1.2 rule 3: what a reference resolves to never decides whether the
    record verifies. Each citing record is schema-valid and verifies under the producer's
    key whatever the artifact it points at turns out to be, the refusal and the three
    composition failures included."""
    vector = _load(path)
    record = vector["record"]
    assert not iter_errors(record), f"{vector['id']}: the record is not schema-valid"
    verify_record(record, vector["context"]["record_signer_jwk"], max_age_seconds=None)
    (entry,) = record["references"]
    assert entry["rel"] == "approval-outcome"
    assert entry["id"] == vector["artifact"]["approval"]["approval_id"]


def test_the_record_signature_covers_the_citation() -> None:
    vector = _vector(4)
    record = copy.deepcopy(vector["record"])
    digest = record["references"][0]["digest"]
    record["references"][0]["digest"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    with pytest.raises(InvalidSignature):
        verify_record(record, vector["context"]["record_signer_jwk"], max_age_seconds=None)


def test_the_unverifiable_signatures_are_genuine() -> None:
    """Vectors 10 and 11 are unverifiable because of what the verifier can compute, not
    because anything is wrong with them: each verifies under its registered key by an
    implementation that computes the algorithm."""
    for number in (10, 11):
        vector = _vector(number)
        view = View(vector["artifact"], vector["context"])
        credential = view.credential
        assert credential is not None
        message = view.authenticator_data + hashlib.sha256(view.client_data_json).digest()
        signature = _b64u_decode(view.assertion["signature"])
        assert _verifies(credential["public_key"], credential["alg"], signature, message)
        assert not _challenge_mismatch(view), f"vector {number}: the challenge is wrong"


def test_the_padded_challenge_is_the_right_bytes_in_the_wrong_string() -> None:
    """Vector 18 separates a comparison of strings from a comparison of decoded bytes
    only if it decodes to exactly the expected bytes. Pinned, so it cannot drift into
    being wrong in both readings."""
    vector = _vector(18)
    view = View(vector["artifact"], vector["context"])
    sent, wanted = view.client_data["challenge"], expected_challenge(vector["artifact"])
    assert sent != wanted and sent.rstrip("=") == wanted
    assert _b64u_decode(sent) == _b64u_decode(wanted)


def test_the_rewritten_approvals_still_carry_a_valid_signature() -> None:
    """Vectors 17 and 49 change the approval after the ceremony and nothing else, so the
    assertion still verifies. Only the challenge, and in 49 the record's digest, can see
    the change; a vector whose signature also broke would not show that."""
    for number in (17, 49):
        vector = _vector(number)
        view = View(vector["artifact"], vector["context"])
        credential = view.credential
        assert credential is not None
        message = view.authenticator_data + hashlib.sha256(view.client_data_json).digest()
        signature = _b64u_decode(view.assertion["signature"])
        assert _verifies(credential["public_key"], credential["alg"], signature, message)
        assert _challenge_mismatch(view)


def test_the_two_record_key_vectors_hold_one_key_written_two_ways() -> None:
    """51 and 52 register the record's own key as the approval credential. In 52 the
    registry's JWK carries `kid` and `alg`, so a comparison of whole objects separates
    them and a comparison of key material does not."""
    registered = []
    for number in (51, 52):
        vector = _vector(number)
        view = View(vector["artifact"], vector["context"], vector["record"])
        credential = view.credential
        assert credential is not None
        assert view.record is not None
        registered.append(credential["public_key"])
        assert _key_material(credential["public_key"]) == _key_material(
            view.record["cnf"]["jwk"]
        )
    plain, labelled = registered
    assert plain == _vector(51)["record"]["cnf"]["jwk"]
    assert labelled != plain and {k: labelled[k] for k in plain} == plain
    assert set(labelled) - set(plain) == {"kid", "alg"}


def test_the_two_counterless_vectors_differ_in_how_the_count_is_missing() -> None:
    """57 has no `sign_count` member and 58 has one that is null. Everything else about the
    ops lead's registry entry is the same, so an implementation that reads presence of
    the member as presence of state is the only thing the pair separates."""
    entries = []
    for number in (57, 58):
        vector = _vector(number)
        entries.append(vector["context"]["credentials"][vector["artifact"]["approval"][
            "credential_id"]])
    absent, null = entries
    assert "sign_count" not in absent and null["sign_count"] is None
    assert {k: v for k, v in null.items() if k != "sign_count"} == absent


def test_the_inverted_window_is_otherwise_an_approval() -> None:
    """Vector 15 is malformed for its order and nothing else. Both of its ends lie within
    the tolerance of the verifier's clock, so the window rule alone lets it through, and
    its signature and challenge are good. A vector that also failed the window would show
    nothing about where the order is checked."""
    vector = _vector(15)
    view = View(vector["artifact"], vector["context"])
    assert view.approval["expires_at"] < view.approval["issued_at"]
    assert _malformed(view) and not _malformed(view, ordered=False)
    assert not _outside_validity_window(view)
    assert not _challenge_mismatch(view)
    credential = view.credential
    assert credential is not None
    message = view.authenticator_data + hashlib.sha256(view.client_data_json).digest()
    signature = _b64u_decode(view.assertion["signature"])
    assert _verifies(credential["public_key"], credential["alg"], signature, message)


def test_the_extra_client_data_member_is_really_there() -> None:
    """Vector 21 is the control for WebAuthn's tolerance of client data members it does not
    define. Pinned, so that it cannot drift into having none."""
    view = View(_vector(21)["artifact"], _vector(21)["context"])
    defined = {"type", "challenge", "origin", "crossOrigin", "topOrigin", "tokenBinding"}
    assert set(view.client_data) - defined


def test_the_reissued_approval_is_valid_without_the_record() -> None:
    """Vector 50's artifact is a good approval under the same identifier as the one the
    record cited, reissued with a new nonce and subject. Only the record's digest can tell
    them apart, so without the record it is valid, and with it only W-21 fires."""
    vector = _vector(50)
    alone = {key: value for key, value in vector.items() if key != "record"}
    assert verify_approval(alone).outcome == "approval-valid"
    citation = View(vector["artifact"], vector["context"], vector["record"]).citation
    assert citation is not None
    assert citation["id"] == vector["artifact"]["approval"]["approval_id"]


def test_the_two_unresolved_approvers_differ_in_how_the_directory_answers() -> None:
    """55's approver has no entry in the directory and 56's has one that resolves to no one,
    as a deprovisioned account does. An implementation that reads an entry's presence as a
    resolution is the only thing the pair separates."""
    missing, deprovisioned = (_vector(number) for number in (55, 56))
    approver = missing["artifact"]["approval"]["approver"]
    assert approver not in missing["context"]["identity"]
    approver = deprovisioned["artifact"]["approval"]["approver"]
    assert approver in deprovisioned["context"]["identity"]
    assert deprovisioned["context"]["identity"][approver] is None


def test_every_other_cited_approver_resolves() -> None:
    """W-24 is load-bearing only if it is silent everywhere else a record cites an approval.
    Every cited vector apart from 55 and 56 names an approver the directory resolves, or the
    record's subject itself."""
    for path in CITED_PATHS:
        if path.name[:2] in {"55", "56"}:
            continue
        vector = _load(path)
        assert not _approver_unresolved(
            View(vector["artifact"], vector["context"], vector["record"])
        ), path.name


def _registered(view: View) -> dict[str, Any]:
    credential = view.credential
    assert credential is not None
    return credential


def _signed_over(
    view: View, signature: bytes, client_data: bytes | None = None, alg: int | None = None
) -> bool:
    credential = _registered(view)
    data = view.client_data_json if client_data is None else client_data
    message = view.authenticator_data + hashlib.sha256(data).digest()
    return _verifies(credential["public_key"], alg or credential["alg"], signature, message)


def test_the_near_miss_vectors_isolate_what_they_are_about() -> None:
    """Vectors 61 to 72 each close one shortcut the first sixty let through. Each is pinned
    to the one property it is about, so none can drift into failing, or passing, for a
    louder reason than the shortcut."""
    def view(number: int) -> View:
        vector = _vector(number)
        return View(vector["artifact"], vector["context"], vector.get("record"))

    # 61: the identifier with a suffix, over an otherwise sound approval.
    suffixed = view(61)
    assert suffixed.artifact["profile"] == PROFILE + ".1"
    assert not _challenge_mismatch(suffixed)
    assert _signed_over(suffixed, _b64u_decode(suffixed.assertion["signature"]))
    # 62: a 15-byte nonce, and nothing else wrong with the artifact.
    short = view(62)
    assert len(_b64u_decode(short.approval["nonce"])) == 15
    assert not _challenge_mismatch(short)
    assert _signed_over(short, _b64u_decode(short.assertion["signature"]))
    # 63: an identifier outside ASCII, where escaping serializers derive another challenge.
    outside = view(63)
    assert not outside.approval["approval_id"].isascii()
    escaped = json.dumps({"profile": PROFILE, "approval": outside.approval},
                         sort_keys=True, separators=(",", ":")).encode()
    assert _b64u(hashlib.sha256(escaped).digest()) != expected_challenge(outside.artifact)
    # 65: the origin begins with the registered one.
    extended_origin = view(65)
    assert extended_origin.client_data["origin"].startswith("https://approvals.example.org")
    assert extended_origin.client_data["origin"] not in _registered(extended_origin)["origins"]
    # 67: the registry names -19, and the signature is Ed25519 under the registered key.
    aliased = view(67)
    assert _registered(aliased)["alg"] == -19 and aliased.assertion["alg"] == EDDSA
    assert _signed_over(aliased, _b64u_decode(aliased.assertion["signature"]), alg=EDDSA)
    # 68: the right r and s, in the fixed-length encoding.
    raw = view(68)
    signature = _b64u_decode(raw.assertion["signature"])
    assert len(signature) == 64 and not _signed_over(raw, signature)
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                               int.from_bytes(signature[32:], "big"))
    assert _signed_over(raw, der)
    # 69: the client data bytes carry whitespace a re-serialization would drop.
    spaced = view(69)
    assert b'", "' in spaced.client_data_json
    compact = json.dumps(spaced.client_data, separators=(",", ":")).encode()
    signature = _b64u_decode(spaced.assertion["signature"])
    assert _signed_over(spaced, signature) and not _signed_over(spaced, signature, compact)
    # 71: eligibility unrecorded, BE and BS set.
    unrecorded = view(71)
    assert "backup_eligible" not in _registered(unrecorded)
    assert unrecorded.flags & BE and unrecorded.flags & BS
    # 72: a reported zero against a stored four.
    reset = view(72)
    assert reset.sign_count == 0 and _registered(reset)["sign_count"] == 4


def test_key_identity_is_the_thumbprint_members_of_each_key_type() -> None:
    """W-22 compares keys, not JWK objects, and a key is what its thumbprint covers. Two
    different RSA keys, or two different AKP keys, have no `crv`, `x` or `y` to differ in,
    so a comparison of the EC members would call them one key."""
    rsa = {"kty": "RSA", "n": "0vx7agoebGcQSuu", "e": "AQAB"}
    akp = {"kty": "AKP", "alg": "ML-DSA-65", "pub": "unH59k4RuutY"}
    unknown = {"kty": "X-FUTURE", "k": "AAAB"}
    for key, member in ((rsa, "n"), (akp, "pub"), (unknown, "k")):
        other = {**key, member: key[member][::-1]}
        assert _key_material(key) != _key_material(other), key["kty"]
    for key in (rsa, akp):
        assert _key_material({**key, "kid": "k-1"}) == _key_material(key), key["kty"]


def test_two_different_rsa_keys_are_not_one_key_under_w22() -> None:
    """Vector 04 with the credential and the record's `cnf` both RSA and different. The
    verifier cannot compute RS256, so the approval is unverifiable; it is not an approval
    signed with the record's key. The same RSA key on both sides is."""
    vector = copy.deepcopy(_vector(4))
    artifact, context, record = vector["artifact"], vector["context"], vector["record"]
    rsa = {"kty": "RSA", "n": "0vx7agoebGcQSuu", "e": "AQAB"}
    artifact["assertion"]["alg"] = -257
    credential = context["credentials"][artifact["approval"]["credential_id"]]
    credential.update(public_key=rsa, alg=-257)
    record["references"][0]["digest"] = _jcs_digest(artifact, "sha256")
    record["cnf"]["jwk"] = {**rsa, "n": rsa["n"][::-1]}
    assert verify_approval(vector) == ApprovalResult(
        "approval-unverifiable", ["algorithm_unsupported"], "attested")
    record["cnf"]["jwk"] = {**rsa, "kid": "producer"}
    assert verify_approval(vector) == ApprovalResult(
        "approval-invalid", ["algorithm_unsupported", "approval_key_is_record_key"], "attested")


def test_a_citation_digest_under_another_name_does_not_match() -> None:
    """The references schema admits `sha256` and `sha384`. A digest under any other name is
    not the artifact's digest, and naming an algorithm the verifier has never heard of is
    a mismatch, not an error."""
    vector = copy.deepcopy(_vector(4))
    reference = vector["record"]["references"][0]
    for digest in ("md5:" + hashlib.md5(rfc8785.dumps(vector["artifact"])).hexdigest(),
                   "blake9:00"):
        reference["digest"] = digest
        assert verify_approval(vector).codes == ["reference_digest_mismatch"], digest


def test_dollar_in_a_pattern_is_the_end_of_the_input() -> None:
    """Python's `$` matches before a final newline, and a base64url member with one
    appended would decode to the same bytes. The shape check reads `$` as ECMA-262 does."""
    artifact = copy.deepcopy(_vector(1)["artifact"])
    artifact["approval"]["credential_id"] += "\n"
    assert _malformed(View(artifact, _vector(1)["context"]))


def test_a_configuration_claiming_an_algorithm_it_cannot_compute_is_refused() -> None:
    """Declaring support for an algorithm the verifier does not implement would turn a
    genuine signature into `signature_invalid`, an accusation in place of an admission."""
    vector = copy.deepcopy(_vector(1))
    vector["context"]["supported_algorithms"] = [-7, -257]
    with pytest.raises(ValueError, match="cannot compute"):
        verify_approval(vector)


CAPTURE = VECTOR_DIR / "browser-capture" / "browser-capture.json"


def test_a_browser_captured_approval_verifies() -> None:
    """Every vector's client data and authenticator data are constructed. This artifact's
    are a browser's: Chromium with a DevTools virtual authenticator, asked for an assertion
    over a challenge derived as RFC section 3.1 says. It is not a vector, since its key and
    nonce are fresh on every capture, and it is judged here as a vector would be, with two
    tamperings that must fail for the acceptance to mean anything."""
    capture = _load(CAPTURE)
    client_data_json = _b64u_decode(capture["artifact"]["assertion"]["client_data_json"])
    assert json.loads(client_data_json) == capture["client_data_decoded"]
    assert verify_approval(capture) == ApprovalResult(
        outcome="approval-valid", codes=[], credential_attestation="self-asserted"
    )

    later = copy.deepcopy(capture)
    later["artifact"]["approval"]["expires_at"] += 86400
    assert verify_approval(later).codes == ["challenge_mismatch"]

    flipped = copy.deepcopy(capture)
    signature = bytearray(_b64u_decode(flipped["artifact"]["assertion"]["signature"]))
    signature[-1] ^= 1
    flipped["artifact"]["assertion"]["signature"] = _b64u(bytes(signature))
    assert verify_approval(flipped).codes == ["signature_invalid"]
