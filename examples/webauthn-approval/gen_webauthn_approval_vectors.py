"""Generate examples/webauthn-approval: approval artifacts signed by a WebAuthn assertion.

Each vector is one artifact, the relying party's configuration it is judged under and,
where the artifact is cited, a signed Trust Record that points at it with
`rel: "approval-outcome"`. The rules the vectors exercise are proposed in
`docs/rfcs/webauthn-approval-profile.md`; nothing here is normative until they are.

The artifact is an approval object and a WebAuthn authentication assertion. An
authenticator signs `authenticatorData || SHA-256(clientDataJSON)` and never sees the
relying party's object, so the object can enter the signed bytes only through the
challenge: the relying party sets the challenge to the SHA-256 of the RFC 8785 form of
`{"profile": ..., "approval": ...}`, and the client writes its base64url encoding into
`clientDataJSON`. A verifier recomputes it from the artifact alone.

Every assertion here carries a real signature, by a software key derived from the seed;
none was captured from a browser or a hardware authenticator. The authenticator data is
constructed, in the WebAuthn Level 3 layout: the SHA-256 of the RP ID, one flags byte and
a four-byte big-endian signature counter. ES256 and ES384 are signed with deterministic
ECDSA (RFC 6979) so that the set regenerates byte for byte, and
tests/test_generators_reproduce_fixtures.py holds the committed files to this script.

Every key derives from one published seed by label, so anyone can reissue any vector.
Each vector's `expected` block is written by hand in the case table below. The reference
verifier is tests/test_webauthn_approval_vectors.py, and this script does not import it:
an expectation computed by the code it is meant to check would check nothing.

The approved object itself is not committed. `subject_digest` is a labelled derivation
from the seed, because no rule in the profile reads the object: whether the executed
action is the approved one is the enforcing component's comparison, not the verifier's.

Usage: python examples/webauthn-approval/gen_webauthn_approval_vectors.py [--out DIR]
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentrust_trace import key_to_jwk, sign_record

SEED = b"trace-spec examples/webauthn-approval 2026-09-22"
HERE = Path(__file__).resolve().parent
SPEC = "docs/rfcs/webauthn-approval-profile.md"

PROFILE = "tag:agentrust-io.com,2026:webauthn-approval-v1"
NEXT_PROFILE = "tag:agentrust-io.com,2026:webauthn-approval-v2"
BRIDGE_PROFILE = "tag:agentrust-io.com,2026:pic-trace-bridge-v1"

RP_ID = "approvals.example.org"
ORIGIN = "https://approvals.example.org"
REVIEW_ORIGIN = "https://review.approvals.example.org"
SUBJECT = "spiffe://trust.example.org/agent/build-bot"
RESOLVER = "https://approvals.example.org/approvals"
RETENTION = "P10Y"

NOW = int(datetime(2026, 9, 22, 9, 0, tzinfo=UTC).timestamp())
ISSUED_AT = NOW - 120
EXPIRES_AT = NOW + 480
RECORD_IAT = NOW - 60

# COSE algorithm identifiers. ED25519 is RFC 9864's fully specified name for WebAuthn's -8.
ES256, EDDSA, ES384, RS256, ED25519 = -7, -8, -35, -257, -19

# Authenticator data flags: user present, user verified, backup eligible, backed up.
UP, UV, BE, BS = 0x01, 0x04, 0x08, 0x10

ABSENT = object()
"""Marks a member to remove, where `None` would write `null`."""


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jcs_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def derived(label: str) -> bytes:
    return hashlib.sha256(SEED + b"|" + label.encode()).digest()


PRODUCER = Ed25519PrivateKey.from_private_bytes(derived("key|producer"))
SUBJECT_DIGEST = "sha256:" + derived("subject|payments-service deploy 2.4.1").hex()


@dataclass(frozen=True)
class Credential:
    """A WebAuthn credential and what the relying party registered about it.

    `counter` is what the authenticator reports on its next assertion, `sign_count` the
    value the relying party last stored, and `None` there means it holds no state.
    """

    label: str
    alg: int
    approver: str
    attestation: str
    counter: int
    origins: tuple[str, ...] = (ORIGIN,)
    backup_eligible: bool | None = None
    sign_count: int | None = None

    @property
    def credential_id(self) -> str:
        return b64u(derived("credential|" + self.label)[:16])

    @property
    def key(self) -> Any:
        if self.label == "producer":
            return PRODUCER
        if self.alg == EDDSA:
            return Ed25519PrivateKey.from_private_bytes(derived("key|" + self.label))
        # Below 2**255, so valid on both curves without knowing either order.
        scalar = int.from_bytes(derived("key|" + self.label), "big") >> 1
        curve = ec.SECP384R1() if self.alg == ES384 else ec.SECP256R1()
        return ec.derive_private_key(scalar, curve)

    @property
    def jwk(self) -> dict[str, str]:
        if self.alg == EDDSA:
            return key_to_jwk(self.key)
        numbers = self.key.public_key().public_numbers()
        size = (self.key.curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": "P-384" if self.alg == ES384 else "P-256",
            "x": b64u(numbers.x.to_bytes(size, "big")),
            "y": b64u(numbers.y.to_bytes(size, "big")),
        }


OPS_LEAD = Credential(
    "ops-lead", ES256, "approver-ops-lead", "attested", counter=5,
    origins=(ORIGIN, REVIEW_ORIGIN), backup_eligible=False, sign_count=4,
)
REVIEWER = Credential("reviewer", EDDSA, "approver-reviewer", "self-asserted", counter=0)
AUDITOR = Credential(
    "auditor", ES256, "approver-auditor", "attested", counter=0,
    backup_eligible=False, sign_count=0,
)
RELEASE_MANAGER = Credential(
    "release-manager", ES384, "approver-release-manager", "attested", counter=13,
    backup_eligible=False, sign_count=12,
)
ON_CALL = Credential(
    "on-call", ES256, "approver-on-call", "self-asserted", counter=0,
    backup_eligible=True, sign_count=0,
)
# Registered only in the vectors that need them.
BUILD_OPERATOR = Credential("producer", EDDSA, "approver-build-operator", "self-asserted", 0)
ENROLLED_BY_AGENT = Credential(
    "enrolled-by-the-agent", ES256, "approver-7c1d", "self-asserted", counter=1, sign_count=0,
)
NAMED_FOR_AGENT = Credential(
    "named-for-the-agent", ES256, SUBJECT, "self-asserted", counter=1, sign_count=0,
)
VISITING_AUDITOR = Credential(
    "visiting-auditor", ES256, "approver-visiting-auditor", "self-asserted", counter=1,
    sign_count=0,
)
FORMER_CONTRACTOR = Credential(
    "former-contractor", ES256, "approver-former-contractor", "self-asserted", counter=1,
    sign_count=0,
)
# Never registered.
CONTRACTOR = Credential("contractor", ES256, "approver-contractor", "self-asserted", 1)

REGISTERED = (OPS_LEAD, REVIEWER, AUDITOR, RELEASE_MANAGER, ON_CALL)

IDENTITY = {
    "approver-ops-lead": "https://idp.example.org/users/ops-lead",
    "approver-reviewer": "https://idp.example.org/users/reviewer",
    "approver-auditor": "https://idp.example.org/users/auditor",
    "approver-release-manager": "https://idp.example.org/users/release-manager",
    "approver-on-call": "https://idp.example.org/users/on-call",
    "approver-build-operator": "https://idp.example.org/users/build-operator",
    # A credential enrolled by the agent's own workload identity.
    "approver-7c1d": SUBJECT,
}


def registry_entry(credential: Credential, changes: dict[str, Any]) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "public_key": credential.jwk,
        "alg": credential.alg,
        "rp_id": RP_ID,
        "origins": list(credential.origins),
        "approver": credential.approver,
        "attestation": credential.attestation,
    }
    if credential.backup_eligible is not None:
        entry["backup_eligible"] = credential.backup_eligible
    if credential.sign_count is not None:
        entry["sign_count"] = credential.sign_count
    for member, value in changes.items():
        if value is ABSENT:
            entry.pop(member, None)
        else:
            entry[member] = value
    return entry


def context(
    *,
    extra: tuple[Credential, ...] = (),
    changes: dict[str, dict[str, Any]] | None = None,
    supported: tuple[int, ...] = (ES256, EDDSA),
    require_uv_for_deny: bool = False,
    clock_skew: int = 0,
    identity: dict[str, Any] | None = None,
    cited: bool = False,
) -> dict[str, Any]:
    """What the relying party holds: its clock, policy, algorithms, registry and directory."""
    changes = changes or {}
    value: dict[str, Any] = {
        "now": NOW,
        "clock_skew_seconds": clock_skew,
        "policy": {"require_uv_for_deny": require_uv_for_deny},
        "supported_algorithms": list(supported),
        "credentials": {
            c.credential_id: registry_entry(c, changes.get(c.label, {}))
            for c in (*REGISTERED, *extra)
        },
        "identity": {**IDENTITY, **(identity or {})},
    }
    if cited:
        value["record_signer_jwk"] = key_to_jwk(PRODUCER)
    return value


def approval(credential: Credential, name: str, **changes: Any) -> dict[str, Any]:
    value = {
        "approval_id": f"approval/{name}",
        "decision": "allow",
        "approver": credential.approver,
        "credential_id": credential.credential_id,
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "subject_kind": "pic-trace-bridge-authorization",
        "subject_digest": SUBJECT_DIGEST,
        "nonce": b64u(derived("nonce|" + name)[:16]),
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
    }
    value.update(changes)
    return value


def challenge(profile: str, approval: dict[str, Any]) -> str:
    """The profile's challenge: base64url, unpadded, of the digest of both members."""
    return b64u(hashlib.sha256(rfc8785.dumps({"profile": profile, "approval": approval})).digest())


def challenge_over_the_approval_alone(profile: str, approval: dict[str, Any]) -> str:
    return b64u(hashlib.sha256(rfc8785.dumps(approval)).digest())


def challenge_with_padding(profile: str, approval: dict[str, Any]) -> str:
    digest = hashlib.sha256(rfc8785.dumps({"profile": profile, "approval": approval})).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def challenge_without_the_integer_range(profile: str, approval: dict[str, Any]) -> str:
    """What a producer whose serializer does not enforce the integer range would sign.

    The `rfc8785` library refuses an integer past 2**53 - 1 rather than emit bytes that a
    neighbouring integer shares, as spec section 3.2.2 records. For this ASCII object,
    sorted keys without whitespace are the bytes RFC 8785 as written would give.
    """
    preimage = json.dumps({"profile": profile, "approval": approval},
                          sort_keys=True, separators=(",", ":"))
    return b64u(hashlib.sha256(preimage.encode()).digest())


def sign(key: Any, alg: int, message: bytes) -> bytes:
    if alg == EDDSA:
        return bytes(key.sign(message))
    digest = hashes.SHA384() if alg == ES384 else hashes.SHA256()
    try:
        return bytes(key.sign(message, ec.ECDSA(digest, deterministic_signing=True)))
    except (TypeError, UnsupportedAlgorithm) as exc:
        raise SystemExit(
            "this generator needs deterministic ECDSA (RFC 6979) from `cryptography`; "
            f"without it the fixtures cannot be reproduced byte for byte ({exc})"
        ) from exc


def assertion(
    signer: Credential,
    challenge_value: str,
    *,
    origin: str,
    rp_id: str,
    flags: int = UP | UV,
    counter: int | None = None,
    alg: int | None = None,
    client_data_changes: dict[str, Any] | None = None,
    hash_client_data: bool = True,
    client_data_separators: tuple[str, str] = (",", ":"),
) -> dict[str, Any]:
    """One authentication ceremony, performed by `signer`'s authenticator."""
    client_data: dict[str, Any] = {
        "type": "webauthn.get",
        "challenge": challenge_value,
        "origin": origin,
        "crossOrigin": False,
    }
    for member, value in (client_data_changes or {}).items():
        if value is ABSENT:
            client_data.pop(member)
        else:
            client_data[member] = value
    client_data_json = json.dumps(client_data, separators=client_data_separators).encode()
    count = signer.counter if counter is None else counter
    authenticator_data = (
        hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")
    )
    signed = authenticator_data + (
        hashlib.sha256(client_data_json).digest() if hash_client_data else client_data_json
    )
    return {
        "authenticator_data": b64u(authenticator_data),
        "client_data_json": b64u(client_data_json),
        "signature": b64u(sign(signer.key, signer.alg, signed)),
        "alg": signer.alg if alg is None else alg,
    }


def artifact(
    credential: Credential,
    name: str,
    *,
    profile: str = PROFILE,
    approval_changes: dict[str, Any] | None = None,
    challenge_rule: Callable[[str, dict[str, Any]], str] = challenge,
    signer: Credential | None = None,
    origin: str | None = None,
    rp_id: str | None = None,
    **ceremony: Any,
) -> dict[str, Any]:
    """An approval by `credential` and the ceremony over it, consistent unless told not to be.

    The client data's origin and the hashed RP ID default to the ones the approval names,
    so a vector departs from the approval only where it says so.
    """
    value = approval(credential, name, **(approval_changes or {}))
    return {
        "profile": profile,
        "approval": value,
        "assertion": assertion(
            signer or credential,
            challenge_rule(profile, value),
            origin=origin or value["origin"],
            rp_id=rp_id or value["rp_id"],
            **ceremony,
        ),
    }


def record_citing(cited: dict[str, Any], digest: str | None = None) -> dict[str, Any]:
    """A signed v0.2 Trust Record pointing at `cited` as its `approval-outcome`."""
    reference = {
        "rel": "approval-outcome",
        "id": cited["approval"]["approval_id"],
        "resolver": RESOLVER,
        "digest": digest or jcs_sha256(cited),
        "retention": RETENTION,
    }
    unsigned = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": RECORD_IAT,
        "subject": SUBJECT,
        "model": {"provider": "example", "model_id": "example-model"},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
        "policy": {"bundle_hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "build_provenance": {"slsa_level": 1, "digest": "sha256:" + "e" * 64},
        "appraisal": {"status": "none", "verifier": "https://verifier.example.org"},
        "cnf": {"jwk": key_to_jwk(PRODUCER)},
        "references": [reference],
    }
    return sign_record(unsigned, PRODUCER)


def raw_ecdsa(value: dict[str, Any], size: int = 32) -> dict[str, Any]:
    """`value` with its DER ECDSA signature rewritten as the fixed-length r and s."""
    altered = copy.deepcopy(value)
    der = base64.urlsafe_b64decode(altered["assertion"]["signature"] + "==")
    r, s = decode_dss_signature(der)
    altered["assertion"]["signature"] = b64u(r.to_bytes(size, "big") + s.to_bytes(size, "big"))
    return altered


def extended(value: dict[str, Any]) -> dict[str, Any]:
    """`value` with its approval's expiry moved a day later, after the ceremony."""
    altered = copy.deepcopy(value)
    altered["approval"]["expires_at"] += 86400
    return altered


VALID = "approval-valid"
DENIED = "not-an-approval"
INVALID = "approval-invalid"
UNVERIFIABLE = "approval-unverifiable"


def build() -> dict[str, dict[str, Any]]:
    a, b = OPS_LEAD, REVIEWER
    cases: list[tuple[str, str, dict[str, Any], dict[str, Any], dict[str, Any] | None,
                      tuple[str, list[str], str | None]]] = []

    def case(
        name: str,
        description: str,
        value: dict[str, Any],
        expected: tuple[str, list[str], str | None],
        *,
        ctx: dict[str, Any] | None = None,
        record: dict[str, Any] | None = None,
    ) -> None:
        cases.append(
            (name, description, ctx or context(cited=record is not None), value, record, expected)
        )

    # -- controls ------------------------------------------------------------------------
    case("valid-es256",
         "The control most vectors are built from: an allow signed by a registered, attested "
         "security key (ES256), with user presence and user verification, inside its "
         "validity window, and a counter above the one the relying party holds.",
         artifact(a, "valid-es256"), (VALID, [], "attested"))
    case("valid-eddsa-no-counter",
         "An allow signed by a registered platform passkey (EdDSA) that reports a counter of "
         "zero, for which the relying party holds no counter state. The counter comparison "
         "runs only when either count is nonzero, so there is nothing to report.",
         artifact(b, "valid-eddsa-no-counter"), (VALID, [], "self-asserted"))
    case("valid-synced-passkey",
         "An allow from a synced passkey: backup eligible and backed up, BE and BS both set, "
         "from a credential the registry records as backup eligible. Backup state describes "
         "the credential and is not a defect in it.",
         artifact(ON_CALL, "valid-synced-passkey", flags=UP | UV | BE | BS),
         (VALID, [], "self-asserted"))
    cited = artifact(a, "valid-cited-by-a-record")
    case("valid-cited-by-a-record",
         "An allow cited by a signed Trust Record as `approval-outcome`, with the RFC 8785 "
         "SHA-256 of the whole artifact as the reference's digest. The approval key is not "
         "the record's key and the approver does not resolve to the record's subject.",
         cited, (VALID, [], "attested"), record=record_citing(cited))
    case("valid-counter-zero-zero",
         "An authenticator that reports a counter of zero to a relying party that stored "
         "zero. The comparison runs only when either value is nonzero, so zero after zero "
         "is not a regression.",
         artifact(AUDITOR, "valid-counter-zero-zero"), (VALID, [], "attested"))

    # -- what the verifier cannot read ---------------------------------------------------
    case("profile-next-version",
         "A well-formed artifact under the next version of this profile. A verifier that "
         "implements v1 cannot read v2 and says so rather than reading it as v1.",
         artifact(a, "profile-next-version", profile=NEXT_PROFILE),
         (UNVERIFIABLE, ["profile_not_supported"], None))
    case("profile-of-another-artifact",
         "An artifact carrying the PIC/TRACE bridge's profile identifier. Refused by exact "
         "and by prefix matching alike, which is what leaves the previous vector as the one "
         "that tells them apart.",
         artifact(a, "profile-of-another-artifact", profile=BRIDGE_PROFILE),
         (UNVERIFIABLE, ["profile_not_supported"], None))
    case("credential-not-registered",
         "Signed by a key the relying party never registered, under a credential id it "
         "does not hold. There is nothing to check the signature against, so the approval "
         "is unverifiable, not forged.",
         artifact(CONTRACTOR, "credential-not-registered"),
         (UNVERIFIABLE, ["credential_unknown"], None))
    case("credential-id-case-differs",
         "Signed by the ops lead's credential, naming its id with the case of every letter "
         "inverted. A credential id is bytes written in base64url, so the lookup is exact "
         "and this id names no registered credential.",
         artifact(a, "credential-id-case-differs",
                  approval_changes={"credential_id": a.credential_id.swapcase()}),
         (UNVERIFIABLE, ["credential_unknown"], None))
    case("algorithm-not-supported-es384",
         "Signed by a registered ES384 credential, judged by a verifier whose declared set is "
         "ES256 and EdDSA. The signature is real; ES384 is outside what the verifier declares "
         "it can compute, so it reports that it did not check it.",
         artifact(RELEASE_MANAGER, "algorithm-not-supported-es384"),
         (UNVERIFIABLE, ["algorithm_unsupported"], "attested"))
    case("algorithm-outside-declared-set",
         "An EdDSA approval judged by a verifier whose declared set is ES256 alone. Under "
         "the default set the same construction is the control in vector 02, so the outcome "
         "is a fact about the verifier.",
         artifact(b, "algorithm-outside-declared-set"),
         (UNVERIFIABLE, ["algorithm_unsupported"], "self-asserted"),
         ctx=context(supported=(ES256,)))

    # -- the artifact's shape -----------------------------------------------------------
    carrying = artifact(a, "extra-member-carrying-a-key", signer=CONTRACTOR)
    carrying["public_key"] = CONTRACTOR.jwk
    case("extra-member-carrying-a-key",
         "Names the ops lead's credential, is signed by an unregistered key, and carries "
         "that key as a top-level `public_key`. Every object is closed, so the extra member "
         "makes the artifact malformed before any key is read; a verifier that used it "
         "would find the signature valid.",
         carrying, (INVALID, ["artifact_malformed"], None))
    case("subject-digest-in-uppercase",
         "The approved object's digest in uppercase hexadecimal, signed as written. The "
         "pattern admits lowercase only, so one digest has one signable spelling.",
         artifact(a, "subject-digest-in-uppercase",
                  approval_changes={"subject_digest": "sha256:" + SUBJECT_DIGEST[7:].upper()}),
         (INVALID, ["artifact_malformed"], None))
    case("expiry-past-the-safe-integer-range",
         "`expires_at` is 2**53, one past the range spec section 3.2.2 holds every "
         "canonicalized integer to: past it, two integers can canonicalize to the same "
         "bytes. The challenge was derived by a serializer that does not enforce the range.",
         artifact(a, "expiry-past-the-safe-integer-range",
                  approval_changes={"expires_at": 2**53},
                  challenge_rule=challenge_without_the_integer_range),
         (INVALID, ["artifact_malformed"], None))
    case("window-inverted",
         "`expires_at` is a minute before `issued_at`. Under the sixty seconds of clock "
         "tolerance this relying party allows, a check of `now` against each end alone passes "
         "it; a window has to be a window before either end is compared with anything.",
         artifact(a, "window-inverted",
                  approval_changes={"issued_at": NOW + 30, "expires_at": NOW - 30}),
         (INVALID, ["artifact_malformed"], None), ctx=context(clock_skew=60))

    # -- the challenge --------------------------------------------------------------------
    case("challenge-over-the-approval-alone",
         "The relying party derived the challenge from `approval` without `profile`. The "
         "signature is valid and the challenge is not the one this profile defines.",
         artifact(a, "challenge-over-the-approval-alone",
                  challenge_rule=challenge_over_the_approval_alone),
         (INVALID, ["challenge_mismatch"], "attested"))
    case("approval-rewritten-after-the-ceremony",
         "The ceremony signed the approval as issued, and `expires_at` was then moved a day "
         "later. The assertion still verifies, because the authenticator never saw the "
         "approval; only the challenge ties the two together.",
         extended(artifact(a, "approval-rewritten-after-the-ceremony")),
         (INVALID, ["challenge_mismatch"], "attested"))
    case("challenge-with-padding",
         "The client data carries the right digest in base64url with its `=` padding. "
         "WebAuthn compares the challenge with the base64url encoding of the expected bytes, "
         "a comparison of strings, so this is a mismatch although it decodes to those bytes.",
         artifact(a, "challenge-with-padding", challenge_rule=challenge_with_padding),
         (INVALID, ["challenge_mismatch"], "attested"))

    # -- the client data ------------------------------------------------------------------
    case("type-is-create",
         "The client data's `type` is `webauthn.create`: a registration ceremony's client "
         "data under an authentication assertion.",
         artifact(a, "type-is-create", client_data_changes={"type": "webauthn.create"}),
         (INVALID, ["client_data_type"], "attested"))
    case("type-absent",
         "The client data has no `type` member, so it says nothing about which ceremony "
         "produced it.",
         artifact(a, "type-absent", client_data_changes={"type": ABSENT}),
         (INVALID, ["client_data_type"], "attested"))
    case("client-data-with-an-extra-member",
         "The client data carries a member no rule reads, `extraData`, as the test vectors in "
         "WebAuthn Level 3 section 16 do. The client data may be extended, so a parser "
         "tolerates unknown keys: the artifact's objects are closed and the client data is "
         "not.",
         artifact(a, "client-data-with-an-extra-member",
                  client_data_changes={"extraData": "clientDataJSON may be extended with "
                                                    "additional fields in the future"}),
         (VALID, [], "attested"))
    case("cross-origin-true",
         "`crossOrigin` is true: the ceremony ran in an iframe that is not same-origin with "
         "its ancestors, and an approval page is not expected to be framed.",
         artifact(a, "cross-origin-true", client_data_changes={"crossOrigin": True}),
         (INVALID, ["cross_origin_not_expected"], "attested"))
    case("top-origin-present",
         "`crossOrigin` is false and `topOrigin` names a top-level page anyway. WebAuthn "
         "checks `topOrigin` whenever it is present, whatever the flag says.",
         artifact(a, "top-origin-present",
                  client_data_changes={"topOrigin": "https://portal.example.net"}),
         (INVALID, ["cross_origin_not_expected"], "attested"))
    case("origin-scheme-differs",
         "The approval and the client data both name `http://approvals.example.org`, and "
         "the credential is registered for the `https` origin. An origin is a scheme, a "
         "host and a port, not a host.",
         artifact(a, "origin-scheme-differs",
                  approval_changes={"origin": "http://approvals.example.org"}),
         (INVALID, ["origin_not_expected"], "attested"))
    case("registered-origin-not-the-approved-one",
         "The client data names the second origin the credential is registered for, and "
         "the signed approval names the first. The approval says where the ceremony was to "
         "happen, and it happened somewhere else.",
         artifact(a, "registered-origin-not-the-approved-one", origin=REVIEW_ORIGIN),
         (INVALID, ["origin_not_expected"], "attested"))
    case("rp-id-not-registered",
         "The approval names RP ID `example.org`, a registrable suffix of the origin, and the "
         "authenticator data hashes the same RP ID. The two agree with each other, and "
         "neither is the RP ID the credential is registered for.",
         artifact(a, "rp-id-not-registered", approval_changes={"rp_id": "example.org"}),
         (INVALID, ["rp_id_mismatch"], "attested"))
    case("rp-id-hash-of-another-domain",
         "The approval names the registered RP ID, and the authenticator data carries the "
         "hash of another domain. The signature covers that authenticator data, so it "
         "verifies, and only the hash comparison catches this.",
         artifact(a, "rp-id-hash-of-another-domain", rp_id="payments.example.org"),
         (INVALID, ["rp_id_mismatch"], "attested"))
    case("approver-registered-to-another-credential",
         "Signed by the ops lead's credential and naming as approver the identifier "
         "registered to the reviewer's. The signature shows who approved and the artifact "
         "says someone else did.",
         artifact(a, "approver-registered-to-another-credential",
                  approval_changes={"approver": b.approver}),
         (INVALID, ["approver_not_registered"], "attested"))
    case("approver-case-differs",
         "Signed by the ops lead's credential, naming its approver with different case. "
         "An approver identifier is opaque and compared exactly.",
         artifact(a, "approver-case-differs",
                  approval_changes={"approver": "Approver-Ops-Lead"}),
         (INVALID, ["approver_not_registered"], "attested"))

    # -- the authenticator flags ----------------------------------------------------------
    case("verified-but-not-present",
         "UV set and UP clear. Every assertion needs UP, and user verification does not "
         "imply presence.",
         artifact(a, "verified-but-not-present", flags=UV),
         (INVALID, ["user_not_present"], "attested"))
    case("deny-with-no-flags",
         "A deny with neither UP nor UV. The default policy does not require user "
         "verification for a deny, so presence is the flag this vector turns on, and without "
         "it the refusal is invalid rather than a valid refusal.",
         artifact(a, "deny-with-no-flags", approval_changes={"decision": "deny"}, flags=0),
         (INVALID, ["decision_not_allow", "user_not_present"], "attested"))
    case("allow-without-verification",
         "An allow with UP and without UV. An allow is an approval, and the profile requires "
         "user verification for every approval.",
         artifact(a, "allow-without-verification", flags=UP),
         (INVALID, ["user_not_verified"], "attested"))
    case("deny-without-verification-under-policy",
         "A deny with UP and without UV, under a policy that requires user verification for "
         "denials as well.",
         artifact(a, "deny-without-verification-under-policy",
                  approval_changes={"decision": "deny"}, flags=UP),
         (INVALID, ["decision_not_allow", "user_not_verified"], "attested"),
         ctx=context(require_uv_for_deny=True))
    case("backup-state-with-eligibility-recorded-false",
         "BS set and BE clear, from a credential the registry records as not backup "
         "eligible. BS without BE fails whatever the registry records.",
         artifact(a, "backup-state-with-eligibility-recorded-false", flags=UP | UV | BS),
         (INVALID, ["backup_state_inconsistent"], "attested"))
    case("backup-state-with-eligibility-unrecorded",
         "BS set and BE clear, from a credential whose eligibility the registry does not "
         "record. The rule reads the flags, not the registry.",
         artifact(b, "backup-state-with-eligibility-unrecorded", flags=UP | UV | BS),
         (INVALID, ["backup_state_inconsistent"], "self-asserted"))
    case("backup-eligibility-lost",
         "The registry records the credential as backup eligible and the assertion has BE "
         "clear. Eligibility is fixed when a credential is created.",
         artifact(ON_CALL, "backup-eligibility-lost", flags=UP | UV),
         (INVALID, ["backup_eligibility_changed"], "self-asserted"))
    case("backup-eligibility-gained",
         "The registry records the credential as not backup eligible and the assertion has "
         "BE set: a device-bound credential now reporting that it can be synced.",
         artifact(a, "backup-eligibility-gained", flags=UP | UV | BE),
         (INVALID, ["backup_eligibility_changed"], "attested"))

    # -- the signature --------------------------------------------------------------------
    case("algorithm-differs-from-the-registry",
         "The artifact's `alg` names EdDSA; the registry holds ES256 for the credential and "
         "the signature is ES256. The registry's algorithm is the one that counts.",
         artifact(a, "algorithm-differs-from-the-registry", alg=EDDSA),
         (INVALID, ["algorithm_mismatch"], "attested"))
    case("artifact-names-rs256",
         "The artifact's `alg` names RS256, which this verifier does not implement; the "
         "registry holds ES256 and the signature is ES256.",
         artifact(a, "artifact-names-rs256", alg=RS256),
         (INVALID, ["algorithm_mismatch"], "attested"))
    case("signed-over-unhashed-client-data",
         "The authenticator data followed by the client data itself, signed without "
         "hashing the client data first.",
         artifact(a, "signed-over-unhashed-client-data", hash_client_data=False),
         (INVALID, ["signature_invalid"], "attested"))
    case("signed-by-another-credential",
         "Everything in the approval names the ops lead's credential, and the assertion was "
         "signed by the auditor's key, with the counter the ops lead's authenticator would "
         "have reported.",
         artifact(a, "signed-by-another-credential", signer=AUDITOR, counter=a.counter),
         (INVALID, ["signature_invalid"], "attested"))

    # -- the validity window --------------------------------------------------------------
    case("at-expiry",
         "`now` equals `expires_at`. The window is half-open, so an approval stops being "
         "usable at `expires_at`, not a second later.",
         artifact(a, "at-expiry",
                  approval_changes={"issued_at": NOW - 600, "expires_at": NOW}),
         (INVALID, ["outside_validity_window"], "attested"))
    case("issued-in-the-future",
         "`issued_at` is a minute after `now`: an approval issued after the moment it is "
         "being judged.",
         artifact(a, "issued-in-the-future",
                  approval_changes={"issued_at": NOW + 60, "expires_at": NOW + 660}),
         (INVALID, ["outside_validity_window"], "attested"))
    case("issued-within-the-clock-tolerance",
         "`issued_at` is thirty seconds after `now`, and the verifier tolerates sixty seconds "
         "of clock skew. The tolerance widens the window at its start.",
         artifact(a, "issued-within-the-clock-tolerance",
                  approval_changes={"issued_at": NOW + 30, "expires_at": NOW + 630}),
         (VALID, [], "attested"), ctx=context(clock_skew=60))
    case("expired-within-the-clock-tolerance",
         "`expires_at` is thirty seconds before `now`, under the same sixty seconds of "
         "tolerance. The tolerance widens the window at its end as well.",
         artifact(a, "expired-within-the-clock-tolerance",
                  approval_changes={"issued_at": NOW - 630, "expires_at": NOW - 30}),
         (VALID, [], "attested"), ctx=context(clock_skew=60))

    # -- the decision ---------------------------------------------------------------------
    case("deny",
         "A validly signed deny. Nothing is wrong with the artifact, and it is not an "
         "approval.",
         artifact(a, "deny", approval_changes={"decision": "deny"}),
         (DENIED, ["decision_not_allow"], "attested"))
    refusal = artifact(a, "deny-cited-as-approval-outcome",
                       approval_changes={"decision": "deny"})
    case("deny-cited-as-approval-outcome",
         "A validly signed deny, cited by a signed record as `approval-outcome` with a "
         "matching digest. The digest establishes which artifact was cited, and that "
         "artifact is a refusal.",
         refusal, (DENIED, ["decision_not_allow"], "attested"), record=record_citing(refusal))

    # -- the citing record ----------------------------------------------------------------
    partial = artifact(a, "citation-digest-over-the-signed-approval")
    case("citation-digest-over-the-signed-approval",
         "The record's digest is over `{profile, approval}`, the challenge pre-image, rather "
         "than the whole artifact. It identifies the approval and not the assertion, so any "
         "other assertion over the same approval would match it.",
         partial, (INVALID, ["reference_digest_mismatch"], "attested"),
         record=record_citing(partial, jcs_sha256(
             {"profile": partial["profile"], "approval": partial["approval"]})))
    issued = artifact(a, "approval-altered-after-issue")
    case("approval-altered-after-issue",
         "The record cited the artifact as issued, and its `expires_at` was then extended "
         "in the copy the resolver holds. The digest and the challenge each catch it on "
         "their own.",
         extended(issued), (INVALID, ["challenge_mismatch", "reference_digest_mismatch"],
                            "attested"),
         record=record_citing(issued))
    first = artifact(a, "resolver-holds-another-approval-under-the-id")
    reissued = artifact(a, "resolver-holds-another-approval-under-the-id", approval_changes={
        "nonce": b64u(derived("nonce|reissued")[:16]),
        "subject_digest": "sha256:" + derived("subject|payments-service deploy 2.4.2").hex(),
    })
    case("resolver-holds-another-approval-under-the-id",
         "The record cited one approval, and the resolver now returns another the relying "
         "party issued under the same `approval_id`, for another object and validly signed. "
         "Only the record's digest says it is not the approval the record acted under.",
         reissued, (INVALID, ["reference_digest_mismatch"], "attested"),
         record=record_citing(first))
    own = artifact(BUILD_OPERATOR, "approval-key-is-the-record-key")
    case("approval-key-is-the-record-key",
         "The approval credential's public key is the key that signs the record, so the "
         "producer that issued the record also approved it, and the approval adds no party.",
         own, (INVALID, ["approval_key_is_record_key"], "self-asserted"),
         ctx=context(extra=(BUILD_OPERATOR,), cited=True), record=record_citing(own))
    own_with_kid = artifact(BUILD_OPERATOR, "approval-key-is-the-record-key-with-kid")
    labelled = {**BUILD_OPERATOR.jwk, "kid": "build-operator-passkey", "alg": "EdDSA"}
    case("approval-key-is-the-record-key-with-kid",
         "The same key, registered with `kid` and `alg` members on its JWK. Two JWKs that "
         "differ only in advisory members hold the same key.",
         own_with_kid, (INVALID, ["approval_key_is_record_key"], "self-asserted"),
         ctx=context(extra=(BUILD_OPERATOR,), changes={"producer": {"public_key": labelled}},
                     cited=True),
         record=record_citing(own_with_kid))
    enrolled = artifact(ENROLLED_BY_AGENT, "approver-resolves-to-the-subject")
    case("approver-resolves-to-the-subject",
         "The approver identifier is opaque, and the relying party's directory resolves it "
         "to the record's subject: the agent enrolled a credential for itself.",
         enrolled, (INVALID, ["approver_is_record_subject"], "self-asserted"),
         ctx=context(extra=(ENROLLED_BY_AGENT,), cited=True), record=record_citing(enrolled))
    named = artifact(NAMED_FOR_AGENT, "approver-is-the-subject")
    case("approver-is-the-subject",
         "The approver identifier is the record's subject, verbatim.",
         named, (INVALID, ["approver_is_record_subject"], "self-asserted"),
         ctx=context(extra=(NAMED_FOR_AGENT,), cited=True), record=record_citing(named))
    visiting = artifact(VISITING_AUDITOR, "approver-not-in-the-directory")
    case("approver-not-in-the-directory",
         "The credential is registered, the approval is valid, and the directory does not "
         "list the approver, so nothing establishes that the approver is not the record's "
         "subject.",
         visiting, (UNVERIFIABLE, ["approver_unresolved"], "self-asserted"),
         ctx=context(extra=(VISITING_AUDITOR,), cited=True), record=record_citing(visiting))
    former = artifact(FORMER_CONTRACTOR, "approver-deprovisioned-in-the-directory")
    case("approver-deprovisioned-in-the-directory",
         "The directory lists the approver with no principal: an account deprovisioned since "
         "the credential was registered. A listed approver with nothing behind it resolves "
         "to no one.",
         former, (UNVERIFIABLE, ["approver_unresolved"], "self-asserted"),
         ctx=context(extra=(FORMER_CONTRACTOR,), identity={FORMER_CONTRACTOR.approver: None},
                     cited=True),
         record=record_citing(former))

    # -- the signature counter ------------------------------------------------------------
    case("counter-state-absent",
         "The relying party holds no counter for the ops lead's credential, and the "
         "authenticator reports 5. Nothing is wrong and nothing was compared, and the "
         "outcome says the second.",
         artifact(a, "counter-state-absent"), (VALID, ["counter_not_checked"], "attested"),
         ctx=context(changes={"ops-lead": {"sign_count": ABSENT}}))
    case("counter-state-null",
         "The same, with the registry's `sign_count` present and null. A null is not a "
         "stored count.",
         artifact(a, "counter-state-null"), (VALID, ["counter_not_checked"], "attested"),
         ctx=context(changes={"ops-lead": {"sign_count": None}}))
    case("counter-equal",
         "The authenticator reports the count the relying party already holds. WebAuthn "
         "calls this a signal and leaves the decision to the relying party, so it is "
         "reported and decides nothing.",
         artifact(a, "counter-equal", counter=4),
         (VALID, ["counter_not_increasing"], "attested"))
    case("counter-lower",
         "The authenticator reports a count below the one the relying party holds.",
         artifact(a, "counter-lower", counter=2),
         (VALID, ["counter_not_increasing"], "attested"))

    # -- one more vector per rule, each for a shortcut the vectors above let through -------
    case("profile-with-a-version-suffix",
         "The profile identifier with `.1` appended. A verifier that matches its own "
         "identifier as a prefix reads this as v1; the identifier is compared exactly.",
         artifact(a, "profile-with-a-version-suffix", profile=PROFILE + ".1"),
         (UNVERIFIABLE, ["profile_not_supported"], None))
    case("nonce-shorter-than-16-bytes",
         "The nonce is 15 bytes. The challenge is exactly as unpredictable as the nonce, so "
         "the shape holds the nonce to the 16 bytes WebAuthn Level 3 section 13.4.3 "
         "recommends for a challenge.",
         artifact(a, "nonce-shorter-than-16-bytes", approval_changes={
             "nonce": b64u(derived("nonce|nonce-shorter-than-16-bytes")[:15])}),
         (INVALID, ["artifact_malformed"], None))
    case("approval-id-outside-ascii",
         "The approval's identifier carries characters outside ASCII. RFC 8785 writes them as "
         "UTF-8; a serializer that escapes them, as Python's `json.dumps` does by default, "
         "derives another challenge, which spec section 3.2.2 names as insufficient.",
         artifact(a, "approval-id-outside-ascii",
                  approval_changes={"approval_id": "approval/déploiement-2.4.1"}),
         (VALID, [], "attested"))
    case("type-is-payment-get",
         "The client data's `type` is `payment.get`, the type Secure Payment Confirmation "
         "gives its own assertions. This profile's ceremony is a plain authentication, and a "
         "payment confirmation is not an approval under it.",
         artifact(a, "type-is-payment-get", client_data_changes={"type": "payment.get"}),
         (INVALID, ["client_data_type"], "attested"))
    case("origin-extends-the-registered-one",
         "The approval and the client data both name "
         "`https://approvals.example.org.attacker.example`, which begins with the registered "
         "origin and is another host. An origin is compared whole, never as a prefix.",
         artifact(a, "origin-extends-the-registered-one", approval_changes={
             "origin": "https://approvals.example.org.attacker.example"}),
         (INVALID, ["origin_not_expected"], "attested"))
    case("deny-with-backup-state-and-no-eligibility",
         "A deny with BS set and BE clear. The flags are inconsistent whatever the decision, "
         "so the refusal is invalid rather than a valid refusal.",
         artifact(a, "deny-with-backup-state-and-no-eligibility",
                  approval_changes={"decision": "deny"}, flags=UP | UV | BS),
         (INVALID, ["backup_state_inconsistent", "decision_not_allow"], "attested"))
    case("registry-holds-the-fully-specified-identifier",
         "The registry holds the reviewer's credential under -19, the fully specified "
         "identifier RFC 9864 registered for Ed25519, and the artifact names -8. Within "
         "WebAuthn the two mean the same algorithm; this profile compares identifiers "
         "exactly, which its open question 8 asks about.",
         artifact(b, "registry-holds-the-fully-specified-identifier"),
         (INVALID, ["algorithm_mismatch", "algorithm_unsupported"], "self-asserted"),
         ctx=context(changes={"reviewer": {"alg": ED25519}}))
    case("ecdsa-signature-in-raw-form",
         "The ES256 signature as the 64 bytes of r and s, the form JOSE uses, instead of the "
         "ASN.1 DER that WebAuthn Level 3 section 6.5.5 requires of an assertion. The same "
         "two numbers in another encoding are not a WebAuthn signature.",
         raw_ecdsa(artifact(a, "ecdsa-signature-in-raw-form")),
         (INVALID, ["signature_invalid"], "attested"))
    case("client-data-with-insignificant-whitespace",
         "The client data serialized with a space after each separator, and signed as "
         "serialized. The signature covers the bytes the client produced, so a verifier "
         "hashes those bytes, never a re-serialization of what it parsed.",
         artifact(a, "client-data-with-insignificant-whitespace",
                  client_data_separators=(", ", ": ")),
         (VALID, [], "attested"))
    case("at-issuance",
         "`now` equals `issued_at`. The window is closed at its start, so an approval is "
         "usable from the second it is issued.",
         artifact(a, "at-issuance",
                  approval_changes={"issued_at": NOW, "expires_at": NOW + 600}),
         (VALID, [], "attested"))
    case("synced-passkey-with-eligibility-unrecorded",
         "A synced passkey, BE and BS set, whose backup eligibility the registry never "
         "recorded. With nothing recorded there is nothing for the flag to contradict.",
         artifact(b, "synced-passkey-with-eligibility-unrecorded", flags=UP | UV | BE | BS),
         (VALID, [], "self-asserted"))
    case("counter-reset-to-zero",
         "The authenticator reports 0 to a relying party that holds 4. A counter that falls "
         "to zero is a counter that went down: zero is exempt only after zero.",
         artifact(a, "counter-reset-to-zero", counter=0),
         (VALID, ["counter_not_increasing"], "attested"))

    files: dict[str, dict[str, Any]] = {}
    for number, (name, description, ctx, value, record, expected) in enumerate(cases, 1):
        vector: dict[str, Any] = {
            "id": f"TRACE-WAPR-{number:03d}",
            "name": name,
            "description": description,
            "spec": SPEC,
            "context": ctx,
            "artifact": value,
        }
        if record is not None:
            vector["record"] = record
        outcome, codes, attestation = expected
        vector["expected"] = {
            "outcome": outcome,
            "codes": sorted(codes),
            "credential_attestation": attestation,
        }
        files[f"{number:02d}-{name}.json"] = vector
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    files = build()
    for name, value in files.items():
        text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
        (out / name).write_bytes(text.encode("utf-8"))
    print(f"{len(files)} files written to {out}")


if __name__ == "__main__":
    main()
