"""Generate portable verifier-compatibility vectors (agentrust-io/trace-spec#116).

Implementation-agnostic JSON: each fixture carries a signed record, the profile set
the verifier declares, and the outcome any conformant verifier must produce. Nothing
in the fixture names a language or an API.

Deterministic key, so the set regenerates byte-for-byte. Public test material.
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

OUT = Path("examples/verifier-compatibility")
PROFILE = "trace.verifier_compatibility.proposal.v0"
V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"
V0_1 = "tag:agentrust.io,2026:trace-v0.1"
FUTURE = "tag:agentrust-io.com,2031:trace-v9.9"

SEED = hashlib.sha256(b"trace-spec#116 verifier-compatibility fixture key").digest()
KEY = Ed25519PrivateKey.from_private_bytes(SEED)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_jwk() -> dict[str, str]:
    raw = KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


BASE_RECORD: dict[str, Any] = {
    "eat_profile": V0_2,
    # Fixed, so the fixture is reproducible. Verifiers running these vectors must
    # disable the freshness check or supply this instant as "now"; version skew is
    # the property under test, not staleness.
    "iat": 1785000000,
    "subject": "spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "anthropic", "model_id": "claude-sonnet-4-6"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    "transparency": "https://rekor.example/api/v1/log/entries/0",
    "cnf": {"jwk": public_jwk()},
}


def signed_record(profile: str) -> dict[str, Any]:
    """A genuinely signed record carrying *profile*.

    Every fixture's signature is valid. That is the point: the question these
    vectors ask is never "does the signature check out", it is "does this verifier
    implement the semantics the record was written under".
    """
    record = copy.deepcopy(BASE_RECORD)
    record["eat_profile"] = profile
    body = rfc8785.dumps(record)
    return {**record, "signature": b64u(KEY.sign(body))}


def fixture(
    name: str,
    description: str,
    *,
    record_profile: str,
    accepted_profiles: list[str],
    expected: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "profile": PROFILE,
        "proposal": {
            "issue": "agentrust-io/trace-spec#116",
            "status": "under review — not accepted normative text",
        },
        "verifier": {
            "accepted_profiles": accepted_profiles,
            "verification_time": 1785000100,
            "check_freshness": False,
        },
        "trusted_key": public_jwk(),
        "record": signed_record(record_profile),
        "expected": expected,
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fixtures = [
        (
            "01-known-version-verified.json",
            fixture(
                "known-version-verified",
                "The record's profile is in the verifier's accepted set. Verification "
                "succeeds and the statement names the profile it ran under.",
                record_profile=V0_2,
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "verified",
                    "failure": None,
                    "statement": {
                        "profile": V0_2,
                        "accepted_profiles": [V0_2],
                        "downgraded": False,
                    },
                },
            ),
        ),
        (
            "02-unknown-version-refused.json",
            fixture(
                "unknown-version-refused",
                "A future profile the verifier does not implement. The signature is "
                "valid and the record must still be refused: fail-open here means "
                "verifying semantics the build does not implement.",
                record_profile=FUTURE,
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "refused",
                    "failure": "profile_not_accepted",
                    "statement": None,
                },
            ),
        ),
        (
            "03-superseded-version-refused.json",
            fixture(
                "superseded-version-refused",
                "The v0.1 identifier. spec/trace-v0.2.md requires a v0.2 verifier to "
                "reject it and forbids accepting both, so this must refuse even though "
                "the older profile is well known.",
                record_profile=V0_1,
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "refused",
                    "failure": "profile_not_accepted",
                    "statement": None,
                },
            ),
        ),
        (
            "04-downgrade-disclosed.json",
            fixture(
                "downgrade-disclosed",
                "The verifier declares support for an older profile as well, and the "
                "record uses it. Conformant, because the fallback is visible: the "
                "statement carries the full accepted set and marks the run as "
                "downgraded.",
                record_profile=V0_1,
                accepted_profiles=[V0_2, V0_1],
                expected={
                    "outcome": "verified",
                    "failure": None,
                    "statement": {
                        "profile": V0_1,
                        "accepted_profiles": [V0_2, V0_1],
                        "downgraded": True,
                    },
                },
            ),
        ),
        (
            "05-downgrade-silent-is-impossible.json",
            fixture(
                "downgrade-silent-is-impossible",
                "The same older record against a verifier that did not declare the "
                "older profile. There must be no outcome in which verification "
                "succeeds under a profile absent from the accepted set: silent "
                "fallback is the failure this vector exists to forbid.",
                record_profile=V0_1,
                accepted_profiles=[V0_2],
                expected={
                    "outcome": "refused",
                    "failure": "profile_not_accepted",
                    "statement": None,
                },
            ),
        ),
        (
            "06-empty-accepted-set-refused.json",
            fixture(
                "empty-accepted-set-refused",
                "A verifier that declares no supported profile verifies nothing. An "
                "empty set must not be read as 'accept anything'.",
                record_profile=V0_2,
                accepted_profiles=[],
                expected={
                    "outcome": "refused",
                    "failure": "no_accepted_profiles",
                    "statement": None,
                },
            ),
        ),
    ]

    for filename, doc in fixtures:
        (OUT / filename).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print("wrote", OUT / filename)

    # 07 has no profile at all, so it cannot be produced by signed_record's profile arg.
    missing = fixture(
        "profile-absent-refused",
        "A record with no profile claim. A verifier cannot supply the semantics by "
        "assumption, so this refuses rather than defaulting to the current version.",
        record_profile=V0_2,
        accepted_profiles=[V0_2],
        expected={
            "outcome": "refused",
            "failure": "profile_absent",
            "statement": None,
        },
    )
    record = copy.deepcopy(BASE_RECORD)
    del record["eat_profile"]
    body = rfc8785.dumps(record)
    missing["record"] = {**record, "signature": b64u(KEY.sign(body))}
    (OUT / "07-profile-absent-refused.json").write_text(
        json.dumps(missing, indent=2) + "\n", encoding="utf-8"
    )
    print("wrote", OUT / "07-profile-absent-refused.json")


if __name__ == "__main__":
    main()
