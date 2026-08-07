"""Portable verifier-compatibility vectors (agentrust-io/trace-spec#116).

These fixtures encode behaviour that is **proposed and under review**, not accepted
normative text.

Unlike the vectors in `test_sign.py`, nothing here is written against this library's
API: each fixture states a signed record, the profile set a verifier declares, and
the outcome any conformant verifier must produce. This module is the adapter that
runs them against `agentrust_trace`; another implementation writes its own adapter
and runs the same JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentrust_trace import verify_record

FIXTURE_DIR = Path(__file__).parent.parent / "examples" / "verifier-compatibility"
PROFILE = "trace.verifier_compatibility.proposal.v0"

# Failure labels are part of the vector contract, so they must not be matched against
# prose that is free to change. Each maps to a fragment this implementation emits.
FAILURE_MARKERS = {
    "profile_not_accepted": "not in this verifier's accepted set",
    "profile_absent": "no 'eat_profile'",
    "no_accepted_profiles": "accepted_profiles is empty",
    "superseded_profile_in_accepted_set": "superseded v0.1 identifier",
}

V0_1 = "tag:agentrust.io,2026:trace-v0.1"

FIXTURE_PATHS = sorted(FIXTURE_DIR.glob("*.json"))


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vector_set_is_complete() -> None:
    assert [path.name for path in FIXTURE_PATHS] == [
        "01-known-version-verified.json",
        "02-unknown-version-refused.json",
        "03-superseded-version-refused.json",
        "04-downgrade-disclosed.json",
        "05-downgrade-silent-is-impossible.json",
        "06-empty-accepted-set-refused.json",
        "07-profile-absent-refused.json",
        "08-dual-accept-configuration-refused.json",
    ]


@pytest.mark.parametrize("fixture_path", FIXTURE_PATHS, ids=lambda path: path.stem)
def test_verifier_compatibility_vector(fixture_path: Path) -> None:
    fixture = _load(fixture_path)

    assert fixture["profile"] == PROFILE
    assert fixture["proposal"]["issue"] == "agentrust-io/trace-spec#116"
    assert "not accepted normative text" in fixture["proposal"]["status"]

    verifier = fixture["verifier"]
    expected = fixture["expected"]
    # Freshness is disabled by every vector: version skew is the property under test,
    # and a fixed iat would otherwise make the set expire.
    assert verifier["check_freshness"] is False

    if expected["outcome"] == "refused":
        with pytest.raises(ValueError) as excinfo:
            verify_record(
                fixture["record"],
                fixture["trusted_key"],
                max_age_seconds=None,
                accepted_profiles=verifier["accepted_profiles"],
            )
        marker = FAILURE_MARKERS[expected["failure"]]
        assert marker in str(excinfo.value), (
            f"{fixture_path.name}: refused for the wrong reason. "
            f"expected {expected['failure']!r}, got: {excinfo.value}"
        )
        return

    statement = verify_record(
        fixture["record"],
        fixture["trusted_key"],
        max_age_seconds=None,
        accepted_profiles=verifier["accepted_profiles"],
    )
    want = expected["statement"]
    assert statement.profile == want["profile"]
    assert list(statement.accepted_profiles) == want["accepted_profiles"]

    # "Downgraded" is a property of the vector, not of this API: the run used a
    # profile other than the newest the verifier declared. A conformant verifier has
    # to be able to report it, however it names the field.
    downgraded = statement.profile != want["accepted_profiles"][0]
    assert downgraded == want["downgraded"]


def test_every_fixture_signature_is_genuine() -> None:
    """No vector may pass or fail because its signature was malformed.

    All seven records are correctly signed. If one were not, a "refused" expectation
    could be satisfied by the signature check rather than by the profile rule, and the
    vector would silently stop testing what it claims to test.
    """
    for path in FIXTURE_PATHS:
        fixture = _load(path)
        record = fixture["record"]
        profile = record.get("eat_profile")
        # Records this library refuses on configuration alone — no profile, or the
        # superseded v0.1 identifier, which no accepted set may contain — cannot have
        # their signatures checked through verify_record at all. Every record in this
        # directory, including those, is re-verified through an independent
        # cryptographic path by test_fixture_signatures_independent.py.
        if not profile or profile == V0_1:
            continue
        # Accept whatever this record carries, so only the signature can fail here.
        verify_record(
            record,
            fixture["trusted_key"],
            max_age_seconds=None,
            accepted_profiles=[profile],
        )
