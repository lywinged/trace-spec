"""validate_json and iter_errors against canonical examples."""

import json
from pathlib import Path

import pytest

from agentrust_trace import SCHEMA, TrustRecord, iter_errors, validate_json

REPO_ROOT = Path(__file__).parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"
NORMATIVE_SCHEMA = REPO_ROOT / "schema" / "trace-claim.json"
PACKAGED_SCHEMA = REPO_ROOT / "src" / "agentrust_trace" / "schema" / "trace-v0.2.json"


def _load(name: str) -> dict:
    # Examples must validate exactly as published: no preprocessing.
    return json.loads((EXAMPLES_DIR / name).read_text())


@pytest.mark.parametrize("filename", ["intel-tdx.json", "amd-sev-snp.json", "nvidia-h100.json"])
def test_examples_pass_json_schema(filename: str) -> None:
    validate_json(_load(filename))


def test_iter_errors_empty_on_valid() -> None:
    assert iter_errors(_load("intel-tdx.json")) == []


def test_invalid_eat_profile_fails() -> None:
    data = _load("intel-tdx.json")
    data["eat_profile"] = "wrong-profile"
    errors = iter_errors(data)
    assert errors, "expected at least one schema error"


def test_missing_required_field_fails() -> None:
    data = _load("intel-tdx.json")
    del data["subject"]
    errors = iter_errors(data)
    assert errors


def test_schema_is_dict() -> None:
    assert isinstance(SCHEMA, dict)
    assert SCHEMA.get("title") == "TRACE Trust Record"


def test_comment_key_fails() -> None:
    """additionalProperties is false: a _comment key must be rejected, including in examples."""
    data = _load("intel-tdx.json")
    data["_comment"] = "human note"
    errors = iter_errors(data)
    assert errors


def test_okp_jwk_without_key_material_fails() -> None:
    """cnf.jwk must carry key material: OKP requires crv and x."""
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {"kty": "OKP"}
    errors = iter_errors(data)
    assert errors


def test_ec_jwk_without_y_fails() -> None:
    """cnf.jwk must carry key material: EC requires crv, x, and y."""
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {"kty": "EC", "crv": "P-256", "x": "dGVzdA"}
    errors = iter_errors(data)
    assert errors


def test_okp_jwk_with_key_material_passes() -> None:
    data = _load("intel-tdx.json")
    data["cnf"]["jwk"] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }
    assert iter_errors(data) == []


def test_delegation_passes_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {
        "parent_record_hash": "sha256:" + "a" * 64,
        "credential_id": "cred-abc",
    }
    assert iter_errors(data) == []


def test_delegation_bad_digest_fails_json_schema() -> None:
    data = _load("intel-tdx.json")
    data["delegation"] = {"parent_record_hash": "nope", "credential_id": "c"}
    assert iter_errors(data)


def test_packaged_schema_matches_normative_schema() -> None:
    """The packaged schema must be a copy of ``schema/trace-claim.json``.

    ``validate_json`` loads the packaged copy, while the spec, README, and
    CONTRIBUTING all point at the root file as normative. When the two drift, the
    schema a caller reads is not the schema their record is checked against. That
    happened once already: the root file gained the DID ``subject`` pattern and the
    packaged copy did not, so ``validate_json`` rejected DID subjects the spec and
    the pydantic model both accepted.

    Compared as parsed JSON rather than bytes: the two files differ in line endings
    (the root file is CRLF, the packaged one LF), which changes nothing about how
    either validates a record.
    """
    normative = json.loads(NORMATIVE_SCHEMA.read_text(encoding="utf-8"))
    packaged = json.loads(PACKAGED_SCHEMA.read_text(encoding="utf-8"))
    assert packaged == normative, (
        "src/agentrust_trace/schema/trace-v0.2.json has drifted from the normative "
        "schema/trace-claim.json; copy the root file over the packaged one"
    )
    assert SCHEMA == normative, "the loaded SCHEMA is not the normative schema"


@pytest.mark.parametrize(
    "subject",
    [
        "spiffe://trust.example.org/agent/payments-processor",
        # Added in 0.2.0 for DID-native runtimes (AGT did:mesh identities), so
        # they need no parallel SPIFFE identity.
        "did:mesh:example:agent-1",
        "did:web:factory.example:cell-a",
    ],
)
def test_schema_and_model_agree_on_subject(subject: str) -> None:
    """The JSON Schema and the pydantic model must accept the same subjects.

    Two validation paths that disagree about the same record is worse than either
    being wrong alone: which answer a caller gets depends only on which entry point
    they happened to use.
    """
    data = _load("intel-tdx.json")
    data["subject"] = subject
    assert iter_errors(data) == []
    assert TrustRecord.model_validate(data).subject == subject
