"""What the verifier-compatibility set can still tell apart, measured rather than assumed.

A vector set is a claim that an implementation which does not do the thing will fail
it. Nothing in the set's own tests checks that claim: they run *this* verifier and
compare verdicts, so they pass whether or not any other implementation could pass too.

Measured against a verifier implementing none of the four obligations in
agentrust-io/trace-spec#116, the set separates 3 of its 8 vectors. Five refusal
vectors separate nothing, and the reason is structural rather than a flaw in how they
were written:

`schema/trace-claim.json` pins `eat_profile` with a `const`, so a record carrying any
other profile is schema-invalid. Since upstream #156 made `verify_record` validate
against that schema, every such record is refused by the schema whether or not the
verifier implements a single profile rule. Vectors 02, 03, 05, 07 and 08 all carry
exactly those records, and their `expected.statement` is null, so there is no second
signal to separate on either.

The set was separating when it was written. #156 introduced a second gate covering the
same inputs, and no vector was edited. **Verdict stability is not coverage stability:**
a vector set has to be re-measured when the implementation changes, not only when the
vectors do. This module is that measurement, recorded exactly so the number cannot
drift in either direction unnoticed.
"""
from __future__ import annotations
import base64
import json
import pathlib

import pytest

from agentrust_trace import sign as _sign
from agentrust_trace.validate import validate_json

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "examples/verifier-compatibility"


def null_verifier(record: dict, trusted_jwk: dict) -> None:
    """Everything `verify_record` does except the four obligations under test.

    Signature, key material and schema, and no return value: it signals success by
    returning rather than by describing what it established. A real implementation
    that simply had not read #116 looks like this.
    """
    validate_json(record)
    signature = record["signature"]
    body = _sign._canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    _sign._pubkey_from_jwk(trusted_jwk).verify(
        base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), body)


def _fixtures() -> dict[str, dict]:
    out = {p.stem: json.loads(p.read_text()) for p in sorted(VECTORS.glob("*.json"))}
    assert out, "no fixtures loaded; this module would pass while measuring nothing"
    return out


def _separates(vector: dict) -> bool:
    """True when the null verifier's behaviour differs from what the vector expects."""
    expected = vector["expected"]
    try:
        null_verifier(vector["record"], vector["trusted_key"])
        outcome, statement = "verified", None
    except Exception:
        outcome, statement = "refused", None
    if outcome != expected["outcome"]:
        return True
    # Same verdict: the vector can still separate if it requires a statement, which a
    # verifier that returns nothing cannot produce.
    return expected.get("statement") is not None and statement is None


# Recorded, not asserted as a threshold. The honest figure is 3 of 8 and a test that
# demanded more would be failing on a truth rather than on a regression. Adding a
# separating vector fails this and the entry is updated; losing one fails it too.
SEPARATING = frozenset({
    "01-known-version-verified",          # requires a statement naming the profile
    "04-downgrade-disclosed",             # a declared older profile must still verify
    "06-empty-accepted-set-refused",      # the record is valid; only the config is wrong
})


def test_separation_is_exactly_what_is_recorded() -> None:
    measured = {name for name, v in _fixtures().items() if _separates(v)}
    assert measured == SEPARATING, (
        "the set's separating power changed.\n"
        f"  recorded: {sorted(SEPARATING)}\n"
        f"  measured: {sorted(measured)}\n"
        "A vector that stopped separating did so because the implementation gained "
        "a gate covering the same input, not because anyone edited it."
    )


@pytest.mark.parametrize("name", sorted(SEPARATING))
def test_each_recorded_vector_really_separates(name: str) -> None:
    """Guards the record against being satisfied by an empty measurement."""
    assert _separates(_fixtures()[name])


def test_the_null_verifier_still_accepts_a_conformant_record() -> None:
    """A null verifier that rejected everything would separate every vector and make
    the measurement meaningless. It has to be a plausible implementation, not a broken
    one."""
    null_verifier(*(lambda v: (v["record"], v["trusted_key"]))(
        _fixtures()["01-known-version-verified"]))
