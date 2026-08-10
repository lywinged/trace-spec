# Verifier-compatibility vectors (proposed, not accepted)

> These fixtures encode the obligations proposed in
> [agentrust-io/trace-spec#116](https://github.com/agentrust-io/trace-spec/issues/116).
> **No normative text for them has been accepted.** Do not read a passing vector here
> as a conformance requirement.

Compliance evidence is verified years after it is issued, so the artifact routinely
outlives the verifier build that reads it. Nothing in `docs/verification.md` currently
says what a verifier must do about version skew, which leaves two failure modes open:
a revision silently orphans existing evidence, or a verifier "helpfully" accepts an
artifact under semantics it does not implement.

The proposal is four obligations: records carry an explicit profile, a verifier
declares the set it supports and refuses anything outside it, the verification
statement names the profile it ran under, and any fallback is disclosed rather than
silent.

## The vectors

| Fixture | Outcome | What it pins down |
|---|---|---|
| `01-known-version-verified.json` | verified | The statement names the profile verification ran under. |
| `02-unknown-version-refused.json` | refused | A future profile is refused, not best-effort verified. |
| `03-superseded-version-refused.json` | refused | The v0.1 identifier, which `spec/trace-v0.2.md` requires a v0.2 verifier to reject. |
| `04-downgrade-disclosed.json` | verified | Falling back to an older profile is conformant when the accepted set shows it. The older profile is a fictional `tag:example.com` one — deliberately not v0.1, which no accepted set may contain. |
| `05-downgrade-silent-is-impossible.json` | refused | The same record where the older profile was never declared. Silent fallback has no outcome. |
| `06-empty-accepted-set-refused.json` | refused | An empty set means "nothing", never "anything". |
| `07-profile-absent-refused.json` | refused | A missing profile cannot be supplied by assumption. |
| `08-dual-accept-configuration-refused.json` | refused | A verifier declaring both v0.2 and v0.1, given a correctly signed v0.1 record. The spec's cutover forbids the configuration itself ("MUST NOT accept both"); the observable requirement is that nothing verifies under it. An earlier revision of vector 04 used v0.1 as its downgrade target and thereby encoded exactly this non-conformant verifier as a positive case. |

**Every record in the set is correctly signed.** These vectors never ask whether a
signature checks out; they ask whether a verifier implements the semantics the record
was written under. A vector that failed because its signature was malformed would
silently stop testing the thing it names, so `tests/test_verifier_compatibility_fixtures.py`
asserts each signature independently.

## Format

Nothing in a fixture names a language or an API:

```jsonc
{
  "verifier": {
    "accepted_profiles": ["tag:agentrust-io.com,2026:trace-v0.2"],
    "verification_time": 1785000100,
    "check_freshness": false     // version skew is the property under test
  },
  "trusted_key": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "record":      { "eat_profile": "...", "signature": "..." },
  "expected": {
    "outcome":   "verified" | "refused",
    "failure":   null | "profile_not_accepted" | "profile_absent" | "no_accepted_profiles",
    "statement": null | { "profile": "...", "accepted_profiles": [...], "downgraded": false }
  }
}
```

`downgraded` is true when the profile verified under is not the first entry of the
accepted set. An implementation may name that field anything, or derive it, as long as
a reader of the statement can tell a fallback happened.

`tests/test_verifier_compatibility_fixtures.py` is the adapter that runs these against
`agentrust_trace`. Another implementation writes its own adapter and runs the same JSON;
that is the point of keeping the expectations out of the test code.

## Regenerating

`gen_vectors.py` rebuilds the set. The signing key is derived from a published seed, so
the fixtures reproduce byte-for-byte and only public JWKs appear in them. They are
deliberately deterministic test keys, not keys with any standing.

```bash
python gen_vectors.py   # writes into examples/verifier-compatibility/
```

## Boundary

Passing these vectors shows a verifier refuses what it does not implement and says what
it verified under. It does not show the verifier implements any particular profile
correctly, and it makes no claim about freshness, revocation, or anchoring — each of
which fails independently.
