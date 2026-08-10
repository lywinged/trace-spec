# Normative crosswalk

**Informative.** This document maps every RFC 2119 statement in `spec/trace-v0.2.md`
to two things the statement itself does not say: **whom it binds**, and **what, if
anything, enforces it**. It changes no normative text.

The first column exists because it is the easy mistake. A MUST that binds a gateway
cannot and need not be enforced by a verifier's schema; a MUST that binds a profile
*document* is discharged by a sentence in that document, not by code. Reading every
MUST as "the SDK must check this" produces findings that dissolve on contact with the
addressee — an error this repository has made and recorded.

**Maintenance contract.** The statement inventory is recovered from the spec source by
`tests/test_normative_crosswalk.py`; the mapping is maintained by hand and guarded. A
normative keyword added to the spec without a row here fails the test, as does a row
whose quoted text no longer appears in the spec. The quotes are verbatim, so the guard
is exact.

**Scope.** MAY and OPTIONAL are excluded: they grant permissions, and a permission has
no enforcement point. Every MUST, MUST NOT, SHALL, SHOULD, REQUIRED, and RECOMMENDED
outside a code fence is in the table.

## The map

| Spec text (verbatim) | Binds | Enforced by | Notes |
|---|---|---|---|
| A v0.2 verifier MUST require | Verifier | `verify_record` defaults to the v0.2 profile alone and refuses a configuration containing the v0.1 identifier; vectors 03 and 08 in `examples/verifier-compatibility/`; `test_sign.py` cutover tests | Covers all three obligations of the cutover paragraph: require v0.2, reject v0.1, never both. The dual-accept configuration is unrepresentable in this library. No cutover vector exists in upstream `trace-tests`. |
| A record whose `origin.kind` is not `self` MUST carry | Producer **and** verifier | `TrustRecord._origin_cannot_claim_hardware` (cross-field validator) and the `allOf` `if`/`then` in both schema copies | The only obligation in this spec binding both sides of the same sentence, and the reason it holds: a rule enforced only in `build_record` is a rule an attacker never runs. Upstream #135. Tested from both directions, and the schema half means a validator that never loads the Python rejects it too. |
| `declared` is the weakest value and MUST NOT be a default | Producer, then consumer | Partly nothing mechanical: a default is producer behaviour and invisible in the record produced. The model requires `enforcement_mode` explicitly, with no default, which satisfies the MUST NOT structurally | Upstream #143. The consumer half (MUST NOT read `declared` as evidence any rule was checked) is not mechanically enforceable either: it constrains what a relying party concludes, not what any record contains. Same shape as the `enforce` default two rows up. |
| `enforcement_mode` MUST default to `enforce` | Gateway (producer) | Nothing mechanical — a default is producer behaviour, invisible in the record it produces | JSON Schema `default` is an annotation, not a constraint, so the schema cannot carry this. This SDK's model takes a third position: the field is required with no default, so a producer must choose explicitly. That satisfies the MUST NOT below structurally and leaves this MUST to gateway implementations. |
| Workload-level keys SHOULD rotate at TEE-image boundaries | Deployment | Nothing — rotation policy is not observable in a single record | A relying party can observe rotation only across records over time. |
| Verifiers MUST consult current revocation status | Verifier | `verify_record(revocation=...)`: consulted when configured, fail-closed when the store errors; `VerificationStatement.revocation_checked` | A default (offline) run does not consult, and says so: `revocation_checked=False` means non-revocation is unproven, not disproven. The statement makes the gap visible instead of silent; see `LIMITATIONS.md`. |
| MUST be cryptographically bound by a signature | Producer and verifier | `sign_record` / `verify_record`; every fixture in the repository is genuinely signed and independently re-verified by `test_fixture_signatures_independent.py` | |
| MUST use an RFC 8785-conformant library | Implementation (both sides) | Upstream `test_sign.py` has four literal-byte known-answer tests over `_canonical_bytes`, which do catch a regression in this library. `examples/canonicalization-boundary/` adds portable material: three schema-valid signed records another implementation can run. | **Correction, 2026-08-07:** an earlier revision of this row said nothing upstream caught a `json.dumps` swap. That was wrong and was asserted without reading `test_sign.py`. Two narrower gaps survive: the unit tests are not runnable by another implementation (v1.0 targets Go, Rust and TypeScript verifiers), and `test_jcs_distinguishes_unicode_key_order_from_json_dumps` cannot catch a code-point sorter — its example object sorts identically under both schemes, as its own docstring notes, so it detects the divergence through `ensure_ascii` escaping instead. The IEEE 754 half is separately unreachable inside a schema-valid record: no field is typed `number`, and a test pins that. |
| Each profile MUST declare which binding form it uses | Profile author (document) | The declaration lives in profile prose — the normal EAT-profile pattern, not a record field | Partially discharged for v0.2 itself: the field table describes both forms and the reference verifier accepts only the embedded one, but no sentence in the profile text says "this profile uses the embedded form". One sentence would close it. |
| verifiers MUST reject it | Verifier | `verify_record` refuses a record with no `signature` and requires a trusted key; upstream `trace-tests` fails a missing signature at conformance level 1 and above (TR-SIG-005) | "It" is a record with no verifiable signature binding. |
| Records MUST carry `iat` | Producer | `iat` is in the schema's `required` array; `validate_json` rejects its absence | |
| Verifiers MUST enforce a maximum record age | Verifier | `verify_record` `max_age_seconds` (default 86400); upstream `trace-tests` fails a 25-hour-old record at every level (TR-ENV-002) | Passing `None` disables the check — a caller decision the statement records via `freshness_checked`. |
| SHOULD additionally support challenge-nonce binding | Verifier | `verify_record(expected_nonce=...)`; `test_verify_record_nonce_match` | |
| a record that omits or mismatches it MUST be rejected | Verifier | Same code path: mismatch raises, comparison is constant-time | Applies when a challenge nonce was issued. |
| A record with no verifiable binding MUST be rejected | Verifier | `verify_record` (no signature, no trusted key, or bad signature all raise); the same sentence's ordering clause — "BEFORE any other field is trusted" — is partially operationalizable at best | "Trusted" is undefined, and cannot be fully literal: `cnf` must be read before verification to obtain the key, and this implementation reads `eat_profile` first to refuse unimplemented semantics. The workable reading — no field may be *relied on for anything but refusal* before the signature verifies — is what the implementation does. A one-line clarification in the spec would make the ordering requirement checkable. |
| MUST treat the audit entry as invalid | Verifier | Action-receipt fixtures 04, 05, 07 and 17–21: signature mismatch, binding mismatch, and chain-gap failures all yield `receipt_invalid` | The configured-key case: any of the three checks failing is positive evidence. |
| SHOULD surface an advisory status | Verifier | Fixtures 16 and 22: unknown issuer key yields `gap_disclosure_unverified` / `receipt_unverified` with a `*_key_unknown` advisory and no failures | These fixtures contradicted this sentence until 2026-08-07 — they returned `receipt_invalid`. The correction is recorded in `DECISIONS.md`. |
| Gateways MUST default `enforcement_mode` to `enforce` | Gateway (producer) | Nothing mechanical (same obligation as the claim-table row above) | |
| A deployment MUST explicitly configure `silent` mode | Deployment | Not observable in a record; the record shows only which mode was in force | An auditor checks this against deployment configuration, not against a Trust Record. |
| `silent` MUST NOT be the default | Gateway (producer) | Structurally, in this SDK: the model has no default at all, so `silent` cannot be one | |

## What this establishes, and does not

- **A row saying "nothing mechanical" is not an accusation.** Several statements bind
  producers or deployments, whose behaviour is not observable in the artifacts this
  repository holds. The row records where enforcement would have to live, which is not
  here.
- **Enforcement in this repository is not enforcement everywhere.** Rows citing
  `verify_record` or local vectors describe the reference implementation. Another
  implementation meets the same MUST with its own machinery — the portable vectors
  exist so that it can be checked, and the upstream `trace-tests` citations record
  which of these obligations the normative suite exercises today.
- **Two rows describe spec text that could be sharpened** (binding-form declaration,
  "before any other field is trusted"). Both are one-sentence clarifications. They are
  noted here and not drafted: normative edits need a sponsor and a comment window
  under `GOVERNANCE.md`.
