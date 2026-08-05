# Action receipt verification examples

These examples describe the fixture shapes used by embodied-action profiles
that attach per-action receipts below a TRACE Trust Record. They are informative
only: the JSON snippets are not TRACE Trust Records and are not validated by
`schema/trace-claim.json`.

The examples exercise the boundary from
[spec section 3.3.2](../../spec/trace-v0.2.md#332-action-receipts-for-embodied-workflows-informative):

1. session evidence verifies the Trust Record and committed transcript;
2. action issuance evidence verifies that a consequential action request was
   signed, ordered, and bound to the session or call; and
3. outcome evidence reports what an external controller or monitor decided.

## Shared receipt shape

An action receipt profile can represent each externally consequential action as
a transcript entry plus a detached receipt:

```json
{
  "call_id": "call-7f31",
  "session_id": "trace-session-2026-07-05T09:42:11Z",
  "action_ref": "sha256:...",
  "controller_target": "did:web:factory.example:cell-a:robot-arm-2",
  "requested_scope": "cell-a.pick.place",
  "receipt": {
    "issuer": "did:web:factory.example:safety-controller",
    "issuer_key_id": "did:web:factory.example:safety-controller#ed25519-2026q3",
    "linked_call_id": "call-7f31",
    "session_id": "trace-session-2026-07-05T09:42:11Z",
    "evidence_type": "application/vnd.agentrust.action-receipt+json",
    "evidence_hash": "sha256:...",
    "previous_receipt_hash": "sha256:...",
    "decision": "accepted",
    "signature": "base64url..."
  }
}
```

The verifier checks the receipt independently of the core Trust Record:

- recompute `action_ref` or `evidence_hash` from the canonical action preimage;
- resolve `issuer_key_id` through a pinned, manifest-bound, or otherwise trusted
  key set;
- verify the signature with `signature` removed from the canonical receipt;
- verify `linked_call_id` and `session_id` match the expected transcript entry;
- verify `previous_receipt_hash` when the profile uses hash-chain ordering; and
- report the receipt result separately from the controller decision.

## Conformance fixtures

The files under `conformance/` provide machine-checkable cases for the
informative action-receipt rules. The fixtures use
`trace.action_receipt.conformance.v0` as a test-profile identifier. This
fixture set leaves the TRACE wire profile and `schema/trace-claim.json`
unchanged.

Fixtures `01`–`09` cover the four receipt outcomes this document already
describes. Fixtures `10`–`17` cover a **proposal that is still under review** and
are described separately below; read that section before treating them as settled
behaviour.

Each fixture contains:

- `context`, which supplies the expected session, call, receipt-chain
  predecessor, and freshness policy;
- `action`, including the canonical action preimage and its `action_ref`;
- `trusted_issuer_keys`, keyed by the pinned `issuer_key_id`;
- detached `evidence` and a signed `receipt`, except in the missing-receipt
  case; and
- `expected`, which records the result, controller outcome, failure codes, and
  warnings a conforming verifier should return.

The fixture contract uses RFC 8785 JSON Canonicalization Scheme (JCS) bytes for
three operations:

1. `action_ref` is SHA-256 over `agent_id`, `action_type`, `action_scope`, and
   `action_timestamp`.
2. `evidence_hash` is SHA-256 over the detached `evidence` object.
3. The Ed25519 signature covers the receipt object with only `signature`
   removed. The verifier resolves the key through `trusted_issuer_keys`; the
   receipt cannot authenticate itself with an embedded key.

| Fixture | Receipt result | Controller outcome | Required interpretation |
|---|---|---|---|
| `01-valid-controller-accepted.json` | `receipt_valid_accepted` | `accepted` | The controller accepted the bound action. Physical completion remains unproven. |
| `02-valid-controller-rejected.json` | `receipt_valid_rejected` | `aborted` | The verifier accepts the signed abort as valid negative evidence. |
| `03-missing-required-receipt.json` | `receipt_missing_required` | unknown | The profile required a receipt and the action has none. |
| `04-signature-key-mismatch.json` | `receipt_invalid` | unknown | The signature does not verify under the pinned issuer key. |
| `05-action-ref-mismatch.json` | `receipt_invalid` | unknown | The signed receipt binds to a different action. |
| `06-stale-receipt.json` | `receipt_invalid` | unknown | The authentic receipt falls outside the configured freshness window. |
| `07-receipt-chain-gap.json` | `receipt_invalid` | unknown | The receipt does not link to the expected predecessor. |
| `08-same-party-self-report.json` | `receipt_valid_accepted` with warning | `accepted` | The evidence verifies, but the issuer is not independent from the gateway. |
| `09-unsupported-physical-completion.json` | `receipt_invalid` | unknown | Base TRACE cannot verify the asserted physical-completion claim. |

`tests/test_action_receipt_fixtures.py` recomputes each digest, verifies each
signature against the pinned key, checks session and call binding, enforces
freshness and receipt-chain ordering, and compares the result with each
fixture's `expected` object. The tests need no ROS installation or network
access.

The pinned JWKs and signatures are public test material. Deployments must use
their own trusted issuer keys.

## Proposed: disclosed receipt gaps (under review, not accepted)

> Fixtures `10`–`17` encode the mechanism proposed in
> [agentrust-io/trace-spec#117](https://github.com/agentrust-io/trace-spec/issues/117).
> **No normative text for it has been accepted.** They exist so the mechanism can
> be exercised and argued about against running code rather than prose. Do not
> read a passing fixture here as a conformance requirement.

The four outcomes above put two different situations in one bucket. A receipt
that is simply absent and a receipt that was lost in a bounded, disclosed crash
both produce `receipt_missing_required`, so an operator who says "I lost 50 ms of
receipts" scores exactly as an adversary who deleted them silently. That rewards
backfilling over disclosure, which is the wrong incentive for an evidence format.

The proposal adds a signed, chain-bound `GapDisclosure` claim and a fifth
outcome, `receipt_gap_disclosed`: bounded negative evidence the operator attested
to, as distinct from silence.

| Fixture | Outcome | What it pins down |
|---|---|---|
| `10-gap-disclosed-valid.json` | `receipt_gap_disclosed` | A signed, chain-bound disclosure covering exactly the absent range. |
| `11-gap-disclosure-range-mismatch.json` | `receipt_missing_required` | A partial disclosure does not launder the receipts it fails to cover. |
| `12-gap-disclosure-unbound.json` | `receipt_invalid` | Not sealed at the resumption point. A signature proves authorship, not position. |
| `13-gap-disclosure-contradicted.json` | `receipt_invalid` | Claims a gap over receipts that are present. Self-contradiction impeaches the emitter. |
| `14-gap-disclosure-foreign-key.json` | `receipt_invalid` | Signed by a trusted key that is neither the receipt-issuing key nor its parent. |
| `15-gap-disclosed-null-estimate.json` | `receipt_gap_disclosed` | `receipts_lost_estimate` may be null; the range boundaries stay normative. |
| `16-gap-disclosure-untrusted-key.json` | `receipt_invalid` | Right key identifier, key not in the verifier's trusted set. |
| `17-gap-disclosure-tampered.json` | `receipt_invalid` | Altered after signing. |

A forged or self-contradictory disclosure is worse than none, so it yields
`receipt_invalid` rather than falling back to the silent case.

**Choices these fixtures had to make that the issue does not settle.** They are
implementation decisions taken to get something runnable, not proposed
requirements, and each is a question for the maintainers:

1. **Chain binding** is checked as `disclosed_at == range_end_before`. The issue
   says "sealed at the resumption point" without defining the check.
2. **Coverage** is an exact boundary match against the absent range. Chain
   positions are hashes and therefore not orderable, so "covers" cannot be a
   range comparison without more structure than the issue provides.
3. **Issuer binding** reads the receipt-issuing key from the verification
   context, with an optional parent identifier for the hierarchical-parent rule.
4. **Overlapping disclosures** are deliberately not implemented. The issue leaves
   the case genuinely underspecified, and a test is the wrong place to settle it.

The signing keys are deliberately deterministic test keys, so the fixture set
regenerates byte-for-byte. Only public JWKs appear in the files.

## Boundary

A valid action receipt proves that a trusted issuer signed a statement about a
specific action request under a specific session or call binding. It does not,
by itself, prove that the physical action completed, that the real world changed
as intended, or that a functional-safety standard was satisfied.

Profiles that need stronger outcome claims should define the external issuer,
certification basis, and verifier trust anchor for those claims explicitly,
without making them part of base TRACE validity.
