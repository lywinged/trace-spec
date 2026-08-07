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

The set falls in three ranges, and the distinction matters more than the numbering:

- **`01`–`09`** cover the four receipt outcomes this document already describes.
- **`10`–`17`** cover a **proposal that is still under review**, described separately
  below. Read that section before treating any of them as settled behaviour.
- **`18`–`24`** cover rules the verifier already applies and that nothing exercised.
  These are not a proposal. They close gaps in behaviour this document already
  requires.

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
| `10-gap-disclosed-valid.json` | `receipt_gap_disclosed` | A disclosure spliced into the chain: it links back to a present element, and the next element links back to it. |
| `11-gap-disclosure-dangling-predecessor.json` | `receipt_invalid` | Links back to an element that is not in the chain. Half a splice fixes nothing in place. |
| `12-gap-disclosure-successor-does-not-link.json` | `receipt_invalid` | The next element links past the disclosure, leaving it attached at one end. |
| `13-gap-disclosure-contradicted.json` | `receipt_invalid` | Implies elements are absent that are present. |
| `14-gap-disclosure-foreign-key.json` | `receipt_invalid` | Signed by a trusted key that is neither the linked element's key nor an ancestor. |
| `15-gap-disclosed-parent-key-null-estimate.json` | `receipt_gap_disclosed` | Signed by the hierarchical parent because the crash took the session key; `receipts_lost_estimate` is null. Reports a run of three consecutive disclosures. |
| `16-gap-disclosure-unknown-key.json` | `gap_disclosure_unverified` | The right key by chain position, not held by the verifier. Unverifiable is not invalid (spec §3.3.1): the disclosure confers nothing and accuses no one, surfaced with a `disclosure_key_unknown` advisory. |
| `17-gap-disclosure-tampered.json` | `receipt_invalid` | Altered after signing. |

`gen_gap_disclosure_vectors.py` regenerates this range byte-for-byte.

**These implement the design in `proposals/117-gap-disclosure-design.md`, which departs
from the field list in #117.** A disclosure carries `previous_receipt_hash` like any chain
element, and no `disclosed_at`, `range_start_after`, or `range_end_before`. The reason is
that a hash chain cannot express a range, and the emitter cannot know its successor's hash
at the moment it writes the disclosure — so the issue's `disclosed_at == range_end_before`
check compares two fields one party controls, and can only fail for an emitter that is
buggy rather than one that is lying. Coverage is structural instead: the chain is linear
and unbroken, so there is nowhere else the missing receipts could have been.

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

## Rule coverage: checks nothing exercised

> Fixtures `18`–`24` are **not a proposal**. Every rule below is one the verifier in
> `tests/test_action_receipt_fixtures.py` already applies, and which no fixture
> distinguished. Until these existed, an implementation could omit each check entirely
> and still pass the published set — which is the one thing a conformance suite exists
> to prevent.

| Fixture | Rule | What an implementation could have skipped |
|---|---|---|
| `18-action-ref-not-recomputable.json` | `action_ref_invalid` | Recomputing the action reference instead of trusting the declared value |
| `19-call-id-mismatch.json` | `call_id_mismatch` | Checking the receipt is bound to *this* call |
| `20-session-id-mismatch.json` | `session_id_mismatch` | Checking it is bound to *this* session |
| `21-evidence-hash-mismatch.json` | `evidence_hash_mismatch` | Recomputing the evidence digest |
| `22-receipt-issuer-key-unknown.json` | `issuer_key_unknown` | Distinguishing a key it cannot check from a check that failed |
| `23-receipt-from-future.json` | `receipt_from_future` | Rejecting a receipt issued after the verification time |
| `24-decision-not-in-enum.json` | `decision_invalid` | Refusing to read an unknown verb as accept or reject |

Two are load-bearing for the trust model rather than tidiness. Without
`issuer_key_unknown` a receipt authenticates itself: a signature verifies against
whatever key it names, and only a pinned set decides which keys the verifier can check
at all. The outcome is `receipt_unverified`, not `receipt_invalid` — an unpinned key is
an inability to check, not evidence of forgery (spec §3.3.1) — but a verifier that never
consults its pinned set would report such a receipt as fully valid, and that is the
implementation this vector distinguishes. Without `evidence_hash_mismatch` the signature
covers a digest whose document can be swapped, because the receipt signs `evidence_hash`
and not the evidence body.

They were found by walking the verifier's source for every failure code it can emit and
comparing that against the codes the fixtures expect — not by reading the set and
guessing. The method, and what it does not establish, is in
[`docs/conformance-method.md`](../../docs/conformance-method.md).

One fixture per rule, each triggering exactly that rule and nothing else, so a failure
names the check that broke. They pin their own deterministic test key, since the private
half of the key behind `01`–`09` is not published and each fixture already carries its
own `trusted_issuer_keys`. `gen_rule_coverage_vectors.py` regenerates them byte-for-byte.

## Boundary

A valid action receipt proves that a trusted issuer signed a statement about a
specific action request under a specific session or call binding. It does not,
by itself, prove that the physical action completed, that the real world changed
as intended, or that a functional-safety standard was satisfied.

Profiles that need stronger outcome claims should define the external issuer,
certification basis, and verifier trust anchor for those claims explicitly,
without making them part of base TRACE validity.
