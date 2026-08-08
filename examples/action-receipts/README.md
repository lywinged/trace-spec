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
- **`10`–`16`** cover rules the verifier already applies and that nothing exercised
  (merged upstream as [#122](https://github.com/agentrust-io/trace-spec/pull/122)).
  Not a proposal: they close gaps in behaviour this document already requires.
- **`17`–`30`** are the **second vector for every rule**
  ([#124](https://github.com/agentrust-io/trace-spec/issues/124): two independent
  vectors each), placed against implementation shortcuts the first set cannot detect.
- **`proposal-117/`** holds the vectors for a **proposal that is still under review**,
  described separately below, in its own directory with its own numbering so the
  ranges cannot collide. Read that section before treating any of them as settled
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
| `10-action-ref-not-recomputable.json` | `receipt_invalid` | unknown | The declared `action_ref` is not the digest of its own preimage, so it binds nothing. |
| `11-call-id-mismatch.json` | `receipt_invalid` | unknown | An authentic receipt bound to a different call. |
| `12-session-id-mismatch.json` | `receipt_invalid` | unknown | An authentic receipt from a different session. |
| `13-evidence-hash-mismatch.json` | `receipt_invalid` | unknown | The receipt is authentic but the detached evidence was swapped after signing. |
| `14-receipt-issuer-key-unknown.json` | `receipt_unverified` with advisory | unknown | The issuer key is not in the verifier's pinned set. Unverifiable is not invalid (spec §3.3.1): no trust is conferred and no forgery is proven, surfaced as an `issuer_key_unknown` advisory. |
| `15-receipt-from-future.json` | `receipt_invalid` | unknown | Issued after the verification time, so an upper bound on age never rejects it. |
| `16-decision-not-in-enum.json` | `receipt_invalid` | unknown | An unrecognised decision verb, which must not read as accept or reject. |
| `17-missing-receipt-explicit-null.json` | `receipt_missing_required` | unknown | The receipt supplied as an explicit `null`: 03's absence through a different door, misread by presence-checking implementations. |
| `18-action-ref-tail-forged.json` | `receipt_invalid` | unknown | The declared `action_ref` matches the recomputed digest in every character but the last. |
| `19-action-ref-mismatch-in-tail.json` | `receipt_invalid` | unknown | Receipt and action references differ only in the final character. |
| `20-call-id-case-mismatch.json` | `receipt_invalid` | unknown | The linked call id is this call's id in a different case — a different call. |
| `21-session-id-case-mismatch.json` | `receipt_invalid` | unknown | The session id in a different case — a different session. |
| `22-evidence-hash-mismatch-in-tail.json` | `receipt_invalid` | unknown | The evidence hash is wrong only in its final character. |
| `23-receipt-issuer-key-case-variant.json` | `receipt_unverified` with advisory | unknown | The right key pinned under a case-variant of the receipt's key id: not the key the receipt names. |
| `24-receipt-signature-malformed.json` | `receipt_invalid` | unknown | Valid base64url decoding to 32 bytes — rejected by structure, where 04 needs cryptography. |
| `25-stale-receipt-boundary.json` | `receipt_invalid` | unknown | Stale by exactly one second. |
| `26-receipt-from-future-boundary.json` | `receipt_invalid` | unknown | Issued one second after the verification time. |
| `27-receipt-chain-gap-in-tail.json` | `receipt_invalid` | unknown | The predecessor link is wrong only in its final character. |
| `28-physical-completion-claim-case.json` | `receipt_invalid` | unknown | The claim `"None"`: the vocabulary word under case-normalisation, outside it as bytes. |
| `29-same-party-self-report-rejected.json` | `receipt_valid_rejected` with warning | `rejected` | A gateway self-report on the rejected branch: issuer independence matters on both. |
| `30-decision-case-variant.json` | `receipt_invalid` | unknown | The decision `"Accepted"`: in the vocabulary case-insensitively, outside it as bytes. |

Fixtures `10`–`16` each pin down one rule that the verifier applies and that no fixture
previously exercised. Every one was a check a conforming implementation could have
omitted entirely while passing this set. Two matter beyond tidiness: without
`issuer_key_unknown` a receipt authenticates itself — a signature verifies against
whatever key it names, and only the pinned set decides which keys the verifier can
check at all; per spec §3.3.1 the outcome is `receipt_unverified`, not
`receipt_invalid`, but a verifier that never consults its pinned set would report such
a receipt as fully valid, which is what the vector distinguishes. Without
`evidence_hash_mismatch` the signature covers a digest whose document may have been
replaced.

Fixtures `17`–`30` are the second, independent vector for each rule. Two vectors are
independent when a single implementation defect causes one to pass and the other to
fail (#124), and each pair here is split by a declared, plausible shortcut: truncated
digest comparison, case-normalised identifier matching, clock tolerance, structural
signature validation, presence-checking instead of null-checking. The defect that
separates each pair is declared and enforced in
`tests/test_vector_completeness.py::DEFECTS`; the method is described in
[`docs/conformance-method.md`](../../docs/conformance-method.md).

Everything from `10` up pins its own deterministic test key, since the private half of
the key used by `01`–`09` is not published; `gen_rule_coverage_vectors.py` regenerates
the range byte-for-byte and only public JWKs appear in the files.

`tests/test_action_receipt_fixtures.py` recomputes each digest, verifies each
signature against the pinned key, checks session and call binding, enforces
freshness and receipt-chain ordering, and compares the result with each
fixture's `expected` object. The tests need no ROS installation or network
access.

The pinned JWKs and signatures are public test material. Deployments must use
their own trusted issuer keys.

## Proposed: disclosed receipt gaps (under review, not accepted)

> The fixtures under `conformance/proposal-117/` encode the mechanism proposed in
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
| `01-gap-disclosed-valid.json` | `receipt_gap_disclosed` | A disclosure spliced into the chain: it links back to a present element, and the next element links back to it. |
| `02-gap-disclosure-dangling-predecessor.json` | `receipt_invalid` | Links back to an element that is not in the chain. Half a splice fixes nothing in place. |
| `03-gap-disclosure-successor-does-not-link.json` | `receipt_invalid` | The next element links past the disclosure, leaving it attached at one end. |
| `04-gap-disclosure-contradicted.json` | `receipt_invalid` | Implies elements are absent that are present. |
| `05-gap-disclosure-foreign-key.json` | `receipt_invalid` | Signed by a trusted key that is neither the linked element's key nor an ancestor. |
| `06-gap-disclosed-parent-key-null-estimate.json` | `receipt_gap_disclosed` | Signed by the hierarchical parent because the crash took the session key; `receipts_lost_estimate` is null. Reports a run of three consecutive disclosures. |
| `07-gap-disclosure-unknown-key.json` | `gap_disclosure_unverified` | The right key by chain position, not held by the verifier. Unverifiable is not invalid (spec §3.3.1): the disclosure confers nothing and accuses no one, surfaced with a `disclosure_key_unknown` advisory. |
| `08-gap-disclosure-tampered.json` | `receipt_invalid` | Altered after signing. |
| `09-gap-disclosure-key-case-variant.json` | `gap_disclosure_unverified` | The right public key pinned under a case-variant of the disclosure's key id: not the key it names. |
| `10-gap-disclosure-signature-malformed.json` | `receipt_invalid` | Valid base64url of the wrong length — structure rejects it, where 08 needs cryptography. |
| `11-gap-disclosure-confusable-ancestor-key.json` | `receipt_invalid` | A trusted key registered under a case-variant of the permitted ancestor's id: a confusable, not the ancestor. |
| `12-gap-disclosure-replayed-stream.json` | `receipt_invalid` | Honestly signed for a different session, presented against this one. Stream binding refuses the transplant. |
| `13-gap-disclosure-stream-case-variant.json` | `receipt_invalid` | The session id under the signature is this session's id in a different case. |
| `14-gap-disclosure-predecessor-link-tail.json` | `receipt_invalid` | The predecessor link is wrong only in its final character. |
| `15-gap-disclosure-seal-tail-mismatch.json` | `receipt_invalid` | The successor's link matches the disclosure's digest in every character but the last. |
| `16-gap-disclosure-contradicted-at-tail.json` | `receipt_invalid` | The contradiction stands at the live tail, where no successor exists to seal it. |

`01`–`08` are one vector per rule; `09`–`16` are the second, independent set (#124),
including both vectors for `disclosure_stream_mismatch` — the rule the
[#117 review](https://github.com/agentrust-io/trace-spec/issues/117) asked for: a
disclosure binds to the receipt stream it excuses, or one honestly signed for stream A
is a transplantable excuse for a gap in stream B.
`proposal-117/gen_gap_disclosure_vectors.py` regenerates the whole directory
byte-for-byte.

**These implement the design in `proposals/117-gap-disclosure-design.md`, which departs
from the field list in #117.** A disclosure carries `previous_receipt_hash` like any chain
element, and no `disclosed_at`, `range_start_after`, or `range_end_before`. The reason is
that a hash chain cannot express a range, and the emitter cannot know its successor's hash
at the moment it writes the disclosure — so the issue's `disclosed_at == range_end_before`
check compares two fields one party controls, and can only fail for an emitter that is
buggy rather than one that is lying. Coverage is structural instead: the chain is linear
and unbroken, so there is nowhere else the missing receipts could have been. The #117
review reached the chain-element conclusion independently, and narrowed the claim: the
splice proves *where* the gap sits, never that the missing receipts existed, how many
were lost, or that the issuer did not selectively omit them.

A forged, transplanted or self-contradictory disclosure is worse than none, so it yields
`receipt_invalid` rather than falling back to the silent case. Whether a *valid*
disclosed gap is acceptable is relying-party policy — with one hard bound: it never
satisfies a profile that requires independently proven completeness.

The design note records the choices the issue left open and how each was settled,
including the review's amendments. The signing keys are deliberately deterministic test
keys, so the fixture set regenerates byte-for-byte. Only public JWKs appear in the files.

## Boundary

A valid action receipt proves that a trusted issuer signed a statement about a
specific action request under a specific session or call binding. It does not,
by itself, prove that the physical action completed, that the real world changed
as intended, or that a functional-safety standard was satisfied.

Profiles that need stronger outcome claims should define the external issuer,
certification basis, and verifier trust anchor for those claims explicitly,
without making them part of base TRACE validity.
