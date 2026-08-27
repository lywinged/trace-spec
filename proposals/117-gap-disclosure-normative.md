# Draft normative text: disclosed receipt gaps (#117)

**Status:** draft, not submitted.

**Target:** `docs/verification.md` (the action-receipt outcome table) and
`spec/trace-v0.2.md` §3.3, with a schema change tracking whichever lands.

**Governance:** normative text. Needs a sponsor or a Maintainer to carry it. Neither has
been sought. The comment window on #117 is also unresolved between five and fourteen days
: see `DECISIONS.md`.

**Depends on:** [`117-gap-disclosure-design.md`](117-gap-disclosure-design.md), which
settles the four checks the issue leaves undefined. **This draft departs from the field
list in #117**: it removes `disclosed_at`, `range_start_after`, and `range_end_before`,
because a hash chain cannot express a range and the emitter cannot know its successor's
hash at write time. The argument is in the design note; the departure is deliberate and
should be argued before this text is offered anywhere.

---

## Draft text

<!-- CHANGED: #117 - disclosed receipt gaps -->

### Disclosed gaps in a receipt chain

Under a profile requiring action receipts, completeness of the receipt chain is the
load-bearing property. No emitter can be made gap-proof: any writer operating
asynchronously has a window in which a crash loses a tail of receipts. A specification
that offers only "complete" and "broken" therefore rewards concealment, because an
operator who backfills a lost receipt scores better than one who reports the loss.

A `GapDisclosure` is a signed statement, occupying a position in the receipt chain, that
receipts which would have occupied that position were never emitted. It is negative
evidence contributed by the emitter about itself.

**Structure.** A `GapDisclosure` is a chain element. It MUST carry:

- `type`, the value `GapDisclosure/1.0`;
- `previous_receipt_hash`, the digest of the chain element immediately preceding the gap,
  in the same form and computed the same way as on a receipt;
- `session_id`, naming the receipt stream the disclosure belongs to;
- `issuer_key_id`, identifying the key that signed it;
- `signature`, over the canonical form of the disclosure with the signature field removed.

It MAY carry `cause` and `receipts_lost_estimate`. Both are descriptive self-reports and
nothing more (per the [#117 review](https://github.com/agentrust-io/trace-spec/issues/117)):
the receipts an estimate counts are absent by definition, so nothing in the chain
corroborates either field. A verifier MUST NOT treat them as established, MUST NOT
condition any outcome on their values, and MUST NOT reject a disclosure because either
disagrees with other evidence. They exist to be reported, not relied on. An earlier
draft made `cause` a required enum; a vocabulary constraint on an uncorroborated field
is precision without evidence, and it was dropped with the review.

**Stream binding.** The `session_id` is covered by the signature, and a verifier MUST
reject a disclosure whose `session_id` does not match the receipt stream under
verification. Without that comparison, a disclosure honestly signed for one stream is a
transplantable excuse for a gap in any other: replay, in the position where replay is
hardest to distinguish from recovery.

**Chain binding.** A `GapDisclosure` MUST be spliced into the receipt chain at the point
of resumption. Concretely, its `previous_receipt_hash` MUST name a chain element that is
present, and the next chain element emitted after resumption MUST carry a
`previous_receipt_hash` naming the disclosure. A disclosure that is not linked from both
directions has not been sealed into the chain and MUST NOT be treated as covering
anything.

That requirement has a window in which it cannot be met honestly: at the live tail of
the chain (after the failure, before resumption) the sealing successor does not exist
yet. A verifier meeting a tail disclosure whose other checks pass MUST NOT report
`receipt_gap_disclosed`, and MUST NOT report `receipt_invalid` either: the absence of a
successor is an inability to check, not evidence of a defect (the same principle as
spec §3.3.1's treatment of unknown keys). It MUST surface the disclosure as unverified
with a distinct advisory, and re-verification after the chain resumes upgrades or
impeaches it on the seal that then exists. This matters adversarially: a chain
truncated immediately after a disclosure is indistinguishable from an honest tail, so
whatever a verifier grants the honest tail, it grants the truncation.

Gap boundaries MUST NOT be expressed as timestamps or as emitter-assigned sequence
numbers. Both are signed by the same key that signs the receipts, so neither constrains an
emitter that is misrepresenting the gap. The chain links are the boundaries.

**Issuer.** A `GapDisclosure` MUST be signed by the key that signed the chain element its
`previous_receipt_hash` names, or by an ancestor of that key in the hierarchy of §3.2.1. A
disclosure signed by any other key MUST be treated as invalid, whether or not that key is
otherwise trusted. A gap is the moment at which introducing an unrelated key is most
useful to an adversary and least distinguishable from recovery.

**Consecutive disclosures.** A `GapDisclosure` MAY name another `GapDisclosure` as its
predecessor, which represents an emitter that failed again before emitting a receipt. A
verifier MUST report the number of consecutive disclosures. It MUST NOT reject solely on
that basis: an emitter failing repeatedly and disclosing each time is behaving better than
one that is silent.

### Verifier outcomes

The outcome `receipt_missing_required` is narrowed, and a fifth outcome is added.

| Outcome | Meaning |
|---|---|
| `receipt_gap_disclosed` | Required receipts are absent, and a valid `GapDisclosure` occupies their position in the chain. Bounded, emitter-attested negative evidence. |
| `receipt_missing_required` | Required receipts are absent and no valid disclosure occupies their position. Silent, and treated as presumptively adversarial. |

A verifier MUST report `receipt_gap_disclosed` distinctly from
`receipt_missing_required`. Collapsing them discards the distinction the disclosure was
issued to make.

Whether `receipt_gap_disclosed` is accepted or rejected MUST be a verifier policy input,
not implementation-defined behaviour. A relying party evaluating a payment authorisation
and one evaluating a telemetry batch will reasonably differ, and neither should have to
change verifier to express that. One bound on that policy is not negotiable: a profile
that requires independently proven completeness of the receipt chain MUST NOT accept
`receipt_gap_disclosed` as satisfying it. A disclosed gap is an attested absence, not a
proof of completeness, and no policy setting may promote the former into the latter.

A `GapDisclosure` that fails signature verification, is not bound into the chain from both
directions, names a session other than the stream under verification, is signed by a key
outside the permitted set, or whose claimed gap is contradicted by chain elements that are
in fact present, MUST yield `receipt_invalid` rather than falling back to
`receipt_missing_required`. A forged, transplanted or self-contradictory disclosure is
worse evidence than no disclosure: it is an attempt to convert silence into attestation,
and the attempt itself is a finding.

**Reporting.** A verification result MUST report each disclosed gap individually, carrying
at minimum the linked predecessor, the number of consecutive disclosures, and the
`cause` when one was supplied. Reducing disclosed gaps to a count or a boolean discards
exactly the detail a relying party's policy needs.

---

## Notes on the draft

**Departure from the issue.** #117 lists `range_start_after`, `range_end_before`, and
`disclosed_at`. This draft has none of them. `previous_receipt_hash` is
`range_start_after` under the name the chain already uses; the other two are the hash of a
successor that does not exist when the disclosure is written. The
[#117 review](https://github.com/agentrust-io/trace-spec/issues/117) reached the same
conclusion independently, chain links suffice, and the conformance fixtures under
`examples/action-receipts/conformance/proposal-117/` implement this draft's shape.

**What a disclosed gap does not establish.** That the receipts were lost rather than
suppressed. An emitter can drop receipts deliberately and disclose the drop; the
disclosure makes the absence *visible and attributable*, not innocent. Nor: stated with
the review's precision: can it establish that the missing receipts ever existed, how
many were lost, or that the issuer did not selectively omit them. What the splice
proves is *where* the gap sits in the chain, and nothing else; every verifier claim in
this draft is written to stay narrower than "covers the missing range". The text says
"negative evidence contributed by the emitter about itself" for that reason, and no
requirement here should be read as making a disclosed gap benign.

**Unrecoverable gaps remain.** A failure that destroys the signing key and its ancestors
leaves an emitter unable to disclose anything, and the result is indistinguishable from
silence. No arrangement of these requirements closes that, and the honest move is to state
it as a boundary in `LIMITATIONS.md` rather than imply the mechanism is total.

**Profile gating.** #117 suggests gating the new outcome behind the widened profile
version contemplated in #114, so existing v0.2 verifiers are untouched. That interacts
directly with the #116 draft: a v0.2 verifier meeting a record under the widened profile
refuses it, rather than reading a fifth outcome it does not implement as if it were one of
the four. The two drafts are stronger together than either alone, and if only one can
proceed, #116 should go first.
