# Draft normative text: disclosed receipt gaps (#117)

**Status:** draft, not submitted.

**Target:** `docs/verification.md` (the action-receipt outcome table) and
`spec/trace-v0.2.md` §3.3, with a schema change tracking whichever lands.

**Governance:** normative text. Needs a sponsor or a Maintainer to carry it. Neither has
been sought. The comment window on #117 is also unresolved between five and fourteen days
— see `DECISIONS.md`.

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
- `session_id`, matching the session whose chain it belongs to;
- `issuer_key_id`, identifying the key that signed it;
- `cause`, one of `crash`, `shutdown`, `backpressure`, `unknown`;
- `signature`, over the canonical form of the disclosure with the signature field removed.

It MAY carry `receipts_lost_estimate`. That value is an unverifiable self-report: the
receipts it counts are absent by definition, so nothing in the chain corroborates it. A
verifier MUST NOT treat it as established, and MUST NOT reject a disclosure solely because
the estimate disagrees with any other evidence. It exists to be reported, not relied on.

**Chain binding.** A `GapDisclosure` MUST be spliced into the receipt chain at the point
of resumption. Concretely, its `previous_receipt_hash` MUST name a chain element that is
present, and the next chain element emitted after resumption MUST carry a
`previous_receipt_hash` naming the disclosure. A disclosure that is not linked from both
directions has not been sealed into the chain and MUST NOT be treated as covering
anything.

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
change verifier to express that.

A `GapDisclosure` that fails signature verification, is not bound into the chain from both
directions, is signed by a key outside the permitted set, or whose claimed gap is
contradicted by chain elements that are in fact present, MUST yield `receipt_invalid`
rather than falling back to `receipt_missing_required`. A forged or self-contradictory
disclosure is worse evidence than no disclosure: it is an attempt to convert silence into
attestation, and the attempt itself is a finding.

**Reporting.** A verification result MUST report each disclosed gap individually, carrying
at minimum the linked predecessor, the cause, and the number of consecutive disclosures.
Reducing disclosed gaps to a count or a boolean discards exactly the detail a relying
party's policy needs.

---

## Notes on the draft

**Departure from the issue.** #117 lists `range_start_after`, `range_end_before`, and
`disclosed_at`. This draft has none of them. `previous_receipt_hash` is
`range_start_after` under the name the chain already uses; the other two are the hash of a
successor that does not exist when the disclosure is written. The conformance fixtures
implement the issue's list, so they and this text currently disagree — deliberately, and
recorded rather than silently reconciled.

**What a disclosed gap does not establish.** That the receipts were lost rather than
suppressed. An emitter can drop receipts deliberately and disclose the drop; the
disclosure makes the absence *visible and attributable*, not innocent. The text says
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
