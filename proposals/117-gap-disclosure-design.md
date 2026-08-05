# Design note: resolving the four open questions behind GapDisclosure (#117)

**Status:** working position, not submitted anywhere. Written to settle the choices the
conformance fixtures had to guess at, so normative text can be drafted against a
resolved design rather than an assumed one.

**Relates to:** [agentrust-io/trace-spec#117](https://github.com/agentrust-io/trace-spec/issues/117),
which proposes a `GapDisclosure` claim and a fifth verifier outcome
`receipt_gap_disclosed`. The proposal states the mechanism and its motivation; it leaves
four checks undefined. The fixtures in `examples/action-receipts/conformance/` implement
one reading of each in order to be runnable, and record that those readings are
provisional.

This note takes a position on all four. One of them contradicts the field list in the
issue, and the contradiction is argued below rather than smoothed over.

---

## 1 and 2. Chain binding and coverage — these are the same question

The issue asks for these separately. They collapse, and seeing why resolves both.

### The issue's own argument rules out sequence numbers

> Gap boundaries MUST be expressed in chain/log order, not timestamps — a key that signs
> receipts also signs its own timestamps, so self-reported time cannot bound a gap.

That reasoning is right, and it does not stop at timestamps. **A self-asserted sequence
number has the identical property.** The same key signs it, so an emitter that wants to
misrepresent a gap can renumber as freely as it can back-date. Reading "chain position"
as an integer index keeps the field name and discards the property the field was
introduced to provide.

So a chain position has to be something the emitter cannot restate unilaterally. Two
candidates:

- **A receipt hash**, in the `previous_receipt_hash` chain the receipts already form.
  Tamper-evident, because changing any earlier receipt breaks every later link.
- **An entry ID in an external append-only log**, per the anchoring in #67. Also
  tamper-evident, and additionally witnessed by a party that is not the emitter.

Hashes are available today and require no external dependency. Entry IDs are stronger
and require a log. The design below is written for hashes and extends to entry IDs
without changing shape.

### Hashes are not orderable, so "covers" cannot be a comparison

This is the difficulty the fixtures ran into. Given a gap bounded by two hashes, there is
no arithmetic that decides whether a third hash lies between them. Coverage as a range
test needs an ordered domain, and the only ordered domain available is the one just
ruled out.

### Resolution: the disclosure is itself a link in the chain

A disclosure does not *describe* a gap from outside it. It **occupies the position the
missing receipts would have occupied**:

```
  receipt R7 ──prev──> receipt R8 ... R10 were never emitted
      │
      └──────── GapDisclosure.previous_receipt_hash = hash(R7)
                     │
                     └──── receipt R11.previous_receipt_hash = hash(GapDisclosure)
```

Verification becomes two local link checks, both of which a verifier can already perform,
because they are the same check it performs on every ordinary receipt:

1. The disclosure's `previous_receipt_hash` is the hash of a receipt that is present.
2. The next receipt's `previous_receipt_hash` is the hash of the disclosure.

Coverage is then **structural rather than asserted**. The chain is linear and unbroken,
so there is nowhere else the missing receipts could have been. Nothing needs to be
compared, and nothing needs to be ordered.

### Consequence: `disclosed_at` should be removed

The issue lists `disclosed_at` as "chain position where this disclosure is sealed". Under
the splice model it is both unnecessary and unverifiable:

- **Unnecessary**, because the position is established by the links, and the links are
  checked anyway.
- **Unverifiable**, because at the moment a disclosure is written the receipt that will
  follow it does not exist yet. The emitter cannot know its hash. Writing the disclosure
  after that receipt exists is worse: a hash chain is append-only, so splicing an element
  in behind an existing successor means rewriting the successor.

The fixtures implement `disclosed_at == range_end_before`, which is a self-consistency
check over two fields the emitter controls completely. It can never fail for an emitter
that is trying to deceive, and it can only fail for one that is buggy. That is the
signature of a check that proves nothing.

Same argument applies to `range_end_before` as a stated field: it is the hash of the
successor, which is unknowable at write time. `range_start_after` survives, but it is
exactly `previous_receipt_hash` under another name, so the honest form is to use the
field the chain already has.

**Position:** a `GapDisclosure` carries `previous_receipt_hash` like any chain element.
It carries no `disclosed_at`, no `range_end_before`, and no separate
`range_start_after`. The end of the gap is established by the next receipt linking back
to the disclosure, which is what "sealed at the resumption point" means once it is made
checkable.

## 3. Issuer binding — anchor on the last present receipt

The issue requires the disclosure to be signed by "the receipt-issuing key or its
hierarchical parent". The verifier has to know which key that is, and the receipts that
would have named it are the ones missing. The fixtures supply it out of band, through
the verification context, which is a way of not answering.

Under the splice model the answer is already in the chain: **the disclosure MUST be
signed by the key that signed the receipt it links back to**, or by that key's parent in
the hierarchy of §3.2.1 (record-signing key → workload attestation key → platform
attestation key → silicon root).

The last receipt before the gap is present by construction — it is the one whose hash the
disclosure names — so its `issuer_key_id` is readable. No external context is needed, and
an emitter cannot introduce a new key at a gap boundary, which is precisely the moment it
would be most convenient to do so.

The parent-key allowance matters operationally: a crash that loses receipts may be the
same crash that lost the session key. Permitting the parent lets a recovering emitter
disclose the loss without first having to re-establish the key that died with it.

## 4. Overlapping disclosures — mostly dissolved, one case remains

The issue leaves this underspecified, and the fixtures deliberately do not implement it.

Under the splice model overlap is largely impossible to express. A chain is linear and
each element occupies one position, so two disclosures cannot claim the same span; there
is no span to claim, only a position to occupy.

What remains is **consecutive disclosures**: a disclosure whose `previous_receipt_hash`
names another disclosure rather than a receipt. That is a real operational state — an
emitter that crashed, disclosed, and crashed again before emitting a receipt.

**Position:** allow it, and require the verifier to report the run length. A single
disclosed gap is an incident. Nine consecutive disclosures with no intervening receipt is
a different claim about the deployment, and collapsing the two into "a gap was disclosed"
throws away the part a relying party would act on. Reporting, not rejecting: an emitter
crashing repeatedly and saying so each time is still behaving better than one that says
nothing.

---

## What changed in the fixtures

The fixtures were regenerated against this design rather than left implementing the
issue's field list. `gen_gap_disclosure_vectors.py` rebuilds them.

| Was | Now |
|---|---|
| `11-gap-disclosure-range-mismatch` | **Removed.** Partial coverage is not expressible when coverage is structural. Replaced by `11-gap-disclosure-dangling-predecessor`: the disclosure links back to an element that is not in the chain. |
| `12-gap-disclosure-unbound` (`disclosed_at != range_end_before`) | Replaced by `12-gap-disclosure-successor-does-not-link`: the next element links past the disclosure, leaving it attached at one end. This is the check the old fixture was reaching for and could not express. |
| `14-gap-disclosure-foreign-key` | Kept. The permitted issuer is now read off the linked element instead of supplied through the verification context. |
| `15-gap-disclosed-null-estimate` | Folded into `15-gap-disclosed-parent-key-null-estimate`, which also covers signing by the hierarchical parent — the case where the crash took the session key with it. |
| `10`, `13`, `16`, `17` | Restructured onto the new fields; substance unchanged. |

The disclosure no longer carries `disclosed_at`, `range_start_after`, or
`range_end_before`. It carries `previous_receipt_hash`, like every other chain element.

**One rule was removed rather than covered.** A draft of the verifier validated the type
of `receipts_lost_estimate`. The completeness suite reported it as a rule no vector
distinguished, and the attempt to justify it failed: the estimate is unverifiable by
construction, and its type is the schema's business. It was deleted rather than given a
fixture, which is the outcome that check exists to force.

**Open: three requirements in the draft text have no vector.** The normative draft
requires `type` to equal `GapDisclosure/1.0`, `session_id` to match the session, and
`cause` to be one of four values. The fixture verifier does not implement those, so the
completeness suite cannot flag them — it only sees rules that exist. This is the class of
gap that method does not close, stated in `docs/conformance-method.md` §6, and it is
recorded here rather than left for someone to find.

## What I might have wrong

- **The splice model assumes receipts form a hash chain.** These fixtures do, and
  `previous_receipt_hash` is in the shape the examples README describes. A profile that
  orders receipts by Merkle inclusion or by an external log index instead needs this
  restated in those terms; the argument carries but the field names do not.
- **It gives up any verifiable statement of how many receipts were lost.**
  `receipts_lost_estimate` stays an unverifiable self-report under any design, since the
  lost receipts are by definition absent. That is worth saying explicitly in normative
  text rather than leaving a reader to assume the estimate carries the same weight as
  the bounds.
- **It assumes the emitter can write the disclosure at all.** A crash that destroys the
  signing key and its parent leaves an emitter unable to disclose anything. Such a gap is
  indistinguishable from a silent one, and no design fixes that — it is a boundary to
  state, not a hole to close.
- **`receipt_gap_disclosed` as both a status and a warning** is how the current fixtures
  encode it. Whether the outcome should also surface as a warning is a presentation
  question this note does not settle.
