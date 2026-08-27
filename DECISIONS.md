# Decisions

Append-only decision records, newest first. Each entry is a **Tier 2 / historical**
document: true when written, not maintained. Read it for intent, and re-check the code
before acting on any file, flag, or command it names. To reverse a decision, append a new
entry that names the one it supersedes; do not edit the old entry.

---

## 2026-08-18: A verifier may only accept a profile it carries a schema for

**Recorded by:** Claude (Opus 5)
**Status:** DECIDED and applied

**Supersedes** the second half of `2026-08-07: The v0.1 identifier is refused wherever
it appears`, which redirected vector 04's downgrade target to a fictional
`tag:example.com,2025:trace-v0.0` profile. That fixed the conformance problem it was
aimed at. It did not notice that no record under that profile could ever verify here,
because `eat_profile` is a `const` in the schema `verify_record` validates against.

`accepted_profiles` could therefore be widened, and nothing could ever be accepted under
the addition. The parameter could narrow and could not widen, which is not what it
claimed. Worse, the failure surfaced as a schema error on a record with nothing wrong
with it, when the defect was in what the verifier had declared about itself.

`verify_record` now refuses an accepted set naming any profile this build carries no
schema for, alongside the existing refusals of an empty set and of the v0.1 identifier.
The ceiling is read out of the packaged schema files rather than restated, so it cannot
drift from what is actually shipped. The sentence already in the code decided this:
*a valid signature over semantics this build does not implement is not evidence.*

**What this costs, stated rather than discovered later.** A disclosed downgrade is now
unreachable in this build: the only profiles it carries schemas for are v0.2 and the
v0.1 identifier, and the cutover forbids accepting v0.1 under any configuration, so
every permitted accepted set is exactly `(v0.2,)`. The field stays on
`VerificationStatement` because a build shipping a second acceptable schema would reach
it, and `test_a_disclosed_downgrade_is_unreachable_in_this_build` fails if that day
arrives, rather than letting the dead branch sit unnoticed.

**On the vectors.** `04-downgrade-disclosed` became `04-unschemaed-profile-refused`, and
its record is now an ordinary v0.2 record. That is the substantive change, not the
rename: a vector aimed at a configuration rule has to carry a record with nothing wrong
with it, or a verifier that only checks records agrees with it for the wrong reason.
Vector 04 separated nothing before this and does now. `09-unschemaed-profile-first-in-set-refused`
was added to give the rule a second vector, with the unusable entry first in the set
rather than last: a mutation that checks only the head of the set is caught by one of
the pair and a mutation that checks only the tail by the other, and neither is caught by
a single vector. The set's measured separating power moves from 3 of 8 to 4 of 9, and
`tests/test_verifier_compatibility_separation.py` records the new figure.

**Not offered upstream.** This is the `accepted_profiles` machinery of #116, which is a
proposal under review and not accepted normative text. What is reportable there is the
measurement, and that was already posted on 2026-08-13.

---

## 2026-08-10: The fork was rebuilt on upstream rather than rebased onto it

**Recorded by:** Claude (Opus 5)
**Decision-maker:** Louie Lu
**Status:** DECIDED and applied

Upstream merged the last large piece this fork was carrying (`#148`, the rule registry and
the second vector per rule, which the maintainer rebased and opened himself under this
fork's authorship). With `#122`, `#125`, `#126`, `#136` and `#137` already merged, most of
the fork's thirty-three commits described work that now lives upstream with better
provenance than this fork could give it: a PR number and a maintainer's review.

`git rebase upstream/main` was attempted first and abandoned. It stopped on the oldest
commit in the set, a schema-and-version alignment whose content upstream had since taken,
superseded and released three times over. Replaying thirty-three commits against fifteen
of upstream's would have resolved early commits into shapes that no longer meant anything.

Rebuilt instead: `main` reset to `upstream/main`, then the genuinely fork-only material
re-applied. The old history is not discarded: it is tagged `archive/pre-576507b` and
pushed, so the reasoning behind any of it stays reachable.

Four files needed a real merge rather than a copy, and the direction was not the same for
all four. `models.py` and `__init__.py` are upstream's plus this fork's two profile
constants: upstream had moved on with `origin` and the `declared` enforcement mode, which
a wholesale copy would have dropped. `sign.py` and `test_sign.py` are this fork's richer
`accepted_profiles` version, which supersedes the minimal cutover check upstream took from
`#125`: that supersession was predicted in `CLAUDE.md` §5 when `#125` was offered. All
four merged cleanly under a three-way merge against `a817621`, which is where the two
histories last agreed.

The crosswalk guard earned its place in the same run. Upstream added two normative
statements this fork had never seen: the `origin.kind`/`software-only` rule from `#135`
and the `declared` enforcement mode from `#143`, and `test_normative_crosswalk.py` failed
until both had rows. That is the check working: a source-derived inventory noticing that
its subject moved, which is the property the document exists to have.

432 passed, 1 skipped; ruff and mypy clean.

---

## 2026-08-08: An unsealed tail disclosure is unverified, not disclosed

**Recorded by:** Claude (Fable 5)
**Decision-maker:** Louie Lu
**Status:** DECIDED and applied

Found while reviewing our own work before replying to the #117 review, and fixed
before replying rather than shipped alongside the reply. The draft normative text said
a disclosure not linked from both directions "MUST NOT be treated as covering
anything"; the reference verifier granted a clean tail disclosure: no successor yet,
everything else valid: full `receipt_gap_disclosed`, and no fixture pinned either
reading. Fail-open, and adversarially relevant: a chain truncated immediately after a
disclosure is indistinguishable from an honest tail, so whatever the verifier granted
the honest tail it granted the truncation, and the successor seal that the
replay-refusal argument leans on does not exist at the tail.

Resolution reuses the spec's own §3.3.1 principle a third time (unknown receipt key,
unknown disclosure key, and now an unborn successor): inability to check is not
evidence of a defect. New warning rule `disclosure_not_yet_sealed`; a clean tail
yields `gap_disclosure_unverified` with the advisory: accusing no one, conferring
nothing, upgrading on re-verification once the chain resumes and the seal exists.
Two vectors (proposal-117/17, 18) and a declared separating defect (deriving
sealed-ness from the successor-link field's non-nullness instead of the successor's
existence), per the margin and independence rules this tree now enforces on itself.

---

## 2026-08-08: The #124 and #117 reviews landed; the instrument and the fixtures changed shape under them

**Recorded by:** Claude (Fable 5)
**Decision-maker:** carloshvp's review comments, applied by Louie Lu's fork
**Status:** DECIDED and applied

Upstream merged #122, #125 and #126 (release 0.6.0, `a817621`), and carloshvp reviewed
the two open issues this fork's remaining work hangs on. Both reviews were specific
enough to act on, and both were acted on rather than argued with, because both were
right.

**#124 (coverage checker):** stays in `trace-spec`: both things it measures are local
here, and moving source-coupled mutation logic into `trace-tests` would turn the
portable suite into an implementation test. The blocking design point: the obligation
inventory must not rest on AST searches for string literals, whose blind spots
(`extend`, `+=`, constants, refactors) we had already conceded. Implemented as the
review prescribed: an explicit registry of named rules that the verifier itself
consumes, mutation by named rule hook, and at least two independent load-bearing
fixtures per registered rule, with independence made executable through declared
weakened-check defects (fail-closed: a rule without a declared defect fails the suite).

**#117 (gap disclosure):** the chain-element shape is confirmed viable; the verifier
claim stays narrower than "covers the missing range". Changes applied: `cause` demoted
from required enum to optional descriptive field alongside `receipts_lost_estimate`;
stream binding is now checked (`disclosure_stream_mismatch`: the field was present and
signed, and never compared); and the draft states that no policy may read
`receipt_gap_disclosed` as satisfying a profile requiring independently proven
completeness.

**Layout consequence:** upstream numbered the #122 fixtures 10-16, colliding with this
fork's gap-disclosure range. Upstream's numbering is authoritative at the top level;
proposal-bound vectors moved to `examples/action-receipts/conformance/proposal-117/`
with their own numbering, so the ranges cannot collide again. Second vectors for every
rule landed as top-level 17-30 and proposal-117/09-16.

---

## 2026-08-07: The cutover is enforced, and vector 04 no longer contradicts it

**Recorded by:** Claude (Fable 5)
**Decision-maker:** Louie Lu
**Status:** DECIDED and applied

The spec's cutover paragraph is accepted normative text: a v0.2 verifier MUST reject
the v0.1 identifier and MUST NOT accept both. Two things in this repository disagreed
with it, and both were ours.

1. **`verify_record` executed the forbidden configuration.** Its docstring said that
   adding `TRACE_PROFILE_V0_1` to `accepted_profiles` "produces a verifier that is not
   v0.2-conformant": documented, and then honored: the caller who did it got a
   verifier that accepts v0.1 records. Now the set itself is refused with `ValueError`
   before any record is read. The non-conformant verifier is unrepresentable, in the
   same way silent downgrade already was. Removing the guard fails two tests.

2. **Vector `04-downgrade-disclosed` encoded that forbidden verifier as a positive
   case.** It declared `[v0.2, v0.1]` and expected a v0.1 record to verify with the
   downgrade disclosed. Disclosure does not license what the cutover forbids. The
   vector now downgrades to a fictional `tag:example.com,2025:trace-v0.0` profile:
   the same instance `test_sign.py` always used, which is how the library tests stayed
   clean while the portable vectors did not. Vector 05 follows for narrative
   consistency, and a new vector 08 pins the dual-accept refusal itself.

Scope note: the downgrade-disclosure design of #116 is unchanged for legitimately
owned older profiles. What changed is only that v0.1 can never be the older profile,
because the spec says exactly that and the point of the vectors is to encode the spec.

---

## 2026-08-07: An unknown issuer key yields "unverified", not "invalid"

**Recorded by:** Claude (Fable 5)
**Decision-maker:** Louie Lu
**Status:** DECIDED and applied

Fixtures 16 and 22 treated a receipt or gap disclosure whose issuer key the verifier
does not hold as `receipt_invalid`, with `issuer_key_untrusted` /
`disclosure_key_untrusted` failures. The spec says otherwise, and said it before we
wrote the fixtures: section 3.3.1, "a receipt whose issuer key is unknown to the
verifier is unverified, not invalid". The contradiction was ours. It was found by
surveying the spec's normative statements against their enforcement points: the same
sweep that produced several findings against upstream, of which this one pointed back
at us.

Resolution: an unpinned key is an inability to check, not evidence of forgery. Two new
outcomes, `receipt_unverified` and `gap_disclosure_unverified`, each carrying an
advisory (`issuer_key_unknown` / `disclosure_key_unknown`) and an empty failure list.
Structural checks still run first and any positive failure still yields
`receipt_invalid`. The fixtures were renamed (`…-untrusted-…` → `…-unknown-…`) because
the old filenames carried the same conflation. Margins for the retired codes were
dropped from `vector_margins.json` and recorded for their replacements in the same
commit, which is the ratchet working as designed.

Scope caveat: fixture 22 was offered upstream in `agentrust-io/trace-spec#122` under
the old expectation. The PR has not been updated as of this entry; whether and how to
amend it is a separate, outward-facing decision.

---

## 2026-08-05: Neither #116 nor #117 is resolved by this branch, and here is exactly what is

**Recorded by:** Claude (Opus 5)
**Decision-maker:** Louie Lu
**Status:** RECORD: a statement of delivered scope, not a decision to approve

Written because "the tests pass" is not the same claim as "the issue is closed", and the
gap between them is where a contribution over-states itself.

### #116: format-versioning and verifier-compatibility obligations

| The issue asks for | State |
|---|---|
| Records carry an explicit profile version | Already true. `eat_profile` is required by the schema and the model. |
| A verifier declares its supported set and MUST refuse anything outside it | **Implemented in this library.** No normative text written. |
| The verification statement names the version it ran under | **Implemented.** No normative text written. |
| Downgrade MUST be disclosed; silent fallback non-conformant | **Implemented.** No normative text written. |
| Conformance vectors | Seven, in `examples/verifier-compatibility/`. |

**Not delivered: any normative text.** All four obligations are proposals for
`docs/verification.md` and none of them is written. A library doing something is not the
specification requiring it, and the issue asks for the second.

**One genuine fix, separable from the proposal.** `verify_record()` never read
`eat_profile` at all, so a record under any profile verified as if it were v0.2, while
`spec/trace-v0.2.md` already requires a v0.2 verifier to reject the v0.1 identifier. That
is an already-merged requirement the reference implementation did not carry out, in the
same shape as the revocation gap closed in #113, and it needs no window and no sponsor.

**Correction made during review.** The first version of these vectors was written as
Python tests against this library's function signature. The issue asks for conformance
vectors, which have to be runnable by an implementation that shares no code with ours;
tests bound to our API are not that. They were rewritten as implementation-agnostic JSON
with a thin adapter, matching the shape the #117 vectors already had.

**On the repository these belong in.** An earlier revision of this entry said the
vectors were in the wrong place because both issues name `trace-tests`. That was wrong,
and checking `trace-tests` is what settled it:

- It is a **certification suite**, run against an implementation
  (`trace-tests verify --record ... --level 1`). Its `tests/vectors/` hold whole Trust
  Records, and its seven modules map to normative spec sections. It has no
  action-receipt module at all.
- Upstream already put action-receipt conformance fixtures in `trace-spec`, in #101, by
  a different contributor. That is the established practice, whatever the issue text
  says.
- Spec §3.3.2 marks action receipts **informative**, and a certification suite cannot
  test a requirement that is not normative yet.

So `trace-spec` is the right home while the mechanism is a proposal. The move to
`trace-tests` is what happens *after* normative text lands, not before, and it is
gated on that rather than pending.

### #117: GapDisclosure claim and the fifth verifier outcome

| The issue asks for | State |
|---|---|
| `GapDisclosure` claim | Not written as schema or spec text. |
| Fifth outcome + re-scope of `receipt_missing_required` | Not written. |
| Verifier obligations (four MUSTs) | Not written. |
| Conformance vectors | Eight, in `examples/action-receipts/conformance/`, marked as proposed. |
| Schema PR tracking the spec PR | Not written. |

**Not delivered: the proposal itself.** What exists is a runnable model of the mechanism
so it can be argued about against code instead of prose, plus the four choices the issue
leaves open recorded next to the fixtures.

### What was done to check the above

- **Mutation tests, run manually, not retained as automation.** Disabling the profile
  check failed 3 tests; tampering a fixture signature failed 1; flipping a fixture's
  expected outcome failed 1; re-signing a deliberately-invalid vector so that it became
  genuinely valid failed 2, including the independent path with the diagnostic that the
  vector had stopped testing what it names.
- **Independent signature verification, retained.**
  `tests/test_fixture_signatures_independent.py` re-derives every fixture signature using
  `cryptography` and `rfc8785` directly, importing nothing from `agentrust_trace` and
  sharing no helper with the conformance modules. A green conformance run otherwise only
  proves the fixtures and the checker agree, and one hand wrote both.
- **Coverage.** 97% overall; the new profile-handling code is fully covered and the
  eleven uncovered statements are pre-existing error branches.
- **195 tests, ruff, and mypy strict pass on 3.11, 3.12, 3.13 and 3.14**: the full CI
  matrix, verified locally and confirmed green on the branch after push.

None of that establishes that the proposals are correct. It establishes that the vectors
fail when they should and that the fixtures are not merely agreeing with their own
generator.

---

## 2026-08-05: Ship the #117 vectors now; the comment window is ambiguous, so ask

**Recorded by:** Claude (Opus 5)
**Decision-maker:** Louie Lu
**Status:** ACCEPTED 2026-08-05: decision delegated by Louie Lu. Already in force: the
vectors shipped and no normative text was written.

**Decision:**

1. **The comment window for #117 is genuinely ambiguous between 5 and 14 days. Ask; do not
   assume.** Both readings are supportable from the same two documents:

   - **5 days.** `GOVERNANCE.md`: non-breaking changes are "new optional fields, new
     OPTIONAL conformance behavior, informative additions". #117 declares itself
     non-breaking and is one optional claim plus one added outcome.
   - **14 days.** `CONTRIBUTING.md` step 2: "Changes touching wire format, cryptographic
     algorithms, or Trust Record required fields require 14 days", and `GOVERNANCE.md`:
     "Wire format changes: treated as breaking regardless of backward-compatibility
     argument." `GapDisclosure` is a new signed claim that travels on the wire with its own
     canonicalization and signature convention, and #117 itself proposes gating the new
     outcome behind the widened profile version from #114: a profile URI change is what
     made v0.2 breaking.

   Counting from 2026-08-02: 5 days closes 2026-08-07, 14 days closes 2026-08-16. The
   original plan assumed 5. Rather than pick one and risk arriving early on a first
   normative contribution, put the question to the maintainers on the issue, alongside the
   vectors, and take the longer reading unless told otherwise. Asking demonstrates the
   governance documents were read; guessing wrong demonstrates the opposite.

2. **Ship the conformance vectors now; hold the normative text.** `GOVERNANCE.md` requires
   no sponsor and no window for "conformance tests, tooling, and informative additions".
   The eight fixtures and the verifier support are exactly that, and they let the mechanism
   be argued about against running code instead of prose. The spec PR waits.

3. **Nothing here is submitted upstream on the strength of an assumed sponsor.**
   `GOVERNANCE.md` requires an organizational sponsor for normative text, and names the
   route when there is none: a Maintainer carries the PR and the proposer is credited in
   the CHANGELOG. This branch relies on neither, because everything on it is in the
   no-sponsor set: conformance tests, tooling, informative documentation, and one fix that
   implements an already-merged requirement.

4. **The fork's Actions are enabled** (verified 2026-08-05), so a PR from it arrives with a
   CI run attached. The third open question in the delivery pack is closed.

**Rationale:**

Getting the window wrong is not a technical error, it is a governance one, and a proposal
that arrives early reads as not having read the rules: the worst possible framing for a
first normative contribution to a standards project. The nine days between 08-07 and 08-16
cost nothing: the vectors are the deliverable that demonstrates the work, and they can land
immediately.

On sponsorship, `GOVERNANCE.md` states the reason plainly: a MUST is a promise the project
keeps for every future version, and it needs an organization that will implement it and
answer for it. Overstating who stands behind a requirement is the same failure this file
already records for the project's own release evidence.

**Implementation:** conformance vectors merged (fixtures 10-17 plus verifier support,
authored by a separate agent session and applied here); `examples/action-receipts/README.md`
marks them as unaccepted and records the four questions the issue leaves open.

**Supersedes:** an earlier plan that targeted 2026-08-07, for the normative PR only. The
vectors were always shippable on their own schedule.

---

## 2026-08-05: This project's own release evidence is Level 0, and is never described as attested

**Recorded by:** Claude (Opus 5)
**Decision-maker:** Louie Lu
**Status:** ACCEPTED 2026-08-05: decision delegated by Louie Lu. Point 2 binds how this
project's own releases are described in public, everywhere, not only in this repository.
To say otherwise, append a superseding entry; do not edit this one.

**Decision:**

1. **trace-spec publishes an evidence chain for its own releases.** Shipped now: SLSA v1
   build provenance over every distribution file, plus a signed SBOM bound to those same
   digests, both via `actions/attest@v4`: short-lived Sigstore certificates, logged to
   Rekor, verifiable by anyone with `gh attestation verify`. A project that defines
   `build_provenance.provenance_uri` and points it at "a Sigstore/Rekor or compatible log"
   should be able to produce one for itself.

2. **That evidence is Level 0, and is never presented as anything else.** GitHub-hosted
   runners are not a TEE. Nothing in this pipeline is hardware-rooted, and
   `LIMITATIONS.md` already states that Level 0 is "suitable for development and audit
   trail tooling only: not for third-party verification". Public wording about the
   project's own releases says what it is: *the build is provenance-signed and
   transparency-logged; it is not hardware-attested.* No release note, README line, slide,
   or demo says or implies otherwise.

3. **If a self-describing Trust Record is emitted later, `runtime.platform` is
   `software-only`.** That enum value exists precisely so a dev-mode record cannot be
   mistaken for hardware-backed evidence by a consumer that only inspects
   `runtime.platform` (see the comment in `models.py`). Using it makes the honesty
   structural rather than a disclaimer someone has to read.

4. **Deferred, not rejected:** a hash-chained release ledger (each release naming the
   digest of its predecessor) and a real TRACE Trust Record emitted per release by the
   library itself. Both are worth doing; neither is done. They are listed here so a later
   session does not mistake the current partial state for the intended end state.

**Rationale:**

The value of TRACE is the precision of what a record does and does not prove. A project
that overstates its own evidence has argued against its own thesis, and the overstatement
would be found by exactly the audience (auditors, CISOs, standards reviewers) the
project is trying to convince. The same discipline applies wherever a
certification is quoted: one that belongs to a chip does not transfer to the operating
system running on it, nor to the application above that. Different scopes, different
claims.

The tooling half is nearly free, which is what makes the claim discipline the real
decision rather than the engineering.

**Implementation:** `.github/workflows/publish.yml`: the `Attest build provenance` and
`Attest SBOM` steps in the `build` job, plus the `attestations: write` permission they
need.

**Corrections to the assessment that preceded this decision** (recorded so a later session
does not redo the analysis and reach the same wrong conclusions):

- **PyPI already has PEP 740 attestations for every release**, 0.1.0 through 0.5.1.
  `pypa/gh-action-pypi-publish` defaults `attestations: true` under Trusted Publishing, so
  this has been happening without anyone configuring it. Verify with the PyPI simple API
  (`Accept: application/vnd.pypi.simple.v1+json`) and read the `provenance` field. The
  action input is now stated explicitly in the workflow, which changes nothing today and
  keeps the guarantee if the upstream default ever moves.
- **SBOMs are already attached to GitHub releases.** `anchore/sbom-action` defaults
  `upload-release-assets: true`, so the `release: published` path in `sbom.yml` has never
  been the "evaporates after 90 days" case. Only the `push: main` path is artifact-only.
- What was genuinely missing was the *signing and binding*: an SBOM that no one signed,
  and no build provenance in the repository's own attestation store.

**Supersedes:** nothing.
