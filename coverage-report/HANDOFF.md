# Handoff

For a local session with full GitHub access. The remote session that produced this work is
scoped to `lywinged/*` and cannot write to `agentrust-io/*` or `kjd/*`, so the three tasks
below are blocked there and unblocked locally.

Read [`REPORT.md`](REPORT.md) first. Everything here assumes it.

---

## State

| | |
|---|---|
| Measurement | done, 2026-08-06, against `agentrust-io/trace-spec` @ `8dc4197` |
| Report + six scripts | this directory, on `lywinged/trace-spec` branch `coverage-report` |
| Upstream | **untouched.** Nothing has been proposed to `agentrust-io/trace-spec` |
| Maintainer response | Imran: *"The single-vector point is the finding, not the ranking... File it on trace-spec and I will treat it as blocking."* |

---

## Task 1 — file the issue (do this first)

Body: `ISSUE_trace_spec_margin.md` in the private notes repo, or reconstruct from §5 of the
report plus the obligation-to-fixture table.

```
repo:     agentrust-io/trace-spec
template: bug_report.md          # blank issues are disabled, a template is mandatory
labels:   bug
title:    Twenty of twenty-one receipt obligations are held by exactly one fixture each
```

The body already fills the template's four fields (**What is wrong** / **Spec section or
file** / **Expected behavior** / **Impact**). Do not restructure it.

**Do not drop the two stated limitations at the end.** They are the difference between a
finding and an overclaim:

1. The measured fixtures are `examples/action-receipts/conformance/`, which
   `examples/README.md` marks **informative** and explicitly not TRACE Trust Records. The
   normative suite in `agentrust-io/trace-tests` was **not** measured and has never been
   read.
2. The criterion is blind to obligations the specification states and the reference verifier
   does not implement. The 21 of 21 is relative to the verifier's rule set, not to the spec.

---

## Task 2 — file the `idna` issue

Unrelated to trace-spec, still outstanding from the same session.

```
repo:  kjd/idna
title: InvalidCodepointContext is unreachable for CONTEXTJ violations; they surface as a different error
body:  idna_issue_body.md
```

Pre-filing checks were re-run on 2026-08-06 and both pass: not previously reported (five
closed issues match the search terms, none describing it), and still present on `master` at
lines 360 to 366 with the exception hierarchy unchanged. **If more than a few weeks have
passed, re-run `idna_patch_check.py` before filing** — it aborts loudly if a newer `idna` no
longer matches the patch context, which is the whole reason it exists.

---

## Task 3 — the follow-up PR

**Ask before writing it.** `CONTRIBUTING.md` says the conformance test suite lives in
`agentrust-io/trace-tests`, but `tests/test_vector_completeness.py` lives in `trace-spec`.
Which repo this belongs in is Imran's call, and guessing wastes the work. Ask in the issue
thread.

Once confirmed, the PR implements the report's own recommendations. All five changes are to
`tests/test_vector_completeness.py`, none touch normative text, so **no organizational
sponsor is required** (`GOVERNANCE.md` requires one only for normative spec changes).

### What is already there

- `_rule_sites()` recovers `failures/warnings.append("literal")` by AST walk. **19 sites.**
- `_literal_failure_lists()` already knows the two codes emitted through inline literal lists
  on early returns, but only for *named* coverage.
- `test_rule_inventory_was_actually_recovered()` is a **vacuity** guard (`len(sites) >= 15`).
  It is not an idiom guard: it cannot tell that a rule was written as `extend`, `+=`, an
  f-string or a named constant and therefore never seen.
- `test_each_rule_is_load_bearing_for_some_fixture()` compares `_statuses()`, which is
  **status only**, and `pytest.skip`s every `warnings` site.
- `UNTESTABLE` is an empty exemption map. Keep it empty; keep the mechanism.

### The five changes

**1. Full-outcome oracle.** Replace `_statuses()` with an `_outcomes()` returning
`(fixture, status, tuple(failures), tuple(warnings))`. This is the change that makes the
other two possible. `coverage-report/scripts/mutation_report.py` has a working version.

**2. Drop the `warnings` skip.** Under the full oracle, `issuer_not_independent` has margin
1: dropping it changes exactly one fixture's emitted warning list. The exemption was an
artifact of the coarse comparison, not a fact about warnings. Delete the `pytest.skip` and
the docstring sentence that justifies it.

**3. Widen `_rule_sites()` to the inline form.** Add the two early-return literal-list sites
so `receipt_gap_disclosed` and `receipt_missing` receive the strong criterion rather than
named coverage only. Both are load-bearing (margins 2 and 1), so this adds no failures. It
closes a gap that existed for reasons of code shape rather than principle.

**4. Add the idiom guard.** Port `coverage-report/scripts/inventory_guard.py` as a test. It
flags non-`append` calls on the rule collections, augmented assignment, aliasing, and
`append` with a non-constant argument. **It finds nothing today. That is the expected result
and the whole point** — the failure it prevents is a future rule joining the suite untested
while coverage still reports complete. This same fault occurred three times in three
languages while building the instrument, and a guard caught it each time.

**5. Add the margin ratchet.** Record each obligation's current margin in a checked-in JSON
file and fail when one drops below its recorded value.

Not a threshold. A young suite legitimately sits at margin 1, and a threshold would either
fail on day one or be set so low it never fires. A ratchet says only: **coverage may not
silently thin.** Raising a recorded margin is a normal PR; lowering one has to be deliberate
and reviewed.

Cost is not a concern: the full mutation pass over 21 sites and 24 fixtures runs in about
half a second.

### Rules that will bite

- **`git commit -s` on every commit.** No DCO sign-off, no merge. Not negotiable and easy to
  forget on a fixup.
- Fill `.github/PULL_REQUEST_TEMPLATE.md`. Type of change is **Editorial** or, if Imran reads
  it otherwise, non-breaking. Not a schema change, not a spec change.
- `CHANGELOG.md` is required only for normative changes. This is not one.
- Review timeline for a non-breaking change is 7 business days.

---

## Task 4 — measure `agentrust-io/trace-tests`, if access is granted

The open question this whole report cannot answer. `trace-tests` carries the *normative*
conformance suite; everything measured so far is the informative fixture set.

If it holds its own vectors and a verifier, the same six scripts apply with two path
constants changed, and it is an afternoon. If it turns out to reuse the same fixtures, that
is also worth knowing and takes ten minutes.

Do not assume either. **Probe before concluding** — that mistake has been made twice in this
work, once marking a corpus unreachable that fetched fine, and once declaring the CDI TCK
too expensive to run when it turned out to cost forty seconds.

---

## Facts worth not getting wrong

```
21 of 21 obligations load-bearing, all correctly attributed
no masking at rank two (210 pairs) or rank three (1330 triples)
20 of 21 obligations held by exactly ONE fixture
receipt_gap_disclosed is the only one at margin 2
416 JSON values byte-identical through two independent RFC 8785 serializers
```

Nine corpora were measured in total. `trace-spec` is the only one with no gap. Do not lead
with that when talking to Imran: he explicitly set the ranking aside and asked for the
single-vector problem, and repeating the compliment reads as deflection.

---

## Things not to do

- **Do not write the twenty vectors.** Anything written from the verifier inherits the
  verifier's blind spots, which is the exact failure this measurement is about. And whoever
  writes them cannot also be the one measuring them, or they become the shared dependency —
  the same defect the fixture independence argument had, which is finding §4.
- **Do not accept a near-duplicate as a second vector.** Two vectors that die to the same
  edit are one vector. The second must reach the obligation by a different route: different
  receipt shape, different position in the chain, different co-occurring conditions.
- **Do not propose anything normative that a commercial interest benefits from without
  disclosing it.** `GOVERNANCE.md` requires maintainers to disclose commercial interest
  before participating in review, and normative changes need a named organizational sponsor.
  Nothing in Tasks 1 to 4 is normative, so nothing here triggers it. It becomes live the
  moment the conversation turns to trust levels or record formats.
