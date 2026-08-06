# Conformance-vector completeness in `trace-spec` — a measurement report

**Subject:** `agentrust-io/trace-spec` @ `8dc4197`
**Measured:** 2026-08-06 · Python 3.11.15, clean venv
**Author:** Claude (Opus 5), for Louie Lu

**Nothing in this report has been committed to `agentrust-io/trace-spec`, and nothing here is
a pull request.** It lives in a fork so that it has a URL. Every figure below is re-derivable
from this repository and the scripts in [`scripts/`](scripts/); §7 gives the commands.

---

## Summary for someone who will read one paragraph

`trace-spec`'s action-receipt conformance vectors are **complete under a criterion stronger
than the usual one**: for all twenty-one obligations the reference verifier enforces,
deleting the obligation changes at least one published vector's outcome, and in every case
one of the vectors that changes is a vector that **names** that rule. No obligation is masked
by any other. Two independent checks that could have found problems — a differential against
a second, independently written RFC 8785 canonicalizer, and a rule-inventory guard — found
none.

That is a better result than any of seven external conformance corpora measured with the
same instrument. It comes with three qualifications, and one of them matters: **twenty of the
twenty-one obligations are held by exactly one vector**, so the suite is complete and has no
margin. Adding a rule tomorrow with no vector, or deleting one vector, moves it from complete
to incomplete in a single step, and nothing in CI would say so.

---

## 1. What was measured, and what "complete" means here

An obligation is **load-bearing** for a corpus when deleting it from the reference verifier
changes the outcome of at least one published vector. This is stronger than the usual
question — *does some vector name this rule?* — because a vector can name a rule it does not
exercise, and a rule can be enforced twice over so that removing one copy changes nothing.

The criterion's shape is **not new**. Coverage-by-mutation has been the answer to *does this
specification actually constrain that system?* in formal verification since the late 1990s
(Hoskote et al., DAC 1999; Chockler, Kupferman and Vardi, 2001–2006), and mutation analysis
of test suites goes back to DeMillo, Lipton and Sayward in 1978. What is being done here is
applying it to a **published conformance vector set**, where a surviving mutant means
something different in kind: not *this suite would miss a bug*, but **a certified
implementation may skip this obligation**.

Three things were computed for each obligation:

| | |
|---|---|
| **margin** | how many vectors change outcome when the obligation is deleted |
| **attribution** | whether the vector that *names* the rule is among those that change |
| **masking** | whether deleting some other obligation first makes this one free |

The oracle compares the **full outcome** — `(status, failures, warnings)` — not status alone.
That choice is not cosmetic; §3 explains what it changes.

## 2. Result

```
verifier: tests/test_action_receipt_fixtures.py
vectors:  24
sites:    21 (19 append-literal, 2 inline early-return)

[margins] status-only : min=0 max=1 mean=0.86
[margins] full outcome: min=1 max=2 mean=1.05

[load-bearing] every obligation is held by at least one vector
[attribution]  every rule is held by a vector that names it
[masking]      no rule is masked by any other (all 210 pairs, all 1330 triples)
```

**21 of 21 obligations are load-bearing, and every one is correctly attributed.**

Set beside seven external corpora measured with the same instrument:

| Corpus | Obligations | Held | Margin med. |
|---|---|---|---|
| **`trace-spec` receipts** | **21** | **21** | **1** |
| JSON Schema Test Suite × `jsonschema` | 36 | 35 | 12 |
| JSON Schema Test Suite × `ajv` | 63 | 36 | 17 |
| Unicode UTS46 × `idna` | 26 | 19 | 52 |
| RFC 6570 URI Templates × `uritemplate` | 12 | 7 | 11 |
| RFC 6902 JSON Patch × `jsonpatch` | 19 | **5** | 2 |
| WHATWG URL × `whatwg-url` | 31 | **0** | — |
| CDI TCK × Weld (spec-tier) | 166 | 74 | 2 |

`trace-spec` is the only subject in the set with **no gap at all**. Several of the others are
mature, widely-implemented standards: the published RFC 6902 corpus leaves fourteen of
nineteen obligations unenforced, and the WHATWG URL conformance corpus enforces **none** of
that specification's thirty-one normatively named validation errors — structurally, because
those errors are non-fatal by definition and the corpus asserts only the parse result.

## 3. Three things this measurement changed about the criterion itself

These are reported because they were found *on this repository* and they generalise. Two of
them corrected the method, not the suite.

### 3.1 The warning exemption was an artifact, and should be removed

The audited implementation exempts warnings from the load-bearing test, on the reasoning that
*a warning does not alter the outcome by design, so dropping one cannot change any vector's
status.* That reasoning is sound **given a status-only oracle** and false without one.

Under the full-outcome oracle, `issuer_not_independent` has margin 1: dropping it changes
exactly one vector's emitted warning list, and a vector notices. **The warning is
load-bearing and testable.** The exemption was never a property of warnings; it was the
coarse comparison showing through as a false constraint.

**Recommendation:** delete the exemption and let the criterion cover warnings.

### 3.2 Two obligations have never received the strong criterion

The audited load-bearing test is parametrized over `append` sites only. Two codes —
`receipt_gap_disclosed` and `receipt_missing` — are emitted through **inline literal lists on
early returns**, so they are checked for *named* coverage and never mutated.

Both turn out to be load-bearing (margins 2 and 1). No harm was done. But they were outside
the criterion for reasons of code shape rather than of principle, and the inventory guard
found them by counting what it could see and comparing against what the test touched.

**Recommendation:** parametrize over both site forms. `scripts/mutation_report.py` shows how.

### 3.3 A status-only criterion would report three obligations as unheld

All three of `issuer_not_independent`, `receipt_gap_disclosed` and `receipt_missing` have
status margin **0** and full-outcome margin ≥ 1. A status-only criterion reports them as
gaps, and would send someone to write vectors **that already exist**.

The finer oracle is therefore not an optimisation. It is what makes warnings and
early-return outcomes testable at all.

## 4. The independence claim in the fixture design, checked

`trace-spec`'s fixture documentation argues that the signatures are protected against a
defect in the canonicalizer, because two paths verify them. Both paths called `rfc8785`.
**The claim was unsupported as written** — a shared-canonicalizer defect would have been
invisible to both.

It is now supported. `scripts/jcs_minimal.py` is a second RFC 8785 serializer written from
the RFC text, sharing no code and no design decisions with `rfc8785`; it refuses floats and
out-of-range integers rather than guessing at ECMAScript `Number::toString`, which is honest
because no fixture contains a float.

```
[differential] compared 416 JSON values through both canonicalizers
[differential] byte-identical on every value
[signatures]   26 verified through the naive path, 4 correctly refused (negative vectors)
```

**The defect was in the argument, not in the artifacts.** The fixtures are correct. Those are
two different facts and only the second was ever in doubt.

Worth noting what the differential covers that the signature check does not: all 416 JSON
values in the corpus, not only the ~30 signed bodies. Canonicalization defects live in the
shape of the data. The one string containing a non-ASCII character (an em dash, U+2014)
exercises the rule that JCS emits UTF-8 literally — a serializer that escapes it produces
valid JSON that is not canonical, and every signature over it would fail against a correct
implementation.

## 5. The one thing that should be fixed: there is no margin

```
margin distribution, full outcome:   1 → 20 obligations
                                     2 →  1 obligation
```

**Twenty of twenty-one obligations are held by exactly one vector.** The suite is complete and
maximally fragile. Compare the mature corpora, where the `type` keyword in the JSON Schema
Test Suite is held by 151 independent cases and the UTS46 median is 52 — depth that arrives
from many independent implementers each finding a different way to be wrong.

Concretely, three ordinary events move this repository from complete to incomplete, and
**none of them would fail CI**:

1. A new rule is added with no vector. The load-bearing test is parametrized over the rules
   it finds, so a rule with no vector fails it — **provided the rule is written in the
   `append("literal")` shape the inventory recognises.** Written as `extend`, `+=`, an
   f-string or a named constant, it joins the suite invisibly, and the suite then reports
   complete coverage of a rule set that no longer includes it.
2. A vector is deleted or edited during unrelated work. Nothing warns that it was the only
   thing holding an obligation.
3. Two rules are written that both reject the same input. Neither becomes free today —
   masking was swept to rank three and found nothing — but redundancy is what produces
   masking later, and it is invisible until it is measured.

Failure mode 1 is not hypothetical. In the course of building the instrument used for this
report, the same fault occurred **three times in three languages**: a Python inventory that
matched one `append` idiom, a JavaScript one that matched `error = true` and missed
`result.error = true`, and a Java one that missed eighteen throw sites written in two other
shapes. Each time the count looked plausible. Each time a guard, not a reviewer, caught it.

**Recommendations, in order of cost:**

- **Adopt `scripts/inventory_guard.py` into CI.** It finds nothing today, which is the
  expected result for a codebase written by one person in one idiom. Its value is prospective
  and its cost is one test.
- **Print the margin distribution in the existing test's output.** A one-line change that
  turns "complete" into "complete, and here is how thin". Consider a *ratchet* rather than a
  threshold: fail when an obligation's margin drops below what it was, since a young suite
  legitimately sits at 1.
- **Add a second vector for the obligations whose failure would be most expensive** —
  signature validity, chain continuity, freshness. Not for coverage, which is already
  complete, but for margin.
- Re-run `scripts/pair_mutation.py` when the rule count grows. Rank two is cheap (210 pairs,
  ~3 seconds); rank three is ~18 seconds and found nothing beyond rank two here.

## 6. What this report does not establish

- **The verifier is not the specification.** Everything here measures the vectors against the
  *reference implementation's* obligations. A requirement the specification states and the
  verifier does not implement is invisible to this method — it is not a rule, so there is
  nothing to delete. RFC 6570 demonstrated the cost of that blind spot: `uritemplate`
  implements no rejection rules at all, and therefore scored *perfectly* on rejection
  coverage while rejecting nothing.
- **Twenty-four vectors is a small corpus**, and the margins reflect that more than they
  reflect any judgement about the suite's design.
- **Nothing here speaks to whether the obligations are the right ones.** Completeness
  relative to a rule set says nothing about the rule set.

## 7. Reproducing every figure

```bash
python -m venv .venv && .venv/bin/pip install rfc8785 cryptography pytest
git clone https://github.com/agentrust-io/trace-spec && cd trace-spec && git checkout 8dc4197

cd coverage-report/scripts
python check_canonicalizer.py /path/to/trace-spec   # §4  differential + signatures
python inventory_guard.py     /path/to/trace-spec   # §5  unrecognised rule forms
python mutation_report.py     /path/to/trace-spec   # §2,§3 margins + attribution
python pair_mutation.py       /path/to/trace-spec   # §5  rank-two masking
python triple_mutation.py     /path/to/trace-spec   # §5  rank three
```

Each exits non-zero on a finding.

The comparison figures in §2 for the seven external corpora come from a broader measurement
study, not from these scripts. They are reported here only for scale; nothing in §§1–7 about
`trace-spec` depends on them.

---

## Appendix — the full obligation table

```
code                                     form    status  full  attributed
-------------------------------------------------------------------------
action_ref_invalid                       append       1     1         yes
action_ref_mismatch                      append       1     1         yes
call_id_mismatch                         append       1     1         yes
decision_invalid                         append       1     1         yes
disclosure_contradicted                  append       1     1         yes
disclosure_issuer_not_chain_key          append       1     1         yes
disclosure_key_untrusted                 append       1     1         yes
disclosure_not_sealed_by_successor       append       1     1         yes
disclosure_predecessor_absent            append       1     1         yes
disclosure_signature_invalid             append       1     1         yes
evidence_hash_mismatch                   append       1     1         yes
issuer_key_untrusted                     append       1     1         yes
issuer_not_independent                   append       0     1         yes   <- warning
receipt_chain_gap                        append       1     1         yes
receipt_from_future                      append       1     1         yes
receipt_stale                            append       1     1         yes
session_id_mismatch                      append       1     1         yes
signature_or_key_mismatch                append       1     1         yes
unsupported_physical_completion_claim    append       1     1         yes
receipt_gap_disclosed                    inline       0     2         yes   <- early return
receipt_missing                          inline       0     1         yes   <- early return
```

`status` is the margin under a status-only oracle; `full` under `(status, failures,
warnings)`. The three rows where they differ are §3.3.

---

## Licence

Prose: **CC BY 4.0** — <https://creativecommons.org/licenses/by/4.0/legalcode>
Code under `scripts/`: **Apache 2.0** — full text in [`LICENSE`](LICENSE).
