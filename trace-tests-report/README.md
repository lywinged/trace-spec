# trace-tests measurement

Fork-only. **Nothing here has been proposed to `agentrust-io/trace-tests`**, and nothing
in that repository was modified — every mutation is reverted and the checkout re-verified
green before the next one runs.

| | |
|---|---|
| [`REPORT.md`](REPORT.md) | The measurement, its findings, and what it does not establish |
| [`scripts/mutate_modules.py`](scripts/mutate_modules.py) | Does the suite notice when a conformance check stops working? Exits 1 if any check is unverified |
| [`scripts/enum_drift.py`](scripts/enum_drift.py) | Hand-written enums vs the normative schema. Exits 1 on drift |

```bash
python scripts/mutate_modules.py /path/to/trace-tests
python scripts/enum_drift.py     /path/to/trace-tests
```

Both take the checkout as `argv[1]` or from `$TRACE_TESTS`.

## The headline

`trace-tests` is what stamps an implementation as conforming, so the question worth asking
is one level up from what it verifies: **would its own suite catch a regression inside a
conformance module?**

For 23 of 33 failure paths, yes. For ten, no — including every failure path of
`TR-TXN-001`, the Level 2 requirement that a tool transcript exist.

## Why not just grep for the check codes

Because it gives the wrong answer. Counting which `TR-xxx-nnn` codes are named in the test
files reports 12 unverified checks on this tree; mutation reports 3. Tests exercise a
module through `check(...)` and assert on the findings without naming codes, so naming is
a convention and changing outcome is the property.

That gap is the reason this is a script rather than a grep, and it is the same distinction
argued in `agentrust-io/trace-spec#124`: coverage counted by name is an upper bound, not a
measurement.

## Relationship to `coverage-report/`

[`coverage-report/`](../coverage-report) measures the **informative** action-receipt
fixtures in `trace-spec`. This measures the **normative** conformance suite in
`trace-tests`. Same question, different subject, and the normative one is the one whose
output is a certification claim.
