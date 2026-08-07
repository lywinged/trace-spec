# coverage-report

A measurement of `trace-spec`'s action-receipt conformance vectors, and the scripts that
produce it.

**This directory exists only in this fork.** Nothing here has been proposed to
`agentrust-io/trace-spec`, and nothing here is a pull request. It is here so the report has
a URL.

- [**REPORT.md**](REPORT.md) — the measurement, the findings, and how to re-run every figure.
- [**HANDOFF.md**](HANDOFF.md) — the outstanding actions, what is blocked and why, and the
  design of the follow-up PR. Written for a session with write access to `agentrust-io`.
- [`scripts/`](scripts/) — six scripts, no dependencies beyond `rfc8785`, `cryptography` and
  `pytest`. Each exits non-zero on a finding.
- [`scripts/jcs_minimal.py`](scripts/jcs_minimal.py) — **the independent check**, worth
  calling out separately. A second RFC 8785 canonicalizer written from the RFC text, sharing
  no code, no helpers and no design decisions with `rfc8785`. It exists so the fixture
  suite's independence argument is *tested* rather than asserted: both of the suite's
  "independent" verification paths call `rfc8785`, so a defect in that library would have
  been invisible to both. Driven by
  [`scripts/check_canonicalizer.py`](scripts/check_canonicalizer.py), which pushes all 416
  JSON values in the corpus through both serializers and re-verifies every signature through
  the second one. Result: **byte-identical on every value.** §4 of the report.

**The headline:** all twenty-one obligations the reference verifier enforces are
*load-bearing* — deleting any one changes at least one published vector's outcome — and every
one is held by a vector that names it. No masking at rank two or rank three. That is a better
result than any of seven external conformance corpora measured the same way.

**The thing to fix:** twenty of the twenty-one are held by **exactly one vector**. Complete,
and with no margin.

---

Prose: CC BY 4.0. Code under `scripts/`: Apache 2.0 ([`LICENSE`](LICENSE)).
