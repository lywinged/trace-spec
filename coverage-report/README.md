# coverage-report

A measurement of `trace-spec`'s action-receipt conformance vectors, and the scripts that
produce it.

**This directory exists only in this fork.** Nothing here has been proposed to
`agentrust-io/trace-spec`, and nothing here is a pull request. It is here so the report has
a URL.

- [**REPORT.md**](REPORT.md) — the measurement, the findings, and how to re-run every figure.
- [`scripts/`](scripts/) — six scripts, no dependencies beyond `rfc8785`, `cryptography` and
  `pytest`. Each exits non-zero on a finding.

**The headline:** all twenty-one obligations the reference verifier enforces are
*load-bearing* — deleting any one changes at least one published vector's outcome — and every
one is held by a vector that names it. No masking at rank two or rank three. That is a better
result than any of seven external conformance corpora measured the same way.

**The thing to fix:** twenty of the twenty-one are held by **exactly one vector**. Complete,
and with no margin.

---

Prose: CC BY 4.0. Code under `scripts/`: Apache 2.0 ([`LICENSE`](LICENSE)).
