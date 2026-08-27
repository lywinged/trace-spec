"""`coverage-report/REPORT.md` states measured figures. This runs the measurement.

The report is a document about numbers a tool produced. Nothing ran that tool
again. Between the report being written and this file being added, the verifier's
obligations moved from `failures.append("literal")` into an explicit `RULES`
registry, `mutation_report.py` did not know the registry form, and every figure in
the report became unreproducible: it read 21 obligations where there are 23, 210
pairs where there are 253, and a margin median of 1 where it is 2.

None of that was noticed, because `coverage-report/scripts/` was referenced by no
test and no workflow. The report's own first recommendation was to put its
instrument into CI, at a stated cost of "one test". This is that test, written
late.

It pins the figures in one place. A change in the vectors or the rule registry
fails here with both numbers, and the fix is to re-run the tool, update
`MEASURED`, and update the report to match. Both are checked, so the document and
the measurement cannot drift apart again without something failing.
"""
from __future__ import annotations

import math
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPORT = ROOT / "coverage-report" / "REPORT.md"
SCRIPT = ROOT / "coverage-report" / "scripts" / "mutation_report.py"

# Re-run `python coverage-report/scripts/mutation_report.py .` and copy the figures
# here when they legitimately move. Recorded rather than asserted as a threshold:
# a margin that improves fails this too, and the entry is updated.
MEASURED = {
    "vectors": 48,
    "sites": 23,
    "full_margin_min": 2,
    "full_margin_max": 3,
    "status_margin_min": 0,
    "status_margin_max": 2,
}

# Every obligation at full-outcome margin 2 except one at 3.
FULL_MARGIN_DISTRIBUTION = {2: 22, 3: 1}

# Rules a status-only oracle reports as unheld, and the finer oracle does not.
STATUS_BLIND = {
    "receipt_gap_disclosed",
    "issuer_not_independent",
    "receipt_missing",
}


def _run() -> str:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, (
        f"mutation_report exited {result.returncode}. It refuses rather than reporting "
        f"when it cannot see the inventory, so this is a real result:\n{result.stderr}"
    )
    return result.stdout


@pytest.fixture(scope="module")
def output() -> str:
    return _run()


def _rows(output: str) -> list[tuple[str, str, int, int, str]]:
    found = re.findall(r"^(\S+)\s+(registry|inline|append)\s+(\d+)\s+(\d+)\s+(\S+)$",
                       output, re.M)
    assert found, "no rule rows parsed; this module would pass while measuring nothing"
    return [(a, b, int(c), int(d), e) for a, b, c, d, e in found]


def test_the_measurement_still_produces_the_recorded_figures(output: str) -> None:
    vectors = int(re.search(r"^vectors:\s+(\d+)", output, re.M).group(1))
    sites = int(re.search(r"^sites:\s+(\d+)", output, re.M).group(1))
    rows = _rows(output)
    got = {
        "vectors": vectors,
        "sites": sites,
        "full_margin_min": min(r[3] for r in rows),
        "full_margin_max": max(r[3] for r in rows),
        "status_margin_min": min(r[2] for r in rows),
        "status_margin_max": max(r[2] for r in rows),
    }
    assert got == MEASURED, (
        f"the measurement moved.\n  recorded: {MEASURED}\n  measured: {got}\n"
        "Re-run the tool, update MEASURED, and update coverage-report/REPORT.md."
    )
    assert len(rows) == sites, (
        f"the report table lists {len(rows)} rules and the header says {sites} sites"
    )


def test_the_margin_distribution_is_what_is_recorded(output: str) -> None:
    dist: dict[int, int] = {}
    for row in _rows(output):
        dist[row[3]] = dist.get(row[3], 0) + 1
    assert dist == FULL_MARGIN_DISTRIBUTION, (
        f"recorded {FULL_MARGIN_DISTRIBUTION}, measured {dist}. Every obligation "
        "carrying a second vector is the property §5 of the report asked for."
    )


def test_the_status_only_blind_spot_is_what_is_recorded(output: str) -> None:
    """The rules a coarse oracle would report as gaps, sending someone to write
    vectors that already exist."""
    blind = {row[0] for row in _rows(output) if row[2] == 0}
    assert blind == STATUS_BLIND, f"recorded {sorted(STATUS_BLIND)}, measured {sorted(blind)}"


def test_every_obligation_is_held_and_attributed(output: str) -> None:
    assert "[load-bearing] every obligation is held by at least one vector" in output
    assert "[attribution] every rule is held by a vector that names it" in output


@pytest.mark.parametrize(
    "claim",
    [
        "**23 of 23 obligations are load-bearing, and every one is correctly attributed.**",
        "| **`trace-spec` receipts** | **23** | **23** | **2** |",
        "all 253 pairs, all 1771 triples",
        "sites:    23 (0 append, 1 inline, 22 registry)",
        "vectors:  48",
    ],
)
def test_the_report_states_the_measured_figures(claim: str) -> None:
    """The document side of the same pin.

    Correcting the numbers once leaves them free to drift again, which is exactly
    what happened. A figure stated in prose and a figure produced by a tool are two
    artifacts, and only a test that reads both keeps them one.
    """
    text = REPORT.read_text(encoding="utf-8")
    assert claim in text, f"coverage-report/REPORT.md no longer states: {claim!r}"


def test_the_pair_and_triple_counts_follow_from_the_site_count() -> None:
    """Derived, not transcribed. 210 and 1330 were correct for 21 sites and were
    left in place when the count changed, in two places that disagreed with the
    rest of the document."""
    sites = MEASURED["sites"]
    text = REPORT.read_text(encoding="utf-8")
    assert f"all {math.comb(sites, 2)} pairs, all {math.comb(sites, 3)} triples" in text
    assert f"{math.comb(sites, 2)} pairs" in text
