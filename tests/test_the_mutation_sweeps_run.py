"""`pair_mutation.py` and `triple_mutation.py` state results. This runs them.

They are the last two scripts in `coverage-report/scripts/` that nothing ran, and the
directory has a history: `mutation_report.py` reported "every obligation is held" over one
site of twenty-three, `check_canonicalizer.py` named two error codes that had been renamed
away, and `inventory_guard.py` recovered zero rules of twenty-three and called it all
clear. Each was wrong by the time anybody looked, and each was wrong because nothing ran it.

These two are not wrong today. They see all twenty-three sites, which is what
`253 = C(23,2)` and `1771 = C(23,3)` say. That is the reason to run them rather than a
reason not to: the other three were also correct on the day they were written.

`REPORT.md` quotes both figures and `test_report_figures_are_measured.py` pins them, but
it pins them by deriving the binomials and by reading `mutation_report.py`'s output. It
never runs these two, so a break in either would be invisible there.

Both are marked `slow`. Together they take about 57 seconds against a suite that otherwise
takes five, and the argument for running them is prospective: they are correct today, and
so were the other three on the day they were written. CI runs `pytest` with no marker
filter, so CI runs them; `-m "not slow"` keeps the local loop at five seconds. Dropping
them to protect that loop would restore exactly the condition this directory keeps failing
under.
"""
from __future__ import annotations

import math
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "coverage-report" / "scripts"

#: The site count both sweeps enumerate over. Derived, not transcribed: the figures below
#: are what a full enumeration produces, so a sweep that saw fewer sites fails on the
#: count rather than passing with a smaller sweep nobody looked at.
SITES = 23


def _run(name: str, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / f"{name}.py"), str(ROOT)],
        capture_output=True, text=True, timeout=timeout,
    )


@pytest.mark.slow
def test_the_pair_sweep_runs_and_finds_no_masking() -> None:
    result = _run("pair_mutation", 600)
    assert result.returncode == 0, (
        f"pair_mutation reported a finding.\n\nstdout:\n{result.stdout}\n\n"
        f"stderr:\n{result.stderr}"
    )
    assert "no rule is masked by any other" in result.stdout, result.stdout


@pytest.mark.slow
def test_the_pair_sweep_enumerated_every_pair() -> None:
    """The assertion that catches the failure this directory keeps having.

    A sweep blinded to the rule registry evaluates the pairs of the sites it can see and
    reports no masking among them, which is a true statement about a set of one.
    """
    out = _run("pair_mutation", 600).stdout
    evaluated = int(out.split("[pairs] evaluated ")[1].split(" ")[0])
    assert evaluated == math.comb(SITES, 2), (
        f"evaluated {evaluated} pairs; {SITES} sites is {math.comb(SITES, 2)}. "
        "A smaller number means the sweep is not seeing every obligation."
    )


@pytest.mark.slow
def test_the_triple_sweep_runs_and_adds_nothing_at_rank_three() -> None:
    result = _run("triple_mutation", 900)
    assert result.returncode == 0, (
        f"triple_mutation reported a finding.\n\nstdout:\n{result.stdout}\n\n"
        f"stderr:\n{result.stderr}"
    )
    assert "Nothing new at rank three." in result.stdout, result.stdout

    evaluated = int(result.stdout.split("[triples] ")[1].split(" ")[0])
    assert evaluated == math.comb(SITES, 3), (
        f"evaluated {evaluated} triples; {SITES} sites is {math.comb(SITES, 3)}"
    )


def test_both_figures_are_the_ones_the_report_states() -> None:
    """The document side. `REPORT.md` quotes both, and a sweep whose enumeration changed
    would otherwise leave the report stating a figure nothing produces any more."""
    report = (ROOT / "coverage-report" / "REPORT.md").read_text(encoding="utf-8")
    assert f"all {math.comb(SITES, 2)} pairs, all {math.comb(SITES, 3)} triples" in report
