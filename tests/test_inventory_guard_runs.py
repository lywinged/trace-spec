"""`coverage-report/scripts/inventory_guard.py` states a result. This runs it.

It is the third script in that directory to get one. `mutation_report.py` and
`check_canonicalizer.py` each stated a result nothing re-derived, and each was wrong by
the time anybody looked: the first reported "every obligation is held" over one site of
twenty-three, the second named two error codes that had been renamed away.

This one was wrong in the same way and for the same reason. It was written against a
verifier whose obligations lived in `failures.append("literal")` sites; the registry
refactor moved twenty-two of the twenty-three into an explicit `RULES` table; it did not
know that shape, recovered zero rules, found nothing unrecognisable in the nothing it had
found, and printed *"no rule is written in a shape the inventory cannot recover"* while
exiting 0.

A guard whose whole purpose is to turn a silent omission into a red run cannot have
"I found nothing" as a success path. It refuses now, and this pins both halves: that it
recovers the obligations that exist, and that it refuses when it recovers none.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "coverage-report" / "scripts" / "inventory_guard.py"


def _run() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(ROOT)],
        capture_output=True, text=True, timeout=300,
    )


def test_the_guard_finds_no_unrecoverable_rule() -> None:
    result = _run()
    assert result.returncode == 0, (
        "inventory_guard reported a rule the inventory cannot see, or refused to "
        f"report at all.\n\nstdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
    )


def test_it_recovered_the_obligations_that_exist() -> None:
    """The assertion the old version would have failed.

    A guard that recovers nothing reports no unrecoverable rule, which is why the exit
    status above is not enough on its own. The count is asserted as a lower bound: it
    moves whenever a rule is added, and a test that failed on a larger registry would be
    read as a defect in the registry.
    """
    out = _run().stdout
    total = int(out.split("[inventory] ")[-1].split(" obligation(s) recovered")[0].split("\n")[0])
    registry = int(out.split(" rule(s) in the `RULES` registry")[0].rsplit("[inventory] ", 1)[1])

    assert registry >= 20, f"only {registry} registry rules recovered; the shape is not being read"
    assert total >= 23, f"only {total} obligations recovered in total"


def test_it_refuses_rather_than_reporting_when_it_recovers_nothing() -> None:
    """Exercised through the module rather than the CLI.

    Pointing the CLI at a synthetic tree makes `mutation_report` die importing the
    verifier, which also exits non-zero. Non-zero for the wrong reason would leave this
    test passing over a refusal that never ran, so the empty recovery is injected
    directly and the exit code is asserted to be the refusal's own.
    """
    sys.path.insert(0, str(ROOT / "coverage-report" / "scripts"))
    sys.path.insert(0, str(ROOT / "tests"))
    import inventory_guard
    import mutation_report

    original_scan, original_sites, original_argv = (
        inventory_guard.scan, mutation_report._sites, sys.argv
    )
    try:
        inventory_guard.scan = lambda _path: ([], 0, 0)
        mutation_report._sites = lambda: []
        sys.argv = ["inventory_guard.py", str(ROOT)]
        code = inventory_guard.main()
    finally:
        inventory_guard.scan = original_scan
        mutation_report._sites = original_sites
        sys.argv = original_argv

    assert code == 2, f"expected the refusal exit code 2, got {code}"


def test_the_refusal_is_not_what_the_real_run_does() -> None:
    """The control for the test above. If the guard refused unconditionally, that test
    would pass and mean nothing."""
    assert _run().returncode == 0
