"""`coverage-report/scripts/check_canonicalizer.py` states a result. This runs it.

The script answers two questions the rest of the suite cannot: whether a second,
independent RFC 8785 serializer agrees with `rfc8785` byte for byte across the
corpus, and whether every fixture signature verifies when the signing input is
rebuilt through that second path. Both suite-internal checks call the same
canonicalizer, so neither can see a defect in it.

It was run by hand. Between then and now two of the four codes naming its negative
cases were renamed, `issuer_key_untrusted` to `issuer_key_unknown` and
`disclosure_key_untrusted` to `disclosure_key_unknown`, and the script kept the old
names. Nothing emitted them, so two negative classes stopped being recognised and
the four vectors carrying them were reported as defects. That state was reachable
only because nothing ran the script, and the reconciliation the script now performs
against the verifier's `RULES` registry is inert unless something does.

This is that something. It asserts the exit status rather than parsing the output,
because the script's own contract is that a non-zero exit means a real finding.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "coverage-report" / "scripts" / "check_canonicalizer.py"


def test_the_canonicalizer_check_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, (
        "check_canonicalizer reported a finding. It exits non-zero for a "
        "canonicalizer disagreement, a signature that does not verify through the "
        "naive path, or a code in `deliberately_bad` the verifier does not "
        f"register.\n\nstdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
    )


def test_it_actually_examined_the_corpus() -> None:
    """An empty run would exit zero and mean nothing.

    Both counts are asserted as lower bounds rather than pinned. The figures move
    whenever a vector is added, and a test that fails on a larger corpus would be
    read as a defect in the corpus.
    """
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    out = result.stdout
    assert "byte-identical on every value" in out, out
    compared = int(out.split("compared ")[1].split(" JSON values")[0])
    verified = int(out.split("[signatures] ")[1].split(" verified")[0])
    assert compared >= 2000, f"only {compared} values compared; the corpus is not being walked"
    assert verified >= 50, f"only {verified} signatures verified through the naive path"
