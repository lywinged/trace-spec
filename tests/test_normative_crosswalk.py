"""Guard for docs/normative-crosswalk.md.

The crosswalk maps every RFC 2119 statement in the spec to its addressee and its
enforcement point. The mapping is judgment and stays hand-written; what must never be
hand-maintained is the *inventory*, because a normative keyword added to the spec
without a crosswalk row would otherwise be a silent hole. So the inventory is
recovered from the spec source here, and the two failure directions are both checked:

- a keyword-bearing spec line no crosswalk row quotes (the map is incomplete), and
- a crosswalk row quoting text the spec no longer contains (the map has rotted).

Quotes are verbatim substrings, so renumbering sections cannot break the guard and
rewording a normative sentence deliberately does.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SPEC = REPO_ROOT / "spec" / "trace-v0.2.md"
CROSSWALK = REPO_ROOT / "docs" / "normative-crosswalk.md"

# RFC 2119 requirement keywords. MAY and OPTIONAL are deliberately absent: they grant
# permissions, and a permission has no enforcement point to map. The crosswalk's scope
# note states the same exclusion; this constant is where it is enforced.
KEYWORDS = re.compile(
    r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|RECOMMENDED)\b"
)


def _keyword_lines() -> list[tuple[int, str]]:
    """Every line of the spec carrying a requirement keyword, code fences excluded."""
    lines: list[tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(SPEC.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence and KEYWORDS.search(line):
            lines.append((number, line))
    return lines


def _anchors() -> list[str]:
    """The verbatim quotes in the crosswalk table's first column."""
    anchors: list[str] = []
    for line in CROSSWALK.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cell = line.split("|")[1].strip()
        # Header and separator rows are not anchors; every real anchor carries a
        # requirement keyword by construction.
        if cell and not set(cell) <= {"-"} and KEYWORDS.search(cell):
            anchors.append(cell)
    return anchors


def test_inventories_were_actually_recovered() -> None:
    """Vacuity guard: an empty inventory would pass everything below."""
    assert len(_keyword_lines()) >= 10, "spec keyword extraction matched almost nothing"
    assert len(_anchors()) >= 15, "crosswalk table parsing matched almost nothing"


def test_no_duplicate_anchors() -> None:
    anchors = _anchors()
    duplicates = {a for a in anchors if anchors.count(a) > 1}
    assert not duplicates, f"duplicate crosswalk quotes: {sorted(duplicates)}"


def test_every_anchor_still_appears_in_a_normative_line() -> None:
    """A row quoting text the spec no longer contains is mapping nothing."""
    keyword_text = [line for _, line in _keyword_lines()]
    rotten = [
        anchor
        for anchor in _anchors()
        if not any(anchor in line for line in keyword_text)
    ]
    assert not rotten, (
        "crosswalk rows quote text absent from the spec's normative lines "
        f"(reworded or removed): {rotten}. Update or drop the row."
    )


def test_every_normative_line_is_mapped() -> None:
    """A keyword added to the spec must appear in the crosswalk before this passes."""
    anchors = _anchors()
    unmapped = [
        f"line {number}: {line.strip()[:100]}"
        for number, line in _keyword_lines()
        if not any(anchor in line for anchor in anchors)
    ]
    assert not unmapped, (
        f"{len(unmapped)} normative line(s) have no crosswalk row:\n  "
        + "\n  ".join(unmapped)
        + "\nAdd a row to docs/normative-crosswalk.md quoting each verbatim."
    )
