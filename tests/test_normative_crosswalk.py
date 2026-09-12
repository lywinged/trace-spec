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

import json
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


BACKLOG = REPO_ROOT / "tests" / "crosswalk_backlog.json"


def _backlog() -> dict:
    return json.loads(BACKLOG.read_text(encoding="utf-8"))


def test_every_normative_line_is_mapped() -> None:
    """A keyword added to the spec must appear in the crosswalk, or in the backlog.

    The backlog exists because syncing this branch onto upstream main brought 23
    normative lines with it, all added after the merge base and all belonging to
    features this branch does not touch. Writing 23 crosswalk rows is a piece of work
    of its own, and guessing at the enforcement point for a feature you have not read
    is worse than recording the gap. Every entry carries the spec's own words, so a
    reworded line leaves the backlog and fails here.
    """
    anchors = _anchors()
    recorded = set(_backlog()["lines"])
    unmapped = [
        f"line {number}: {line.strip()[:100]}"
        for number, line in _keyword_lines()
        if not any(anchor in line for anchor in anchors) and line.strip() not in recorded
    ]
    assert not unmapped, (
        f"{len(unmapped)} normative line(s) have no crosswalk row and are not in the "
        f"recorded backlog:\n  "
        + "\n  ".join(unmapped)
        + "\nAdd a row to docs/normative-crosswalk.md quoting each verbatim."
    )


def test_the_crosswalk_backlog_is_a_ratchet() -> None:
    """It may shrink and it may not grow, and a closed entry has to come out.

    Without this the backlog is a place to put anything inconvenient, which is the
    failure mode of every exemption list. Recorded 2026-09-12 with 23 entries.
    """
    recorded = _backlog()["lines"]
    assert recorded, "positive control: an empty backlog exempts nothing and asserts nothing"
    assert len(recorded) <= 23, (
        f"the backlog has grown to {len(recorded)}. It was 23 when it was recorded on "
        f"{_backlog()['recorded']} and it is a ratchet: map the new line instead.")
    anchors = _anchors()
    keyword_text = [line.strip() for _, line in _keyword_lines()]
    closed = [entry for entry in recorded
              if any(anchor in entry for anchor in anchors)]
    assert not closed, (
        f"these backlog entries now have a crosswalk row and must be removed from "
        f"tests/crosswalk_backlog.json: {closed}")
    gone = [entry for entry in recorded if entry not in keyword_text]
    assert not gone, (
        f"these backlog entries are no longer normative lines of the spec, so the "
        f"exemption is stale: {gone}")
