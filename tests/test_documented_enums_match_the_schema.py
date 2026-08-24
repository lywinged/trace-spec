"""Pins every enumerated value ``docs/schema.md`` states against the schema.

``tests/test_build_provenance_depth_doc.py`` does this for a handful of facts a
single note asserts. This does it for the closed sets, which drift the same way
and for the same reason: the schema gains a value, the table that lists them is
edited by hand or not at all, and nothing compares the two. A reader who trusts
the table then emits a value the schema rejects, or never learns that a value
they need exists.

Both directions matter. A value in the schema and not in the table is a feature
nobody can find. A value in the table and not in the schema is worse, because a
producer who follows the documentation is rejected by the artifact that decides.

The check reads the row that documents each field and requires the backticked
tokens in its description to be exactly the schema's enum, as a set. Fields
whose descriptions carry backticked prose beyond the value list are listed in
``_PROSE_IN_DESCRIPTION`` and checked in the containment direction only, with
the reason stated per field rather than as a blanket exemption.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "trace-claim.json").read_text(encoding="utf-8"))
DOC = (ROOT / "docs" / "schema.md").read_text(encoding="utf-8")

# Descriptions that name a value in prose as well as in the list, so an exact
# set comparison would fail on the prose rather than on a drift.
_PROSE_IN_DESCRIPTION = {
    # "Absent is read as `surface`" repeats a value as the default.
    "build_provenance.provenance_depth": "restates the default in prose",
}


def _enums(node: object, path: str = "") -> list[tuple[str, list[str]]]:
    found: list[tuple[str, list[str]]] = []
    if isinstance(node, dict):
        if "enum" in node and path:
            found.append((path, list(node["enum"])))
        for name, child in node.get("properties", {}).items():
            found.extend(_enums(child, f"{path}.{name}" if path else name))
        if "items" in node:
            found.extend(_enums(node["items"], path))
    return found


ENUMS = sorted(_enums(SCHEMA))


def _documented(field: str) -> list[str]:
    """The backticked tokens in the table row that documents ``field``."""
    pattern = rf"^\|\s*`{re.escape(field)}`\s*\|[^|]*\|[^|]*\|([^|]*)\|"
    row = re.search(pattern, DOC, re.MULTILINE)
    assert row, f"docs/schema.md has no table row documenting `{field}`"
    return re.findall(r"`([^`]+)`", row.group(1))


def test_the_schema_still_has_enumerated_fields() -> None:
    """Guards the guard: an empty list would make every check below vacuous."""
    assert len(ENUMS) >= 6, ENUMS


@pytest.mark.parametrize(("path", "values"), ENUMS, ids=lambda v: v if isinstance(v, str) else "")
def test_the_table_lists_exactly_the_schema_values(path: str, values: list[str]) -> None:
    field = path.rsplit(".", 1)[-1]
    stated = _documented(field)
    missing = sorted(set(values) - set(stated))
    assert not missing, (
        f"schema/trace-claim.json accepts {missing} for {path}, and the "
        f"docs/schema.md row for `{field}` does not list them."
    )
    if path in _PROSE_IN_DESCRIPTION:
        return
    invented = sorted(set(stated) - set(values))
    assert not invented, (
        f"the docs/schema.md row for `{field}` offers {invented}, which "
        f"schema/trace-claim.json rejects. A producer following the table is refused."
    )
