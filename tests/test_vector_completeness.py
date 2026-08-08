"""Completeness checks over the conformance vector sets.

The other modules ask whether the vectors are *correct*. This one asks whether they are
*complete*: does every obligation the verifier implements have at least one vector that
notices when the obligation is gone?

Nothing here is maintained by hand. The rule inventory is recovered from the verifier's
own source with `ast`, so a rule added without a vector is a failing test rather than a
silent hole.

Four questions, in increasing strength:

1. Does any fixture expect a code the verifier cannot produce? (dead expectations)
2. Is every code the verifier can produce expected by some fixture? (unexercised rules)
3. Does deleting each rule change at least one fixture's outcome? (obligations that are
   named but not load-bearing, because another rule fires on the same input)
4. Has any obligation's margin — the number of fixtures that notice its deletion —
   dropped below what it was? (silent thinning)

**Recovering an inventory from source has its own failure mode**, and it is the mirror of
the one it replaces. A hand-maintained list drifts when someone forgets to add to it. A
source-derived list drifts when someone writes the rule in a shape the walk does not
recognise: `failures.extend([...])`, `+=`, an alias, an f-string. The suite then reports
complete coverage over an inventory that is quietly missing entries.
`test_no_unrecognised_rule_idiom` is the guard for that, and it is expected to find
nothing — the failure it prevents is the rule added months from now, not any rule today.
"""

from __future__ import annotations

import ast
import json
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

TESTS_DIR = Path(__file__).parent
VERIFIER_MODULE = TESTS_DIR / "test_action_receipt_fixtures.py"
FIXTURE_DIR = TESTS_DIR.parent / "examples" / "action-receipts" / "conformance"
MARGINS_FILE = TESTS_DIR / "vector_margins.json"
FIXTURES = sorted(p for p in FIXTURE_DIR.rglob("*.json"))

RULE_COLLECTIONS = frozenset({"failures", "warnings"})

# Codes a verifier may emit that no fixture can reasonably pin down, with the reason.
# Kept empty on purpose: an entry here is a claim that an obligation is untestable, which
# should have to be argued for in review rather than accumulated quietly.
UNTESTABLE: dict[str, str] = {}


@dataclass(frozen=True)
class Site:
    """One place the verifier emits a rule code."""

    lineno: int
    code: str
    kind: str  # "append" | "inline"


def _source_tree() -> ast.Module:
    return ast.parse(VERIFIER_MODULE.read_text(encoding="utf-8"))


def _is_recognised_append(call: ast.Call) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "append"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in RULE_COLLECTIONS
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    )


def _rule_sites() -> list[Site]:
    """Every place a rule code is emitted, in either shape the verifier uses.

    Both shapes are returned so both are mutated. An earlier revision walked only
    `append` calls, which left the two codes emitted through inline literal lists on
    early returns outside the strong criterion — a gap that existed because of the shape
    of the code rather than for any reason of principle.
    """
    sites: list[Site] = []
    for node in ast.walk(_source_tree()):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            if _is_recognised_append(node.value):
                sites.append(Site(node.lineno, node.value.args[0].value, "append"))
        if isinstance(node, ast.keyword) and node.arg in RULE_COLLECTIONS:
            if isinstance(node.value, ast.List):
                for element in node.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        sites.append(Site(element.lineno, element.value, "inline"))
    return sites


def _declared_statuses() -> set[str]:
    """Every status the verifier can return, read from its source."""
    statuses: set[str] = set()
    tree = _source_tree()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "status":
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                statuses.add(node.value.value)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "status" for t in node.targets):
            continue
        # Only the branches of a conditional are statuses. Walking the whole value would
        # also collect the literal being compared against in the test.
        values = (
            [node.value.body, node.value.orelse]
            if isinstance(node.value, ast.IfExp)
            else [node.value]
        )
        for value in values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                statuses.add(value.value)
    return statuses


def _expected(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))["expected"]


def _codes_expected_by_fixtures() -> set[str]:
    codes: set[str] = set()
    for path in FIXTURES:
        expected = _expected(path)
        codes.update(expected.get("failures", []))
        codes.update(expected.get("warnings", []))
    return codes


# ---------------------------------------------------------------------------
# 0. Guards on the instrument itself
# ---------------------------------------------------------------------------


def test_rule_inventory_was_actually_recovered() -> None:
    """A vacuity guard: if the walk matched nothing, everything below passes emptily."""
    assert len(_rule_sites()) >= 15
    assert _declared_statuses(), "no status values recovered from the verifier source"
    assert FIXTURES, "no fixtures found"


def test_no_unrecognised_rule_idiom() -> None:
    """No rule may be emitted in a shape the inventory cannot see.

    Expected to find nothing. That is the point: this does not check today's coverage,
    it prevents a future rule from joining the verifier in a shape that keeps it out of
    the inventory while the suite still reports complete.
    """
    findings: list[str] = []
    tree = _source_tree()
    lines = VERIFIER_MODULE.read_text(encoding="utf-8").splitlines()

    def src(node: ast.AST) -> str:
        return lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else "?"

    for node in ast.walk(tree):
        # A method other than append on a rule collection: extend, insert, __setitem__.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            target = node.func.value
            if isinstance(target, ast.Name) and target.id in RULE_COLLECTIONS:
                if not _is_recognised_append(node):
                    findings.append(
                        f"line {node.lineno}: {target.id}.{node.func.attr}(...) is not "
                        f'the append("literal") shape the inventory reads — {src(node)}'
                    )
        # failures += [...]
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id in RULE_COLLECTIONS:
                findings.append(
                    f"line {node.lineno}: {node.target.id} extended by augmented "
                    f"assignment, which the inventory does not walk — {src(node)}"
                )
        # f = failures; every later f.append(...) is invisible, since the walk keys on name
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            if node.value.id in RULE_COLLECTIONS:
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id not in RULE_COLLECTIONS:
                        findings.append(
                            f"line {node.lineno}: {target.id} aliases {node.value.id}; "
                            f"appends through the alias are invisible — {src(node)}"
                        )

    assert not findings, (
        "the verifier emits rules in shapes the inventory cannot recover, so coverage "
        "would be reported over an incomplete rule set:\n  " + "\n  ".join(findings)
    )


# ---------------------------------------------------------------------------
# 1-2. Cheap diagnostics
# ---------------------------------------------------------------------------


def test_no_fixture_expects_a_code_the_verifier_cannot_emit() -> None:
    """A fixture naming a code nothing produces holds an assertion that cannot fail."""
    emitted = {site.code for site in _rule_sites()}
    orphans = _codes_expected_by_fixtures() - emitted
    assert not orphans, (
        f"fixtures expect codes the verifier can never produce: {sorted(orphans)}. "
        "Either the rule was removed and the fixture kept, or the code is misspelled — "
        "in both cases the fixture is no longer testing anything."
    )


def test_every_verifier_rule_is_exercised_by_some_fixture() -> None:
    emitted = {site.code for site in _rule_sites()}
    unexercised = sorted(emitted - _codes_expected_by_fixtures() - set(UNTESTABLE))
    assert not unexercised, (
        f"{len(unexercised)} obligation(s) have no conformance vector: {unexercised}. "
        "Each is a check a conforming implementation could omit entirely and still pass."
    )


def test_every_declared_outcome_is_reached_by_some_fixture() -> None:
    reachable = _declared_statuses()
    reached = {_expected(path)["status"] for path in FIXTURES}
    assert not sorted(reachable - reached), (
        f"outcomes the verifier can return that no fixture produces: "
        f"{sorted(reachable - reached)}"
    )
    assert not sorted(reached - reachable), (
        f"fixtures expect outcomes the verifier cannot return: {sorted(reached - reachable)}"
    )


# ---------------------------------------------------------------------------
# 3-4. The strong criterion, and the ratchet on it
# ---------------------------------------------------------------------------

Outcome = tuple[str, str, tuple[str, ...], tuple[str, ...]]


def _outcomes(verify: Any) -> list[Outcome]:
    """Full outcome per fixture: status, failures and warnings.

    Status alone is too coarse. Under a status-only comparison a warning can never be
    load-bearing by construction, which reads as "warnings are untestable" when it is
    only an artifact of what is being compared.
    """
    results: list[Outcome] = []
    for path in FIXTURES:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        try:
            r = verify(fixture)
            results.append((path.name, r.status, tuple(r.failures), tuple(r.warnings)))
        except Exception as exc:  # a removal that breaks the verifier still counts
            results.append((path.name, f"raised:{type(exc).__name__}", (), ()))
    return results


def _run_with_site_dropped(site: Site) -> list[Outcome]:
    """Re-execute the verifier with one emission site removed."""
    tree = _source_tree()

    class Drop(ast.NodeTransformer):
        def visit_Expr(self, node: ast.Expr) -> ast.AST:
            # `pass`, not deletion: a rule that is the sole body of an `if` or `except`
            # would leave an empty block, and the mutant would fail to compile — which
            # reads as "the rule matters" for the wrong reason.
            if site.kind == "append" and node.lineno == site.lineno:
                return ast.copy_location(ast.Pass(), node)
            return node

        def visit_keyword(self, node: ast.keyword) -> ast.AST:
            if site.kind == "inline" and node.arg in RULE_COLLECTIONS:
                if isinstance(node.value, ast.List):
                    node.value.elts = [
                        e
                        for e in node.value.elts
                        if not (
                            isinstance(e, ast.Constant)
                            and e.value == site.code
                            and e.lineno == site.lineno
                        )
                    ]
            return node

    mutated = ast.fix_missing_locations(Drop().visit(tree))

    # The mutant must be a registered module: `@dataclass` resolves
    # `sys.modules[cls.__module__]`, so exec'ing into a bare dict raises before a single
    # fixture runs — which would read as "every rule matters" while testing nothing.
    name = f"_mutant_verifier_{site.kind}_{site.lineno}"
    module = types.ModuleType(name)
    module.__file__ = str(VERIFIER_MODULE)
    sys.modules[name] = module
    try:
        exec(compile(mutated, str(VERIFIER_MODULE), "exec"), module.__dict__)  # noqa: S102
        return _outcomes(module.__dict__["_verify_fixture"])
    finally:
        del sys.modules[name]


def _baseline() -> list[Outcome]:
    return [
        (path.name, e["status"], tuple(e.get("failures", [])), tuple(e.get("warnings", [])))
        for path, e in ((p, _expected(p)) for p in FIXTURES)
    ]


BASELINE = _baseline()
SITES = _rule_sites()


def _margin(site: Site) -> int:
    """How many fixtures notice this site's removal."""
    mutated = _run_with_site_dropped(site)
    return sum(1 for was, now in zip(BASELINE, mutated, strict=True) if was != now)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{s.kind}:{s.lineno}:{s.code}")
def test_each_rule_is_load_bearing_for_some_fixture(site: Site) -> None:
    """Deleting an obligation must change at least one fixture's outcome.

    An obligation can be named by a fixture and still not be load-bearing: if another
    rule fires on the same input, removing this one changes nothing, and a conforming
    implementation could skip it entirely while passing.
    """
    assert _margin(site) > 0, (
        f"removing the site that emits {site.code!r} (line {site.lineno}, {site.kind}) "
        "changed no fixture outcome. No vector distinguishes an implementation that "
        "performs this check from one that skips it."
    )


def test_margins_have_not_thinned() -> None:
    """A ratchet, not a threshold: coverage may not silently get thinner.

    A young suite legitimately sits at margin 1 for most obligations, so a threshold
    would either fail on day one or be set so low it never fires. Recording the current
    margins and failing on a decrease says only that a change which reduces coverage has
    to be deliberate. Raising a recorded margin is an ordinary PR; lowering one is a
    decision someone has to make on purpose.
    """
    current = {f"{s.code}@{s.kind}": _margin(s) for s in SITES}

    if not MARGINS_FILE.exists():
        MARGINS_FILE.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip(f"recorded initial margins to {MARGINS_FILE.name}; re-run to enforce")

    recorded: dict[str, int] = json.loads(MARGINS_FILE.read_text(encoding="utf-8"))
    thinned = {
        key: (recorded[key], current[key])
        for key in recorded
        if key in current and current[key] < recorded[key]
    }
    assert not thinned, (
        "coverage thinned for: "
        + ", ".join(f"{k} {was}->{now}" for k, (was, now) in sorted(thinned.items()))
        + f". If the reduction is intended, update {MARGINS_FILE.name} in the same commit "
        "and say why."
    )

    vanished = sorted(set(recorded) - set(current))
    assert not vanished, (
        f"obligations that had recorded margins no longer exist: {vanished}. If they were "
        f"removed on purpose, drop them from {MARGINS_FILE.name} in the same commit."
    )
