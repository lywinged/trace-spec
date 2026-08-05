"""Completeness checks over the conformance vector sets.

The other modules ask whether the vectors are *correct*. This one asks whether they
are *complete*: does every rule the verifier implements have at least one vector that
notices when the rule is gone?

Nothing here is maintained by hand. The rule inventory is recovered from the verifier's
own source with `ast`, so a rule added without a vector is a failing test rather than a
silent hole. A hand-written catalogue would drift the moment someone adds a rule and
forgets the list, which is the failure mode this module exists to make impossible.

Three questions, in increasing strength:

1. Does any fixture expect a code the verifier cannot produce? (dead expectations)
2. Is every code the verifier can produce expected by some fixture? (unexercised rules)
3. Does deleting each rule break at least one fixture? (rules that are exercised but
   not *load-bearing* — a fixture can name a code and still pass without it, if another
   rule fires on the same input)

The third is the real definition, and the first two are cheaper diagnostics for the
same thing.
"""

from __future__ import annotations

import ast
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

TESTS_DIR = Path(__file__).parent
VERIFIER_MODULE = TESTS_DIR / "test_action_receipt_fixtures.py"
FIXTURE_DIR = TESTS_DIR.parent / "examples" / "action-receipts" / "conformance"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))

# Codes a verifier may emit that no fixture can reasonably pin down, with the reason.
# Kept empty on purpose: an entry here is a claim that a rule is untestable, which
# should have to be argued for in review rather than accumulated quietly.
UNTESTABLE: dict[str, str] = {}


def _source_tree() -> ast.Module:
    return ast.parse(VERIFIER_MODULE.read_text(encoding="utf-8"))


def _rule_sites() -> list[tuple[int, str, str]]:
    """Return (lineno, kind, code) for every `failures/warnings.append("literal")`."""
    sites: list[tuple[int, str, str]] = []
    for node in ast.walk(_source_tree()):
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr != "append":
            continue
        target = func.value
        if not isinstance(target, ast.Name) or target.id not in {"failures", "warnings"}:
            continue
        if len(call.args) != 1 or not isinstance(call.args[0], ast.Constant):
            continue
        value = call.args[0].value
        if isinstance(value, str):
            sites.append((node.lineno, target.id, value))
    return sites


def _declared_statuses() -> set[str]:
    """Every status the verifier can return, read from its source.

    Covers both `status="literal"` and the conditional form that assigns a status to a
    local first. Missing the second reported two real outcomes as unreachable.
    """
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
        # Only the branches of a conditional are statuses. Walking the whole value
        # would also collect the literal being compared against in the test — which
        # reported `"accepted"` as an unreachable outcome.
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


def _codes_expected_by_fixtures() -> dict[str, set[str]]:
    failures: set[str] = set()
    warnings: set[str] = set()
    for path in FIXTURES:
        expected = _expected(path)
        failures.update(expected.get("failures", []))
        warnings.update(expected.get("warnings", []))
    return {"failures": failures, "warnings": warnings}


def test_rule_inventory_was_actually_recovered() -> None:
    """If the AST walk silently matched nothing, every check below would pass vacuously."""
    sites = _rule_sites()
    assert len(sites) >= 15, f"expected the verifier to carry many rules, found {len(sites)}"
    assert _declared_statuses(), "no status values recovered from the verifier source"
    assert FIXTURES, "no fixtures found"


def test_no_fixture_expects_a_code_the_verifier_cannot_emit() -> None:
    """A fixture naming a code nothing produces is an expectation that can never fail."""
    emitted = {code for _, _, code in _rule_sites()}
    expected = _codes_expected_by_fixtures()
    # `receipt_missing` and the gap codes are produced by early returns rather than by
    # an append, so read those from the status/failure literals too.
    emitted |= _literal_failure_lists()

    orphans = (expected["failures"] | expected["warnings"]) - emitted
    assert not orphans, (
        "fixtures expect failure codes the verifier can never produce: "
        f"{sorted(orphans)}. Either the rule was removed and the fixture kept, or the "
        "code is misspelled — in both cases the fixture is no longer testing anything."
    )


def _literal_failure_lists() -> set[str]:
    """Codes appearing in inline `failures=[...]` / `warnings=[...]` arguments.

    Both kinds matter. Scanning only `failures` reported `receipt_gap_disclosed` as a
    code no rule could produce, when the verifier emits it as a warning on an early
    return rather than through an append.
    """
    codes: set[str] = set()
    for node in ast.walk(_source_tree()):
        if isinstance(node, ast.keyword) and node.arg in {"failures", "warnings"}:
            if isinstance(node.value, ast.List):
                for element in node.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        codes.add(element.value)
    return codes


def test_every_verifier_rule_is_exercised_by_some_fixture() -> None:
    """Every code the verifier can emit must be pinned down by at least one vector."""
    emitted = {code for _, kind, code in _rule_sites()} | _literal_failure_lists()
    expected = _codes_expected_by_fixtures()
    covered = expected["failures"] | expected["warnings"]

    unexercised = sorted(emitted - covered - set(UNTESTABLE))
    assert not unexercised, (
        f"{len(unexercised)} verifier rule(s) have no conformance vector: "
        f"{unexercised}. Each is a check a conforming implementation could omit "
        "entirely and still pass this suite."
    )


def test_every_declared_outcome_is_reached_by_some_fixture() -> None:
    reachable = _declared_statuses()
    reached = {_expected(path)["status"] for path in FIXTURES}

    unreached = sorted(reachable - reached)
    assert not unreached, (
        f"outcomes the verifier can return that no fixture produces: {unreached}"
    )
    invented = sorted(reached - reachable)
    assert not invented, (
        f"fixtures expect outcomes the verifier cannot return: {invented}"
    )


def _run_with_rule_dropped(lineno: int) -> list[tuple[str, str]]:
    """Re-execute the verifier with one rule removed; return (fixture, status) pairs."""
    tree = _source_tree()

    class Drop(ast.NodeTransformer):
        def visit_Expr(self, node: ast.Expr) -> ast.AST:
            # Replaced with `pass`, not deleted: a rule that is the sole body of an
            # `if` or an `except` would otherwise leave an empty block and the mutant
            # would fail to compile, which reads as "the rule matters" for the wrong
            # reason.
            return ast.copy_location(ast.Pass(), node) if node.lineno == lineno else node

    mutated = ast.fix_missing_locations(Drop().visit(tree))

    # The mutant must be a real, registered module: `@dataclass` resolves
    # `sys.modules[cls.__module__]`, so exec'ing into a bare dict raises before a
    # single fixture runs — which would read as "every rule matters" while actually
    # testing nothing.
    name = f"_mutant_verifier_{lineno}"
    module = types.ModuleType(name)
    module.__file__ = str(VERIFIER_MODULE)
    sys.modules[name] = module
    try:
        exec(compile(mutated, str(VERIFIER_MODULE), "exec"), module.__dict__)  # noqa: S102
        verify = module.__dict__["_verify_fixture"]
        return _statuses(verify)
    finally:
        del sys.modules[name]


def _statuses(verify: Any) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for path in FIXTURES:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        try:
            result = verify(fixture)
            results.append((path.name, result.status))
        except Exception as exc:  # a rule removal that breaks the verifier still counts
            results.append((path.name, f"raised:{type(exc).__name__}:{exc}"))
    return results


BASELINE = [(path.name, _expected(path)["status"]) for path in FIXTURES]


@pytest.mark.parametrize(
    "lineno,kind,code",
    _rule_sites(),
    ids=lambda value: value if isinstance(value, str) else str(value),
)
def test_each_rule_is_load_bearing_for_some_fixture(lineno: int, kind: str, code: str) -> None:
    """Deleting a rule must change at least one fixture's outcome.

    A rule can be named by a fixture and still not be load-bearing: if another rule
    fires on the same input, removing this one changes nothing and a conforming
    implementation could skip it entirely while passing the suite. Warnings are
    exempt because they do not alter the outcome by design.
    """
    if kind == "warnings":
        pytest.skip("warnings do not change the outcome, so dropping one cannot")

    mutated = _run_with_rule_dropped(lineno)
    changed = [
        (name, was, now)
        for (name, was), (_, now) in zip(BASELINE, mutated, strict=True)
        if was != now
    ]
    assert changed, (
        f"removing the rule that emits {code!r} (line {lineno}) changed no fixture "
        "outcome. No vector distinguishes an implementation that performs this check "
        "from one that skips it."
    )
