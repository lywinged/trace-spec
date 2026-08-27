"""Sections 8.1 items 3, 4, 5 and the gap the guard surfaced.

Four changes to the audited load-bearing test, each of which either strengthens the
criterion or reports something the boolean form hides.

**(3) Margin, not a boolean.** The audited test asserts that *some* vector notices a
dropped rule. It does not say how many. A suite where every rule is held up by one vector
and a suite where every rule is held up by four both "pass", and they are not equally
robust: in the first, editing any single vector silently returns its rule to
unenforceable. Report the distribution.

**(4) Attribution.** The audited test is satisfied when *any* vector's outcome changes. It
should be satisfied only when the vector that *names* the rule is among them. A rule can
otherwise be load-bearing because some unrelated vector happens to shift, which meets the
letter of the criterion while leaving the vector that claims to test the rule untested for
exactly that.

**(5) Full outcomes, not just status.** The audited test compares statuses. Two rules
returning the same status on the same input mask each other at that granularity. The finer
oracle costs nothing.

**(new) Early-return rules get mutated too.** The audited load-bearing test is parametrized
over `append` sites only, so codes emitted through inline `failures=[...]` /
`warnings=[...]` arguments on early returns are checked for named coverage and never
mutated. Those obligations never receive the strong criterion at all. Here they are
mutated by deleting the code from the literal list, which models an implementation that
takes the same path and does not report the finding, and which is invisible to a
status-only oracle, so it also demonstrates why (5) is needed.

Run: python mutation_report.py [path-to-trace-spec]
"""

from __future__ import annotations

import ast
import json
import os
import sys
import types
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TRACE_SPEC = Path(
    sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_SPEC", os.path.expanduser("~/trace-spec"))
)
VERIFIER = TRACE_SPEC / "tests" / "test_action_receipt_fixtures.py"
FIXTURE_DIR = TRACE_SPEC / "examples" / "action-receipts" / "conformance"

sys.path.insert(0, str(TRACE_SPEC / "tests"))

# Discovery comes from the verifier module rather than being restated here. A flat
# `glob("*.json")` stood here and saw thirty of forty-eight vectors: everything one
# directory down, in `conformance/proposal-117/`, was invisible. That is not a
# miscount, it changes the answers. `receipt_gap_disclosed` is held by exactly two
# vectors and both are down there, so this script reported the obligation as held by
# nothing and exited non-zero, and `pair_mutation` and `triple_mutation`, which
# import FIXTURES from here: reported "no rule is masked" and "nothing new at rank
# three" over a corpus missing a fifth of itself, exiting zero while doing it.
#
# It is the defect of agentrust-io/trace-spec#208, which upstream closed for its two
# readers with a shared `discover_fixtures`. Importing that same function is what
# stops a third reader from drifting away from them again.
from test_action_receipt_fixtures import discover_fixtures  # noqa: E402

FIXTURES = discover_fixtures(FIXTURE_DIR)

# Rules a vector set may leave unmutated, each with the reason. Consulted by *every*
# criterion here: the audited implementation consults its equivalent for named coverage
# and not for load-bearing, which is latent rather than live only because the map is empty.
UNTESTABLE: dict[str, str] = {}


@dataclass(frozen=True)
class Site:
    lineno: int
    kind: str  # "failures" | "warnings"
    code: str
    form: str  # "append" | "inline" | "registry"


def _tree() -> ast.Module:
    return ast.parse(VERIFIER.read_text(encoding="utf-8"))


def _sites() -> list[Site]:
    """Every place the verifier emits a code, in either form."""
    sites: list[Site] = []
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            func = call.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "append"
                and isinstance(func.value, ast.Name)
                and func.value.id in {"failures", "warnings"}
                and len(call.args) == 1
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, str)
            ):
                sites.append(Site(node.lineno, func.value.id, call.args[0].value, "append"))
        if isinstance(node, ast.keyword) and node.arg in {"failures", "warnings"}:
            if isinstance(node.value, ast.List):
                for element in node.value.elts:
                    if isinstance(element, ast.Constant) and isinstance(element.value, str):
                        sites.append(Site(element.lineno, node.arg, element.value, "inline"))

        # The verifier's obligations live in an explicit `RULES` registry, and a rule
        # there emits its code through the registry rather than through either literal
        # form above. Discovering only the literal forms is how this tooling came to
        # mutate one site against a registry of twenty-two: the registry refactor moved
        # every obligation out of reach at once, and all three scripts kept printing a
        # clean result over what was left. A rule is a `Rule("code", "severity", ...)`
        # element of the tuple, and neutralising it means removing that element.
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == "RULES" for t in targets) and isinstance(
                node.value, (ast.Tuple, ast.List)
            ):
                for element in node.value.elts:
                    if (
                        isinstance(element, ast.Call)
                        and isinstance(element.func, ast.Name)
                        and element.func.id == "Rule"
                        and len(element.args) >= 2
                        and isinstance(element.args[0], ast.Constant)
                        and isinstance(element.args[0].value, str)
                        and isinstance(element.args[1], ast.Constant)
                    ):
                        kind = "failures" if element.args[1].value == "failure" else "warnings"
                        sites.append(
                            Site(element.lineno, kind, element.args[0].value, "registry")
                        )
    return sites


def drop_sites(tree: ast.Module, sites: Sequence[Site]) -> ast.Module:
    """Neutralise every site in *sites*, in whichever form each one takes.

    One transformer, imported by `pair_mutation` and `triple_mutation` rather than
    restated in each. Three separately maintained copies is how a form can be added to
    discovery and silently not applied by two of the three readers: the mutants come
    out identical to the baseline, no vector's outcome changes, and the rule is scored
    unheld for a reason that has nothing to do with vectors.
    """
    append_lines = {s.lineno for s in sites if s.form == "append"}
    inline = {(s.lineno, s.code) for s in sites if s.form == "inline"}
    registry = {(s.lineno, s.code) for s in sites if s.form == "registry"}

    class Drop(ast.NodeTransformer):
        def visit_Expr(self, node: ast.Expr) -> ast.AST:
            # `pass`, not deletion: a rule that is the sole body of an `if` would leave an
            # empty block, the mutant would fail to compile, and every vector would
            # "change": scoring the rule load-bearing for the wrong reason, uniformly.
            return (
                ast.copy_location(ast.Pass(), node) if node.lineno in append_lines else node
            )

        def visit_keyword(self, node: ast.keyword) -> ast.AST:
            self.generic_visit(node)
            if node.arg in {"failures", "warnings"} and isinstance(node.value, ast.List):
                node.value.elts = [
                    element
                    for element in node.value.elts
                    if not (
                        isinstance(element, ast.Constant)
                        and (element.lineno, element.value) in inline
                    )
                ]
            return node

        def _drop_rules(self, node: ast.AST) -> ast.AST:
            if isinstance(node.value, (ast.Tuple, ast.List)):
                node.value.elts = [
                    element
                    for element in node.value.elts
                    if not (
                        isinstance(element, ast.Call)
                        and element.args
                        and isinstance(element.args[0], ast.Constant)
                        and (element.lineno, element.args[0].value) in registry
                    )
                ]
            return node

        def visit_Assign(self, node: ast.Assign) -> ast.AST:
            self.generic_visit(node)
            if any(isinstance(t, ast.Name) and t.id == "RULES" for t in node.targets):
                return self._drop_rules(node)
            return node

        def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AST:
            self.generic_visit(node)
            if isinstance(node.target, ast.Name) and node.target.id == "RULES":
                return self._drop_rules(node)
            return node

    return ast.fix_missing_locations(Drop().visit(tree))


def declared_obligations() -> set[str]:
    """The obligations the verifier itself declares, read from its own registry.

    Empty when the verifier has no registry, which is the pre-refactor shape: the
    reconciliation below then asserts nothing rather than failing on every tree.
    """
    import test_action_receipt_fixtures as reference

    return {rule.code for rule in getattr(reference, "RULES", ())}


def reconcile_or_refuse(sites: Sequence[Site]) -> None:
    """Refuse to report when discovery cannot see the verifier's own inventory.

    Every conclusion these scripts print is a claim about obligations, so it is only
    as wide as the set of obligations discovery can reach. When that set and the
    verifier's declared set disagree, the honest output is no output. This tooling
    found one site against a registry of twenty-two and printed "every obligation is
    held by at least one vector", which is the same sentence a suite containing no
    checks at all would produce, and there is no way to tell the two apart from the
    output. Exit 2, distinct from the exit 1 a real coverage gap earns.

    A verifier with no registry declares no inventory, so there is nothing to
    reconcile against and this check passes vacuously on such a tree. That is the
    limit of the guard rather than an oversight: partial blindness is only
    detectable against a declaration of what should have been found, which is the
    argument for the registry existing. What is still caught on such a tree is
    discovery finding nothing at all.
    """
    if not sites:
        print(
            "\nREFUSING TO REPORT: site discovery found nothing to mutate.\n"
            "An empty table under a heading that says every obligation is held is\n"
            "the most confident output this script can produce and the least earned.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    declared = declared_obligations()
    missing = sorted(declared - {site.code for site in sites})
    if not missing:
        return
    print(
        f"\nREFUSING TO REPORT: {len(missing)} of {len(declared)} declared obligations "
        f"are invisible to site discovery.",
        file=sys.stderr,
    )
    for code in missing:
        print(f"    {code}", file=sys.stderr)
    print(
        "\nThe verifier declares these in its RULES registry and discovery found no\n"
        "mutable site for them. Any coverage conclusion would be drawn over a fraction\n"
        "of the inventory, so none is printed. Fix discovery first.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _outcomes(verify: Any) -> list[tuple[str, str, tuple, tuple]]:
    """(fixture, status, failures, warnings) for every vector."""
    results = []
    for path in FIXTURES:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        try:
            result = verify(fixture)
            results.append(
                (
                    path.name,
                    result.status,
                    tuple(sorted(result.failures)),
                    tuple(sorted(result.warnings)),
                )
            )
        except Exception as exc:
            results.append((path.name, f"raised:{type(exc).__name__}", (), ()))
    return results


def _run_mutant(site: Site) -> list[tuple[str, str, tuple, tuple]]:
    """Re-execute the verifier with one code-emission site neutralised."""
    mutated = drop_sites(_tree(), [site])

    # A real, registered module: `@dataclass` resolves sys.modules[cls.__module__], so
    # exec'ing into a bare dict raises before any vector runs, which reads as "every rule
    # matters" while testing nothing.
    name = f"_mutant_{site.form}_{site.lineno}"
    module = types.ModuleType(name)
    module.__file__ = str(VERIFIER)
    sys.modules[name] = module
    try:
        exec(compile(mutated, str(VERIFIER), "exec"), module.__dict__)  # noqa: S102
        return _outcomes(module.__dict__["_verify_fixture"])
    finally:
        del sys.modules[name]


def _names_rule(path: Path, code: str) -> bool:
    expected = json.loads(path.read_text(encoding="utf-8"))["expected"]
    return code in set(expected.get("failures", [])) | set(expected.get("warnings", []))


def main() -> int:
    import test_action_receipt_fixtures as reference

    baseline = _outcomes(reference._verify_fixture)
    sites = _sites()
    naming = {
        site.code: {p.name for p in FIXTURES if _names_rule(p, site.code)} for site in sites
    }

    print(f"verifier: {VERIFIER}")
    print(f"vectors:  {len(FIXTURES)}")
    print(f"sites:    {len(sites)} "
          f"({sum(1 for s in sites if s.form == 'append')} append, "
          f"{sum(1 for s in sites if s.form == 'inline')} inline, "
          f"{sum(1 for s in sites if s.form == 'registry')} registry)")
    reconcile_or_refuse(sites)
    print()
    header = f"{'code':<40} {'form':<7} {'status':>6} {'full':>5} {'attributed':>11}"
    print(header)
    print("-" * len(header))

    rows = []
    unheld: list[str] = []
    unattributed: list[str] = []

    for site in sorted(sites, key=lambda s: (s.form, s.code)):
        if site.code in UNTESTABLE:
            continue
        mutant = _run_mutant(site)

        status_margin = sum(1 for b, m in zip(baseline, mutant) if b[1] != m[1])
        full_margin = sum(1 for b, m in zip(baseline, mutant) if b != m)
        changed = {b[0] for b, m in zip(baseline, mutant) if b != m}

        namers = naming[site.code]
        attributed = bool(namers & changed) if namers else False
        mark = "yes" if attributed else ("NO NAMER" if not namers else "NO")

        rows.append((site, status_margin, full_margin, attributed))
        print(f"{site.code:<40} {site.form:<7} {status_margin:>6} {full_margin:>5} {mark:>11}")

        if full_margin == 0:
            unheld.append(f"{site.code} ({site.form}, line {site.lineno})")
        elif not attributed:
            unattributed.append(
                f"{site.code}: changed {sorted(changed)}, but the vector(s) naming it "
                f"{sorted(namers) or '(none)'} did not"
            )

    print()
    status_margins = [r[1] for r in rows]
    full_margins = [r[2] for r in rows]
    print("[margins] status-only : "
          f"min={min(status_margins)} max={max(status_margins)} "
          f"mean={sum(status_margins) / len(status_margins):.2f}")
    print("[margins] full outcome: "
          f"min={min(full_margins)} max={max(full_margins)} "
          f"mean={sum(full_margins) / len(full_margins):.2f}")
    only_full = [r[0].code for r in rows if r[1] == 0 and r[2] > 0]
    if only_full:
        print(f"[margins] detectable ONLY with the finer oracle: {only_full}")
        print("          a status-only criterion reports these as unheld obligations.")
    print()

    if unheld:
        print(f"[load-bearing] {len(unheld)} obligation(s) NOT held by any vector:")
        for line in unheld:
            print(f"  {line}")
    else:
        print("[load-bearing] every obligation is held by at least one vector")
    print()

    if unattributed:
        print(f"[attribution] {len(unattributed)} rule(s) load-bearing via the wrong vector:")
        for line in unattributed:
            print(f"  {line}")
    else:
        print("[attribution] every rule is held by a vector that names it")

    return 1 if (unheld or unattributed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
