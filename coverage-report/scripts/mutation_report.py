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
takes the same path and does not report the finding — and which is invisible to a
status-only oracle, so it also demonstrates why (5) is needed.

Run: python mutation_report.py [path-to-trace-spec]
"""

from __future__ import annotations

import ast
import json
import os
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TRACE_SPEC = Path(
    sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_SPEC", os.path.expanduser("~/trace-spec"))
)
VERIFIER = TRACE_SPEC / "tests" / "test_action_receipt_fixtures.py"
FIXTURE_DIR = TRACE_SPEC / "examples" / "action-receipts" / "conformance"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))

sys.path.insert(0, str(TRACE_SPEC / "tests"))

# Rules a vector set may leave unmutated, each with the reason. Consulted by *every*
# criterion here — the audited implementation consults its equivalent for named coverage
# and not for load-bearing, which is latent rather than live only because the map is empty.
UNTESTABLE: dict[str, str] = {}


@dataclass(frozen=True)
class Site:
    lineno: int
    kind: str  # "failures" | "warnings"
    code: str
    form: str  # "append" | "inline"


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
    return sites


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
    tree = _tree()

    class DropAppend(ast.NodeTransformer):
        def visit_Expr(self, node: ast.Expr) -> ast.AST:
            # `pass`, not deletion: a rule that is the sole body of an `if` would leave an
            # empty block, the mutant would fail to compile, and every vector would
            # "change" — scoring the rule load-bearing for the wrong reason, uniformly.
            return ast.copy_location(ast.Pass(), node) if node.lineno == site.lineno else node

    class DropInline(ast.NodeTransformer):
        def visit_keyword(self, node: ast.keyword) -> ast.AST:
            self.generic_visit(node)
            if node.arg in {"failures", "warnings"} and isinstance(node.value, ast.List):
                node.value.elts = [
                    element
                    for element in node.value.elts
                    if not (
                        isinstance(element, ast.Constant)
                        and element.value == site.code
                        and element.lineno == site.lineno
                    )
                ]
            return node

    transformer = DropAppend() if site.form == "append" else DropInline()
    mutated = ast.fix_missing_locations(transformer.visit(tree))

    # A real, registered module: `@dataclass` resolves sys.modules[cls.__module__], so
    # exec'ing into a bare dict raises before any vector runs — which reads as "every rule
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
          f"{sum(1 for s in sites if s.form == 'inline')} inline)")
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
