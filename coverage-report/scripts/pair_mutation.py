"""Section 8.1 item 6 — second-order mutation, to test the masking claim in section 7.5.

The paper asserts that first-order mutation cannot see mutual masking: *two rules that
always co-fire can each be individually load-bearing while no vector distinguishes an
implementation that performs one from an implementation that performs both.* That was
asserted, not measured. This measures it.

The question has to be posed carefully, because the obvious version is trivially true.
Asking "does dropping both rules change some vector?" always answers yes when each rule is
individually load-bearing — the joint mutant inherits both effects. That is not the
conformance question anyone cares about.

The question that matters is **conditional**:

> Given an implementation that already omits rule *b*, is additionally omitting rule *a*
> detectable?

Formally, *a* is **masked by** *b* when `outcomes(drop {a, b}) == outcomes(drop {b})`. If
they are equal, then once *b* is gone, *a* is free: no vector in the set distinguishes an
implementation that skips both from one that skips only *b*. A certification suite that
permits this is issuing a mark that means less for a partially-conformant implementation
than it does for a fully-conformant one — and partial conformance is the realistic case.

This matters here in particular because the margin distribution is 1 almost everywhere
(section 6.3). A rule held up by a single vector is a rule whose enforcement depends on
that vector still discriminating in the presence of other omissions, and nothing measured
so far establishes that it does.

Run: python pair_mutation.py [path-to-trace-spec]
"""

from __future__ import annotations

import ast
import itertools
import json
import sys
import types
from pathlib import Path
from typing import Any

from mutation_report import FIXTURES, TRACE_SPEC, VERIFIER, Site, _outcomes, _sites


def _run_mutant(sites: list[Site]) -> list[tuple[str, str, tuple, tuple]]:
    """Re-execute the verifier with an arbitrary set of emission sites neutralised.

    Same two precautions as the first-order case, for the same reasons: `pass` rather than
    deletion, so a rule that is the sole body of an `if` does not leave an empty block and
    a mutant that fails to compile; and a real registered module, so `@dataclass` can
    resolve `sys.modules[cls.__module__]` instead of raising before any vector runs.
    """
    tree = ast.parse(VERIFIER.read_text(encoding="utf-8"))
    append_lines = {s.lineno for s in sites if s.form == "append"}
    inline = {(s.lineno, s.code) for s in sites if s.form == "inline"}

    class Drop(ast.NodeTransformer):
        def visit_Expr(self, node: ast.Expr) -> ast.AST:
            return ast.copy_location(ast.Pass(), node) if node.lineno in append_lines else node

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

    mutated = ast.fix_missing_locations(Drop().visit(tree))
    name = "_mutant_pair_" + "_".join(f"{s.form}{s.lineno}" for s in sites)
    module = types.ModuleType(name)
    module.__file__ = str(VERIFIER)
    sys.modules[name] = module
    try:
        exec(compile(mutated, str(VERIFIER), "exec"), module.__dict__)  # noqa: S102
        return _outcomes(module.__dict__["_verify_fixture"])
    finally:
        del sys.modules[name]


def main() -> int:
    import test_action_receipt_fixtures as reference

    baseline = _outcomes(reference._verify_fixture)
    sites = _sites()
    single = {site.code: _run_mutant([site]) for site in sites}

    print(f"verifier: {VERIFIER}")
    print(f"sites:    {len(sites)}   pairs: {len(sites) * (len(sites) - 1) // 2}")
    print()

    masked: list[tuple[str, str]] = []
    joint_invisible: list[tuple[str, str]] = []
    evaluated = 0

    for first, second in itertools.combinations(sites, 2):
        joint = _run_mutant([first, second])
        evaluated += 1

        if joint == baseline:
            joint_invisible.append((first.code, second.code))

        # Conditional detectability, in both directions.
        if joint == single[second.code]:
            masked.append((first.code, second.code))
        if joint == single[first.code]:
            masked.append((second.code, first.code))

    print(f"[pairs] evaluated {evaluated} joint mutants")
    print()

    if joint_invisible:
        print(f"[joint] {len(joint_invisible)} pair(s) whose JOINT removal no vector notices:")
        for a, b in joint_invisible:
            print(f"  {{{a}, {b}}}")
    else:
        print("[joint] every pair's joint removal is noticed by some vector")
    print()

    if masked:
        print(f"[masking] {len(masked)} ordered pair(s) where the first is free once the")
        print("          second is already omitted — no vector distinguishes an")
        print("          implementation skipping both from one skipping only the second:")
        for a, b in masked:
            print(f"  {a}  is masked by  {b}")
    else:
        print("[masking] no rule is masked by any other: for every pair, omitting the")
        print("          second does not make omitting the first free.")

    return 1 if (masked or joint_invisible) else 0


if __name__ == "__main__":
    raise SystemExit(main())
