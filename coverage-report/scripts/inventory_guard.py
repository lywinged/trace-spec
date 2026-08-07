"""Close section 6.4(b): fail loudly on any rule the inventory would silently miss.

The audited inventory recovers rules by matching exactly one shape —
`failures.append("string-literal")` with a single constant argument. That is drift-proof
against *forgetting to update a list*, which is the failure it was designed for. It is not
drift-proof against *writing the rule differently*: `failures.extend([...])`,
`failures += [...]`, `failures.append(f"...{x}")` and `failures.append(SOME_CONSTANT)` are
all invisible to it, and an invisible rule is examined by neither the named-coverage
criterion nor the load-bearing one, with nothing failing.

The existing vacuity guard does not help. It asserts the inventory is non-empty and of
plausible size, which catches the AST walk collapsing entirely, not the loss of one rule
out of nineteen.

So this module inverts the question. Instead of asking *what can the inventory recognise?*
it asks *is there anything here the inventory cannot recognise?* — and treats any such
thing as a failure demanding either the canonical idiom or an explicit declaration. That
converts an unrecognised rule from a silent omission into a red run, which is the design
principle of the source-recovered inventory applied consistently to itself.

Run: python inventory_guard.py [path-to-trace-spec]
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

RULE_COLLECTIONS = {"failures", "warnings"}

# Rules written in a shape the inventory cannot see, each with the reason it is tolerated.
# Empty for the same reason the audited suite's UNTESTABLE map is empty: an entry here is
# a claim that a rule may stay invisible, and that should have to survive review.
DECLARED_EXCEPTIONS: dict[str, str] = {}


class Finding:
    def __init__(self, lineno: int, kind: str, detail: str, source: str) -> None:
        self.lineno = lineno
        self.kind = kind
        self.detail = detail
        self.source = source

    def __str__(self) -> str:
        return f"  line {self.lineno:>4}  [{self.kind}] {self.detail}\n              {self.source}"


def _is_recognised_append(call: ast.Call) -> bool:
    """The one shape the audited inventory recovers."""
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "append"
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    )


def scan(path: Path) -> tuple[list[Finding], int, int]:
    """Return (findings, recognised_appends, inline_literal_codes)."""
    source_text = path.read_text(encoding="utf-8")
    lines = source_text.splitlines()
    tree = ast.parse(source_text)
    findings: list[Finding] = []
    recognised = 0
    inline_codes = 0

    def src(node: ast.AST) -> str:
        return lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else "?"

    for node in ast.walk(tree):
        # (1) Any method call on a rule collection.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            target = node.func.value
            if isinstance(target, ast.Name) and target.id in RULE_COLLECTIONS:
                if _is_recognised_append(node):
                    recognised += 1
                else:
                    findings.append(
                        Finding(
                            node.lineno,
                            "unrecognised-call",
                            f"{target.id}.{node.func.attr}(...) is not the "
                            "`append(\"literal\")` shape the inventory recovers",
                            src(node),
                        )
                    )

        # (2) Augmented assignment: `failures += [...]`.
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id in RULE_COLLECTIONS:
                findings.append(
                    Finding(
                        node.lineno,
                        "augmented-assign",
                        f"{node.target.id} is extended by augmented assignment, "
                        "which the inventory does not walk",
                        src(node),
                    )
                )

        # (3) Aliasing: `f = failures` puts every later `f.append(...)` out of reach,
        #     because the inventory keys on the *name* of the collection.
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
            if node.value.id in RULE_COLLECTIONS:
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id not in RULE_COLLECTIONS:
                        findings.append(
                            Finding(
                                node.lineno,
                                "alias",
                                f"{target.id} aliases {node.value.id}; appends through "
                                "the alias are invisible to the inventory",
                                src(node),
                            )
                        )

        # (4) Inline literal lists on early returns: `failures=[...]` / `warnings=[...]`.
        #     These *are* recovered for named coverage, and are never mutated, because the
        #     load-bearing test is parametrized over append-sites only. Counted, not
        #     failed — see the note this script prints.
        if isinstance(node, ast.keyword) and node.arg in RULE_COLLECTIONS:
            if isinstance(node.value, ast.List):
                inline_codes += sum(
                    1
                    for element in node.value.elts
                    if isinstance(element, ast.Constant) and isinstance(element.value, str)
                )

    return findings, recognised, inline_codes


def main() -> int:
    trace_spec = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else os.environ.get("TRACE_SPEC", os.path.expanduser("~/trace-spec"))
    )
    verifier = trace_spec / "tests" / "test_action_receipt_fixtures.py"
    print(f"verifier: {verifier}")
    print()

    findings, recognised, inline_codes = scan(verifier)
    live = [f for f in findings if f.source not in DECLARED_EXCEPTIONS]

    print(f"[inventory] {recognised} rule(s) in the recognised `append(\"literal\")` shape")
    print(f"[inventory] {inline_codes} code(s) emitted through inline literal lists")
    print()

    if live:
        print(f"[guard] {len(live)} rule(s) the inventory CANNOT see:")
        for finding in live:
            print(finding)
        print()
        print("  Each is a rule that neither criterion examines, with nothing failing.")
        print("  Rewrite in the canonical shape, or declare it in DECLARED_EXCEPTIONS")
        print("  with a reason that has to survive review.")
    else:
        print("[guard] no rule is written in a shape the inventory cannot recover")

    print()
    print(
        "[note] the "
        f"{inline_codes} inline-literal code(s) are checked for named coverage but are "
        "never\n       mutated: the load-bearing test is parametrized over append-sites "
        "only, so\n       those obligations never get the strong criterion. See "
        "mutation_report.py."
    )

    return 1 if live else 0


if __name__ == "__main__":
    raise SystemExit(main())
