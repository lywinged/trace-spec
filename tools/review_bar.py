#!/usr/bin/env python3
"""Re-run the two library-fix checks CONTRIBUTING.md asks a pull request to describe.

"Before a pull request is reviewed" asks a change to code under ``src/`` that fixes
a bug, or makes code reject input it used to accept, to show a test that fails
when the change is switched off, and one other fix run against the tests. A
description can say both without anyone having run either. This tool runs them,
so the reviewer reads a result instead of a claim. It reports and never fails the
build: what it finds is evidence for the reviewer, not a verdict.

Base run
    The pull request's new and changed test files are put on top of the merge
    base, so they run against the code as it was before the change. Each
    outcome is sorted by why it happened. A test that fails on an assertion, or
    on ``pytest.raises`` not raising, fails on behaviour: that is the test the
    contribution guide asks for. A test that fails only because a module,
    function, attribute or keyword the change adds is missing fails on a name,
    which any test of new code does whatever the code does, and it is listed
    apart so it is not read as evidence. The sorting reads the failure's text,
    so a test that fails because of a signature the change adds without saying
    so still lands under behaviour. That is why the mutants come second and
    count for more.

Mutants
    Each line the pull request adds under ``src/`` is a site for small edits a
    reviewer might have written instead: a ``raise`` deleted, a comparison
    weakened or flipped, ``and`` and ``or`` swapped. The changed test files run
    against each one. A mutant they still pass is a fix the tests cannot tell
    apart from the one submitted, and it is listed by file and line. Only the
    changed tests run, which keeps the job inside a pull request's time budget
    and asks the right question: whether the tests that came with the change
    can see it.

Usage: ``python tools/review_bar.py --base BASE --head HEAD [--summary PATH]``.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# A failure whose text says a name is missing. Anything else that fails is
# behaviour: an AssertionError, pytest's "DID NOT RAISE", or a wrong exception.
# An attribute missing from None is behaviour too: something returned None.
MISSING_NAME = re.compile(
    r"\b(ImportError|ModuleNotFoundError|NameError)\b"
    r"|\bAttributeError: (?!'NoneType')\S.*\bhas no attribute\b"
    r"|\bTypeError\b.*(unexpected keyword argument|missing \d+ required"
    r"|takes \d+ positional arguments? but \d+ (were|was) given)"
)

def missing_name(text: str, new_names: frozenset[str] = frozenset()) -> bool:
    """Whether a failure's text says a name is missing, or names one the change adds.

    The second half catches what the exception type alone does not: a signature
    read with ``inspect`` and a ``KeyError`` on the new parameter, or a table of
    keyword arguments that now includes one the old function rejects.
    """
    if MISSING_NAME.search(text):
        return True
    return any(re.search(rf"(?<!\w){re.escape(n)}(?!\w)", text) for n in new_names)


SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.In: ast.NotIn, ast.NotIn: ast.In,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
}
OP_TEXT = {
    ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!=",
    ast.In: "in", ast.NotIn: "not in", ast.Is: "is", ast.IsNot: "is not",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout


def export(repo: Path, rev: str, dest: Path) -> None:
    """Write the tree at *rev* into *dest*, without .git."""
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", rev], capture_output=True, check=True
    ).stdout
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive, check=True)


def changed(repo: Path, base: str, head: str) -> tuple[list[str], list[str]]:
    """Test files and src Python files added or modified between base and head."""
    tests, src = [], []
    for line in git(repo, "diff", "--name-status", "--no-renames", base, head).splitlines():
        status, path = line.split("\t", 1)
        if status not in ("A", "M"):
            continue
        name = path.rsplit("/", 1)[-1]
        if path.startswith("tests/") and name.startswith("test_") and name.endswith(".py"):
            tests.append(path)
        elif path.startswith("src/") and path.endswith(".py"):
            src.append(path)
    return sorted(tests), sorted(src)


def added_lines(repo: Path, base: str, head: str, path: str) -> set[int]:
    """Line numbers in *head*'s copy of *path* that the diff adds."""
    lines: set[int] = set()
    for hunk in re.finditer(
        r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@",
        git(repo, "diff", "-U0", base, head, "--", path),
        re.M,
    ):
        start, count = int(hunk.group(1)), int(hunk.group(2) or "1")
        lines.update(range(start, start + count))
    return lines


def _names(source: str) -> set[str]:
    """Functions, classes, parameters and module-level names a module defines."""
    found: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            found.update(x.arg for x in [*a.posonlyargs, *a.args, *a.kwonlyargs])
    for node in tree.body:
        if isinstance(node, ast.Assign):
            found.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return found


def added_names(repo: Path, base: str, head: str, src: list[str]) -> set[str]:
    """Names the change adds under ``src/``, by comparing each module's definitions."""
    added: set[str] = set()
    for path in src:
        after = _names(git(repo, "show", f"{head}:{path}"))
        try:
            before = _names(git(repo, "show", f"{base}:{path}"))
        except subprocess.CalledProcessError:
            before = set()
        added |= after - before
    # Short names are too common to tell a test's text about them from anything else.
    return {n for n in added if len(n) >= 4}


@dataclass
class Outcome:
    test: str
    result: str  # passed, skipped, behaviour, name
    detail: str = ""


def run_tests(
    tree: Path, tests: list[str], timeout: int, new_names: frozenset[str] = frozenset()
) -> tuple[int, list[Outcome]]:
    """Run *tests* in *tree*; return pytest's exit code and each test's outcome."""
    junit = tree / ".review-bar-junit.xml"
    env = {**os.environ, "PYTHONPATH": str(tree / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             "-o", "addopts=", "--continue-on-collection-errors",
             f"--junitxml={junit}", *tests],
            cwd=tree, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return -1, []
    outcomes = []
    if junit.exists():
        for case in ET.parse(junit).getroot().iter("testcase"):
            name = f"{case.get('classname', '')}::{case.get('name', '')}".strip(":")
            bad = case.find("failure")
            if bad is None:
                bad = case.find("error")
            if bad is not None:
                text = f"{bad.get('message', '')}\n{bad.text or ''}"
                # A file that cannot be collected on the base has not failed on the
                # bug: it is missing something the change adds, a module or a file.
                collect = bad.tag == "error" and "collection failure" in text
                kind = "name" if collect or missing_name(text, new_names) else "behaviour"
                first = (bad.get("message") or "").splitlines()[:1]
                outcomes.append(Outcome(name, kind, first[0][:160] if first else ""))
            elif case.find("skipped") is not None:
                outcomes.append(Outcome(name, "skipped"))
            else:
                outcomes.append(Outcome(name, "passed"))
        junit.unlink()
    return proc.returncode, outcomes


@dataclass
class Mutant:
    path: str
    line: int
    edit: str
    status: str = ""  # killed, survived, timeout


class _Sites(ast.NodeVisitor):
    def __init__(self, lines: set[int]) -> None:
        self.lines = lines
        self.sites: list[tuple[int, str, ast.AST | _Op]] = []

    def visit_Raise(self, node: ast.Raise) -> None:
        if node.lineno in self.lines:
            self.sites.append((node.lineno, "delete the raise", node))
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if node.lineno in self.lines:
            for i, op in enumerate(node.ops):
                swap = SWAPS.get(type(op))
                if swap is not None:
                    edit = f"{OP_TEXT[type(op)]} becomes {OP_TEXT[swap]}"
                    self.sites.append((node.lineno, edit, _Op(node, i, swap)))
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if node.lineno in self.lines:
            edit = "and becomes or" if isinstance(node.op, ast.And) else "or becomes and"
            self.sites.append((node.lineno, edit, node))
        self.generic_visit(node)


@dataclass
class _Op:
    node: ast.Compare
    index: int
    swap: type[ast.cmpop]
    lineno: int = field(init=False)

    def __post_init__(self) -> None:
        self.lineno = self.node.lineno


def _mutate(source: str, site: int) -> str:
    """Return *source* with the *site*-th mutation, in visit order, applied."""
    tree = ast.parse(source)
    lines = {n.lineno for n in ast.walk(tree) if hasattr(n, "lineno")}
    sites = _Sites(lines)
    sites.visit(tree)
    _, _, target = sites.sites[site]
    if isinstance(target, _Op):
        target.node.ops[target.index] = target.swap()
    elif isinstance(target, ast.BoolOp):
        target.op = ast.Or() if isinstance(target.op, ast.And) else ast.And()
    else:
        for parent in ast.walk(tree):
            for _field, value in ast.iter_fields(parent):
                if isinstance(value, list) and target in value:
                    value[value.index(target)] = ast.copy_location(ast.Pass(), target)
    return ast.unparse(ast.fix_missing_locations(tree))


def mutants(repo: Path, base: str, head: str, src: list[str]) -> list[tuple[Mutant, str]]:
    """Every mutant on a line *head* adds, with the mutated source it needs."""
    out = []
    for path in src:
        source = git(repo, "show", f"{head}:{path}")
        tree = ast.parse(source)
        lines = added_lines(repo, base, head, path)
        everywhere = _Sites({n.lineno for n in ast.walk(tree) if hasattr(n, "lineno")})
        everywhere.visit(tree)
        for index, (line, edit, _) in enumerate(everywhere.sites):
            if line in lines:
                out.append((Mutant(path, line, edit), _mutate(source, index)))
    return out


@dataclass
class Report:
    base: str
    head: str
    tests: list[str]
    src: list[str]
    base_exit: int | None = None
    base_outcomes: list[Outcome] = field(default_factory=list)
    mutants: list[Mutant] = field(default_factory=list)
    skipped_mutants: int = 0
    notes: list[str] = field(default_factory=list)

    def markdown(self) -> str:
        out = [f"## Review bar: {self.base[:7]}..{self.head[:7]}", ""]
        if self.notes:
            out += [f"- {n}" for n in self.notes] + [""]
        if self.base_exit is not None:
            behaviour = [o for o in self.base_outcomes if o.result == "behaviour"]
            name = [o for o in self.base_outcomes if o.result == "name"]
            rest = [o for o in self.base_outcomes if o.result in ("passed", "skipped")]
            out += ["### Changed tests against the merge base", ""]
            out.append(
                f"{len(behaviour)} fail on behaviour, {len(name)} fail only on a missing "
                f"name or file, {len(rest)} pass or skip."
            )
            out.append(
                "A test can also fail here because of a signature or a table the change"
                " adds without naming it, so this is the weaker evidence. The mutants"
                " below are the stronger."
            )
            out.append("")
            groups = (("Fail on behaviour", behaviour), ("Fail on a missing name or file", name))
            for title, group in groups:
                if group:
                    out += [f"{title}:", ""] + [f"- `{o.test}`: {o.detail}" for o in group] + [""]
        if self.mutants or self.skipped_mutants:
            survived = [m for m in self.mutants if m.status == "survived"]
            killed = sum(m.status == "killed" for m in self.mutants)
            timeout = sum(m.status == "timeout" for m in self.mutants)
            out += ["### Mutants on the lines this pull request adds", ""]
            skipped = self.skipped_mutants
            over = f", {skipped} not run (over the limit)" if skipped else ""
            out.append(
                f"{len(self.mutants)} run: {killed} caught by the changed tests, "
                f"{len(survived)} not caught, {timeout} timed out{over}."
            )
            out.append("")
            if survived:
                out += ["Not caught, so the tests cannot tell these apart from the change:", ""]
                out += [f"- `{m.path}:{m.line}`: {m.edit}" for m in survived] + [""]
        return "\n".join(out).rstrip() + "\n"


def review(repo: Path, base: str, head: str, max_mutants: int = 40, timeout: int = 300) -> Report:
    merge_base = git(repo, "merge-base", base, head).strip()
    tests, src = changed(repo, merge_base, head)
    report = Report(merge_base, head, tests, src)
    if not tests:
        report.notes.append("No test file under tests/ is added or changed, so nothing was run.")
        return report
    with tempfile.TemporaryDirectory(prefix="review-bar-") as tmp:
        before = Path(tmp) / "base"
        export(repo, merge_base, before)
        for path in tests:
            target = before / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(git(repo, "show", f"{head}:{path}"))
        names = frozenset(added_names(repo, merge_base, head, src))
        report.base_exit, report.base_outcomes = run_tests(before, tests, timeout, names)
        if report.base_exit == -1:
            report.notes.append(f"The base run timed out after {timeout} s.")
        if not src:
            report.notes.append("No Python file under src/ is added or changed, so no mutants.")
            return report
        after = Path(tmp) / "head"
        export(repo, head, after)
        candidates = mutants(repo, merge_base, head, src)
        report.skipped_mutants = max(0, len(candidates) - max_mutants)
        for mutant, mutated in candidates[:max_mutants]:
            original = (after / mutant.path).read_text()
            (after / mutant.path).write_text(mutated)
            try:
                code, _ = run_tests(after, tests, timeout)
            finally:
                (after / mutant.path).write_text(original)
            mutant.status = "timeout" if code == -1 else ("survived" if code == 0 else "killed")
            report.mutants.append(mutant)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--max-mutants", type=int, default=40)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--summary", type=Path, help="append the report here as well")
    args = parser.parse_args(argv)
    text = review(args.repo, args.base, args.head, args.max_mutants, args.timeout).markdown()
    print(text)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
