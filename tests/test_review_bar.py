"""tools/review_bar.py on a two-commit repository built here.

The head commit adds a refusal (``x > 100``), a new function, and three kinds of
test: one that fails on the base for behaviour, one that fails there only
because the new function is missing, and one in a new file whose import of a
new module fails at collection. Its tests check 1000 but not 100, so weakening
``>`` to ``>=`` is a fix they cannot tell apart, and the report has to say so.
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_bar", ROOT / "tools" / "review_bar.py")
assert spec is not None and spec.loader is not None
review_bar = importlib.util.module_from_spec(spec)
sys.modules["review_bar"] = review_bar
spec.loader.exec_module(review_bar)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

BASE_CORE = '''def check(x):
    if x < 0:
        raise ValueError("negative")
    return x
'''
HEAD_CORE = '''def check(x):
    if x < 0:
        raise ValueError("negative")
    if x > 100:
        raise ValueError("too big")
    return x


def limit(cap=100):
    return cap
'''
BASE_TESTS = '''from pkg.core import check


def test_zero():
    assert check(0) == 0
'''
HEAD_TESTS = '''import pytest

from pkg.core import check


def test_zero():
    assert check(0) == 0


def test_too_big_is_refused():
    with pytest.raises(ValueError):
        check(1000)


def test_limit_is_one_hundred():
    from pkg.core import limit

    assert limit() == 100
'''
NEW_FILE_TEST = '''from pathlib import Path

DATA = (Path(__file__).parent.parent / "data.txt").read_text()


def test_data():
    assert DATA == "x\\n"
'''
NEW_MODULE_TEST = '''from pkg.extra import VALUE


def test_value():
    assert VALUE == 1
'''


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for path, text in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com",
         "commit", "-q", "-m", message],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str, str]:
    root = tmp_path_factory.mktemp("review-bar-repo")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    base = _commit(root, {
        "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
        "src/pkg/__init__.py": "",
        "src/pkg/core.py": BASE_CORE,
        "tests/test_core.py": BASE_TESTS,
    }, "base")
    head = _commit(root, {
        "src/pkg/core.py": HEAD_CORE,
        "src/pkg/extra.py": "VALUE = 1\n",
        "tests/test_core.py": HEAD_TESTS,
        "tests/test_extra.py": NEW_MODULE_TEST,
        "data.txt": "x\n",
        "tests/test_data.py": NEW_FILE_TEST,
    }, "head")
    return root, base, head


@pytest.fixture(scope="module")
def report(repo: tuple[Path, str, str]) -> object:
    root, base, head = repo
    return review_bar.review(root, base, head, timeout=120)


def _by_name(report: object) -> dict[str, str]:
    return {o.test.rsplit("::", 1)[-1]: o.result for o in report.base_outcomes}


def test_changed_files_are_the_added_and_modified_tests_and_src(repo):
    root, base, head = repo
    assert review_bar.changed(root, base, head) == (
        ["tests/test_core.py", "tests/test_data.py", "tests/test_extra.py"],
        ["src/pkg/core.py", "src/pkg/extra.py"],
    )


def test_added_lines_are_the_new_refusal_and_function(repo):
    # Line 6, `return x`, is the base's line 4 moved down, so git does not count it.
    root, base, head = repo
    assert review_bar.added_lines(root, base, head, "src/pkg/core.py") == {4, 5, 7, 8, 9, 10}


def test_a_test_that_fails_on_the_base_for_behaviour_is_reported_as_behaviour(report):
    outcomes = _by_name(report)
    assert outcomes["test_too_big_is_refused"] == "behaviour"
    assert outcomes["test_zero"] == "passed"


def test_a_test_that_fails_only_on_a_new_name_is_not_reported_as_behaviour(report):
    outcomes = _by_name(report)
    assert outcomes["test_limit_is_one_hundred"] == "name"
    extra = [o for o in report.base_outcomes if "test_extra" in o.test]
    assert extra and all(o.result == "name" for o in extra)


def test_a_test_file_that_cannot_be_collected_on_the_base_is_not_behaviour(report):
    # It reads a file the change adds, so on the base it fails at collection.
    data = [o for o in report.base_outcomes if "test_data" in o.test]
    assert data and all(o.result == "name" for o in data)


def test_mutants_are_only_on_added_lines_and_the_untested_boundary_survives(report):
    found = {(m.line, m.edit): m.status for m in report.mutants}
    assert found == {
        (4, "> becomes >="): "survived",
        (5, "delete the raise"): "killed",
    }


def test_the_report_names_the_surviving_mutant(report):
    text = report.markdown()
    assert "1 fail on behaviour, 3 fail only on a missing name or file" in text
    assert "so this is the weaker evidence" in text
    assert "`src/pkg/core.py:4`: > becomes >=" in text
    assert "1 caught by the changed tests, 1 not caught" in text


@pytest.mark.parametrize(
    ("message", "kind"),
    [
        ("ImportError: cannot import name 'limit' from 'pkg.core'", "name"),
        ("ModuleNotFoundError: No module named 'pkg.extra'", "name"),
        ("AttributeError: module 'pkg.core' has no attribute 'limit'", "name"),
        ("TypeError: check() got an unexpected keyword argument 'strict'", "name"),
        ("AttributeError: 'NoneType' object has no attribute 'get'", "behaviour"),
        ("Failed: DID NOT RAISE <class 'ValueError'>", "behaviour"),
        ("AssertionError: assert 1000 == 100", "behaviour"),
    ],
)
def test_failures_are_sorted_by_what_their_text_says(message, kind):
    assert ("name" if review_bar.missing_name(message) else "behaviour") == kind


@pytest.mark.parametrize(
    ("message", "kind"),
    [
        ("KeyError: 'trusted_observer'", "name"),
        ("AssertionError: KEYWORD_CALLS names ['m.f.trusted_observer']", "name"),
        ("AssertionError: assert 'trusted_observers' == 'x'", "behaviour"),
        ("AssertionError: assert check.trusted_observer_x == 1", "behaviour"),
    ],
)
def test_a_failure_that_names_a_name_the_change_adds_is_a_missing_name(message, kind):
    names = frozenset({"trusted_observer"})
    assert ("name" if review_bar.missing_name(message, names) else "behaviour") == kind


def test_added_names_are_new_functions_parameters_and_module_names(repo):
    # `cap` is added too, and left out: a three-letter name is too common to match on.
    root, base, head = repo
    added = review_bar.added_names(root, base, head, ["src/pkg/core.py", "src/pkg/extra.py"])
    assert added == {"limit", "VALUE"}


def test_with_no_changed_test_file_nothing_runs_and_the_report_says_so(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    base = _commit(tmp_path, {"src/pkg/core.py": BASE_CORE}, "base")
    head = _commit(tmp_path, {"src/pkg/core.py": HEAD_CORE}, "head")
    report = review_bar.review(tmp_path, base, head)
    assert report.base_exit is None and report.mutants == []
    assert "No test file under tests/ is added or changed" in report.markdown()


def test_the_command_line_writes_the_summary_and_never_fails_the_build(repo, tmp_path):
    root, base, head = repo
    summary = tmp_path / "summary.md"
    code = review_bar.main(
        ["--repo", str(root), "--base", base, "--head", head, "--summary", str(summary)]
    )
    assert code == 0
    assert "### Mutants on the lines this pull request adds" in summary.read_text()
