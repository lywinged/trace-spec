"""Every API call the README names has to exist in the package.

`pyproject.toml` sets `readme = "README.md"`, so this file is the PyPI long
description: a call written here is the first instruction a new user reads, and
it is the text an answer engine quotes back when asked how to use TRACE. Through
0.10.0 the README told them to call `TrustRecord.sign(claims, signing_key)`,
`record.anchor()` and `record.verify(verifying_key)`. None of the three has ever
existed. The package signs with `sign_record`, checks with `verify_record`, and
does not anchor anything.

Nothing caught it. `tests/test_docs_quickstart.py` executes the fenced blocks in
`docs/`, and the README states its API in inline spans inside prose, which no
instrument read. That is the gap this file closes, and it closes it for the file
that travels furthest.

The rule is deliberately narrow, so it stays a fact check rather than a style
check. A call-shaped inline span is resolved one of two ways:

* a qualified name (`agentrust_trace.sign_record(...)`, `TrustRecord.sign(...)`)
  is walked attribute by attribute from the exported symbol it starts at;
* an unqualified receiver (`record.anchor()`) cannot be resolved, so the method
  name has to exist on some exported class instead.

A call that is deliberately not package API (`json.dumps(...)`, say) fails here
by design. Qualify it, or move it into a fenced block, rather than loosening the
rule: the point is that a reader cannot tell prose from instructions, so neither
does this test.
"""
from __future__ import annotations

import inspect
import pathlib
import re

import agentrust_trace

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"

#: A call inside an inline code span: the dotted name in front of the paren.
CALL = re.compile(r"`([A-Za-z_][A-Za-z0-9_.]*)\s*\(")


def _exported_classes() -> list[type]:
    return [
        value
        for name in agentrust_trace.__all__
        if inspect.isclass(value := getattr(agentrust_trace, name, None))
    ]


def unresolvable(text: str) -> list[str]:
    """Return the call-shaped names in `text` that do not exist in the package."""
    missing = []
    for name in dict.fromkeys(CALL.findall(text)):
        head, *rest = name.split(".")
        if head == agentrust_trace.__name__:
            # Fully qualified, which is the clearest form to write and would
            # otherwise look like an unresolvable receiver.
            head, *rest = rest or [head]
        target = getattr(agentrust_trace, head, None)
        if target is None:
            # An unqualified receiver. The method has to exist on some exported
            # class, or the sentence is telling a reader to call nothing.
            method = rest[-1] if rest else head
            if not any(hasattr(cls, method) for cls in _exported_classes()):
                missing.append(name)
            continue
        for attribute in rest:
            target = getattr(target, attribute, None)
            if target is None:
                missing.append(name)
                break
    return missing


def test_every_api_call_in_the_readme_exists() -> None:
    assert unresolvable(README.read_text(encoding="utf-8")) == []


def test_a_qualified_call_resolves() -> None:
    """The other direction: the clearest way to write a call must not be refused."""
    assert unresolvable("`agentrust_trace.verify_record(record)` and `sign_record(r, k)`") == []


def test_the_check_catches_the_calls_that_shipped_through_0_10_0() -> None:
    """The negative control is the defect itself, kept so the check cannot rot.

    If this ever passes, `unresolvable` has stopped resolving anything and the
    test above is measuring nothing.
    """
    shipped = (
        "sign a record with `TrustRecord.sign(claims, signing_key)`, anchor it to a "
        "SCITT ledger with `record.anchor()`, and check it with "
        "`record.verify(verifying_key)`."
    )
    assert unresolvable(shipped) == [
        "TrustRecord.sign",
        "record.anchor",
        "record.verify",
    ]
