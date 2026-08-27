"""A deliberately naive RFC 8785 (JCS) serializer, written to share nothing with `rfc8785`.

This exists to close the hole reported in the paper's section 6.4(a): the "independent"
signature path in the audited suite verifies through `rfc8785.dumps`, and the library it
claims independence from signs through `rfc8785.dumps`. Same third-party canonicalizer on
both sides, so a canonicalization defect in that package is applied identically to the
fixtures and to the check, both agree, and the independent path reports success. That is
precisely the failure mode the independence argument exists to detect.

The point of this module is that it is *worse* code than the one it cross-checks. It is
written from the RFC text alone, straight-line, with no attention to speed, no shared
helpers and no shared design decisions. Two implementations agreeing is evidence only when
they could plausibly have disagreed.

Deliberate refusals, rather than best-effort handling:

- **Floats raise.** RFC 8785 delegates number serialization to ECMAScript
  `Number::toString`, which is genuinely intricate (shortest round-tripping
  representation, exponent thresholds at 1e21 and 1e-7). A half-correct implementation
  here would produce bytes that differ from `rfc8785` on inputs neither party intended to
  test, and the differential check would report a canonicalizer disagreement that is
  really a bug in this file. No fixture in the audited corpus contains a float, so the
  honest move is to refuse rather than to guess.
- **Integers outside the IEEE-754 exactly-representable range raise**, for the same
  reason: past 2**53 the ECMAScript rules stop agreeing with Python's arbitrary
  precision, and silently serializing a value nobody can round-trip is worse than
  stopping.
- **Non-string object keys raise.** JCS is defined over JSON, where keys are strings.
  Python dicts permit more; accepting it would mean inventing a rule the RFC does not
  state.

Every one of those is a case where being loud beats being accommodating, which is the same
principle the paper argues for in the checker itself.
"""

from __future__ import annotations

from typing import Any

# JSON's named short escapes. Everything else below 0x20 goes to \u00xx.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}

_MAX_EXACT_INT = 2**53 - 1


class NotCanonicalizable(ValueError):
    """Raised for input this module refuses to serialize rather than guess at."""


def _escape_string(value: str) -> str:
    """Escape per RFC 8785 section 3.2.2.2: short forms where they exist, \\u00xx for the
    remaining control characters, and every other character emitted literally.

    Emitting non-ASCII literally is the part worth stating. JCS output is UTF-8, so an
    em dash is three raw bytes and *not* \\u2014. A serializer that escapes it produces
    valid JSON that is not canonical, and the resulting signature will not verify against
    an implementation that got it right.
    """
    out = []
    for char in value:
        code = ord(char)
        if code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def _sort_key(key: str) -> bytes:
    """Order object keys by UTF-16 code unit, per RFC 8785 section 3.2.3.

    Not by code point, which is what Python's default string comparison does. The two
    orders differ for characters above the BMP: U+FFFD sorts *after* U+10000 by code
    point and *before* it by UTF-16 code unit, because the latter compares the leading
    surrogate D800 first. Encoding big-endian and comparing bytes reproduces code-unit
    order exactly, since a big-endian byte comparison of 16-bit units agrees with a
    numeric comparison of those units.
    """
    return key.encode("utf-16-be")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"

    # bool before int: bool is a subclass of int in Python, and `True` must serialize as
    # `true`, not as `1`. Checking int first would silently corrupt every boolean.
    if value is True:
        return "true"
    if value is False:
        return "false"

    if isinstance(value, int):
        if abs(value) > _MAX_EXACT_INT:
            raise NotCanonicalizable(
                f"integer {value} is outside the exactly-representable range; "
                "ECMAScript number rules stop agreeing with Python here"
            )
        return str(value)

    if isinstance(value, float):
        raise NotCanonicalizable(
            f"float {value!r}: ECMAScript Number::toString is not implemented here on "
            "purpose: see this module's docstring"
        )

    if isinstance(value, str):
        return _escape_string(value)

    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"

    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise NotCanonicalizable(f"object key {key!r} is not a string")
        pairs = sorted(value.items(), key=lambda kv: _sort_key(kv[0]))
        return "{" + ",".join(f"{_escape_string(k)}:{_serialize(v)}" for k, v in pairs) + "}"

    raise NotCanonicalizable(f"unsupported type {type(value).__name__}")


def dumps(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes for *value*."""
    return _serialize(value).encode("utf-8")
