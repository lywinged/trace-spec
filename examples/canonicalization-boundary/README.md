# Canonicalization boundary vectors

Spec section 3.2.2 requires an RFC 8785-conformant canonicalizer and names
`json.dumps(sort_keys=True)` as insufficient.

**What already existed.** `tests/test_sign.py` carries four literal-byte known-answer
tests over `_canonical_bytes` — non-ASCII escaping, number formatting, whitespace and
key sorting, and a comparison against the reference library. They are good tests and
they do catch a regression in this library.

**What these vectors add.** Two things those tests cannot do:

1. **They are portable.** A known-answer test over a private function is runnable only
   from Python, by this package. The roadmap targets Go, Rust and TypeScript verifiers
   for v1.0, and none of them can run `test_sign.py`. These are signed records: any
   implementation runs them against its own verifier. Every *other* record in the
   repository is ASCII-only with schema-fixed keys, where all serializers agree
   byte-for-byte — so no existing record's acceptance depends on canonicalizing
   correctly.
2. **One of them separates key ordering, which nothing else does.**
   `test_jcs_distinguishes_unicode_key_order_from_json_dumps` compares `{"z": 1,
   "\U0001f600": 2}`. Under RFC 8785's UTF-16 code-unit sort and under Python's
   code-point sort that object serializes in the *same* order — its own docstring says
   so — and the test detects divergence through `ensure_ascii` escaping instead. A
   canonicalizer that sorts by code point but emits raw UTF-8 passes it. Vector `03`
   is the first object in the repository whose two orderings actually disagree.

Each record is schema-valid and correctly signed over its RFC 8785 bytes, so a
conformant verifier accepts it, and a verifier built on any ad-hoc form computes
different signing bytes and rejects a valid record.

## The ladder

Each form fixes the previous one's divergence and still fails somewhere:

| Form | Diverges because | Caught by |
|---|---|---|
| `json.dumps(o, sort_keys=True)` | Default separators insert spaces | every vector (and any signed record) |
| `… separators=(",", ":")` | `ensure_ascii` escapes non-ASCII as `\uXXXX`; RFC 8785 emits literal UTF-8 | `01`, `02`, `03` |
| `… separators=(",", ":"), ensure_ascii=False` | Python sorts keys by code point; RFC 8785 sorts by UTF-16 code units. The orders differ exactly when a key contains a supplementary-plane character | `03` only |

`03-utf16-key-order.json` is the load-bearing vector: it is the only record in this
repository that distinguishes a true RFC 8785 serializer from `json.dumps` with every
option chosen carefully. Its two extra `cnf.jwk` members (RFC 7517 permits additional
JWK members, and `cnf.jwk` is the one schema object open to them) are `zk` followed by
U+1F600 and `zk` followed by U+FFFD — U+1F600 is `D83D DE00` in UTF-16, so it sorts
*before* U+FFFD by code units and *after* it by code points.

## What each fixture carries

- `record` — a complete, schema-valid, signed v0.2 Trust Record.
- `trusted_key` — the Ed25519 JWK to verify against.
- `expected.outcome` — `verified`, always. These are positive vectors; the negative
  behaviour (rejection) is what a non-conformant verifier does to them.
- `diverges_under` — which ad-hoc forms compute different bytes for this record.
  `tests/test_canonicalization_boundary.py` recomputes this list on every run rather
  than trusting it, and separately asserts that the set as a whole still catches every
  form on the ladder.

`iat` is fixed so the set regenerates byte-for-byte; run with freshness disabled or
with `iat`'s instant supplied as "now". `gen_boundary_vectors.py` regenerates the set.

## The number domain, which this set does not yet cover

An earlier version of this section claimed RFC 8785's IEEE 754 number serialization was
unreachable in a schema-valid v0.2 record, on the grounds that no field in
`schema/trace-claim.json` is typed `number` and that integers up to 2^53 serialize
identically everywhere. The first half holds. The second half does not carry the claim,
because nothing bounds those integers at 2^53.

`schema/trace-claim.json` declares five integer fields, and only
`build_provenance.slsa_level` has a `maximum`. `iat`, `tool_use.call_count`,
`source.ingested_at` and `appraisal.timestamp` are unbounded above, so
`"call_count": 9007199254740993` is a schema-valid record — and RFC 8785 section 3.2.2.3
admits only numbers representable as IEEE 754 doubles, which that value is not.

Measured against three implementations:

| Value | `rfc8785.dumps` | `json.dumps` (CPython) | `JSON.stringify` (Node) |
|---|---|---|---|
| 9007199254740991 (2^53 − 1) | `9007199254740991` | `9007199254740991` | `9007199254740991` |
| 9007199254740992 (2^53) | raises `IntegerDomainError` | `9007199254740992` | `9007199254740992` |
| 9007199254740993 (2^53 + 1) | raises `IntegerDomainError` | `9007199254740993` | `9007199254740992` |
| 12345678901234567890 | raises `IntegerDomainError` | `12345678901234567890` | `12345678901234567000` |

2^53 + 1 is the sharp value: the three disagree three ways — refuse, serialize exactly,
serialize a different number. The third is silent, and it is the one that matters across
implementations, because a JavaScript verifier has lost the value at parse time and has
nothing left to detect it with.

The fixture owed here does not fit the shape of `01`–`04`. Those carry
`expected.outcome: verified` and a signature over their RFC 8785 bytes; for this case
there are no RFC 8785 bytes to sign. It is a negative vector: a schema-valid record that
a conformant implementation must refuse to canonicalize, and that an ad-hoc implementation
serializes without complaint.

`test_number_divergence_is_still_unreachable` in `tests/test_canonicalization_boundary.py`
asserts only that no field is typed `number`. It does not look at integer bounds, so it
passes today and would have passed on the day the claim above stopped holding. It is left
as it stands pending a decision between bounding these fields in the schema and adding the
vector.

These vectors exercise accepted normative text (the section 3.2.2 MUST), not a
proposal; they carry no proposal marker.
