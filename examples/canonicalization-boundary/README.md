# Canonicalization boundary vectors

Spec section 3.2.2 requires an RFC 8785-conformant canonicalizer and names
`json.dumps(sort_keys=True)` as insufficient. Before this set existed, nothing
published exercised that sentence: every record in the repository was ASCII-only with
schema-fixed keys, and on such records every ad-hoc serializer agrees with RFC 8785
byte-for-byte. An implementation built on ad-hoc sorting passed everything.

These three records are where the agreement ends. Each is schema-valid and correctly
signed over its RFC 8785 bytes, so a conformant verifier accepts it — and a verifier
whose canonicalizer is any of the ad-hoc forms computes different signing bytes and
rejects a valid record. The failure is loud, which is the point: the alternative was
silent, because nothing else made the difference observable.

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

## What there is deliberately no vector for

RFC 8785's IEEE 754 number serialization (the other divergence the spec warns about)
is **unreachable in a schema-valid v0.2 record**: no field in `schema/trace-claim.json`
is typed `number`, and integers up to 2^53 serialize identically everywhere. The test
suite pins this with `test_number_divergence_is_still_unreachable`, which fails the day
a numeric field enters the schema — at which point the correct response is a
number-formatting vector here, not an edit to the test.

These vectors exercise accepted normative text (the section 3.2.2 MUST), not a
proposal; they carry no proposal marker.
