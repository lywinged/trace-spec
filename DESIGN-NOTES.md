# Design notes

**Local to this fork. Nothing here is proposed to upstream.**

`DECISIONS.md` records decisions that were made. This file records the layer before
that: **structural observations with evidence, a shape the fix might take, and the cost
somebody would have to accept to take it.** An observation stays here until it is either
offered upstream, decided against, or refuted — and a refuted one stays too, with the
refutation, so the next reader does not investigate it again.

Every entry states what was measured, against which commit. A claim without a command
behind it does not belong on this page.

---

## 1. There is no shared signature-envelope layer

**Measured against `agentrust-io/trace-spec` @ `576507b` (0.9.0), 2026-08-11.**

Three code paths verify something signed. They share exactly two helpers,
`_canonical_bytes` and `_pubkey_from_jwk`. Everything above those is written separately
in each, and they have diverged:

| | signature | profile / format pinned | key identified by thumbprint | revocation consulted | freshness | returns |
|---|---|---|---|---|---|---|
| `sign.verify_record` (Trust Record) | yes | yes | yes | yes | yes | `None` |
| `provenance.verify_record` (server record) | yes | yes | **no** | **no** | yes | `None` |
| `content_marking.verify_assertion` (C2PA) | **no, by design** | yes | no | no | no | `dict` |

`content_marking` not verifying a signature is deliberate and documented; it checks a
hash binding and says so. The gap is the middle row.

**This has already produced two defects, and they are the evidence rather than the
argument.**

- **Revocation exists in one path only.** `spec/trace-v0.2.md` §3.2.1 requires a verifier
  to consult revocation status at verification time. `sign.py` implements it (`revocation`
  parameter, listed key rejected, unavailable store also rejected). `provenance.py`
  contains the string `revocation` zero times. A revoked publisher key still verifies a
  server provenance record.
- **`jwk_thumbprint` existed and was not reachable.** `provenance.verify_record` compared
  the embedded key to the trusted key with `embedded != trusted_jwk`, a dict comparison,
  so a legitimately signed record whose `cnf.jwk` carried a `kid` was refused although the
  key material was identical. RFC 7638 thumbprinting was already in the package —
  `jwk_thumbprint` is defined in `sign.py` and exported from `__init__` — and the second
  implementation reinvented key identity worse. Fixed in upstream #149; **the fix is the
  symptom.**

**Two corrections to earlier statements of this observation, both mine, both the same
mistake.** It was first written as "four signature formats each implement verification".
Two implementations verify signatures; the third deliberately does not. And a first draft
of this page said `jwk_thumbprint` appeared 21 times in `sign.py`; it appears 4 times.
The 21 was a combined count of two patterns, `jwk_thumbprint` **or** `revocation`, read off
one command and then attributed to one of them.

Both are the same failure: a number or a claim covering several objects, restated as though
it were about one. It happened three times on 2026-08-11 alone, twice in text that reached
a maintainer. **The corrected version of this observation is sharper, not weaker** — the
divergence is between two siblings rather than scattered across four — which is the usual
outcome when a number is checked, and the reason to check it.

**Shape of a fix.** An envelope layer that owns the parts that are the same everywhere:
canonical bytes, key resolution by thumbprint, revocation consultation, freshness bound,
and a single description of what was checked. Each format keeps its own structural rules
and calls the envelope for the rest.

**The cost, which is the maintainer's to accept and not ours to assume.** It couples the
release cadence of three modules that currently ship independently, and
`content_marking` would use only a fraction of it — a shared layer that one of its three
consumers barely touches is a shared layer under pressure to grow options. Upstream shipped
0.7.0, 0.8.0 and 0.9.0 in forty-eight hours across these files. **Nothing here should be
built in this fork:** an envelope abstracted against a subject moving that fast is stale
before it is reviewed, and the decision it forces is a scheduling decision that belongs to
whoever owns the schedule.

**What travels is the evidence.** Two defects, both already in their tracker, both caused
by the same missing layer. That is an issue, not a pull request.

---

## 2. The three-step C2PA verification cannot be enforced, because step two returns nothing

**Measured against the same commit.**

`docs`/`spec/content-marking-v1.md` describe verification as three steps: check the C2PA
manifest signature, check the Trust Record signature, check that the assertion's hash
matches the record actually retrieved. `verify_assertion` performs the third and says so
plainly in its own docstring:

> **This checks the binding, not the whole chain.** The C2PA manifest signature and the
> Trust Record signature are separate checks by separate keys, and this function performs
> neither.

Upstream #144 made `record_bytes` required with no default, which is right and closes the
weaker hole — an assertion whose hash was never checked is a URL in a file.

**But the remaining step is held by prose, and this project has explicitly rejected that
shape.** From the maintainer on `trace-tests#53`: *"Naming is a convention; changing
outcome is the property."*

The reason it cannot currently be otherwise is structural, and sharper than "nobody wrote
the check":

```python
sign.verify_record(record, key, ...)        -> None
provenance.verify_record(record, jwk)       -> None
content_marking.verify_assertion(a, bytes)  -> dict
```

**Both verifiers return `None`.** There is no artifact a caller could be required to
present, so `verify_assertion` accepts raw bytes because raw bytes are the only thing that
exists. `grep` confirms the corollary: **no module in the package calls another module's
`verify_record`.** The three paths do not compose because there is nothing to compose.

**Shape of a fix.** `verify_record` returns a statement of what it checked rather than
`None`, and `verify_assertion` takes that statement instead of loose bytes. The statement
carries the record's canonical bytes (or their digest) so the hash binding still works, plus
which checks ran — profile pinned, revocation consulted or not, freshness bound.

**This is #116's `VerificationStatement`, reached from a second direction.** That draft
argues for it as *a record of what a verifier checked*, so a relying party is not left
inferring it from the absence of an exception. This observation adds a different argument:
it is also **the token that binds two verified artifacts together**. A function that must be
handed one cannot be called on an unverified thing by accident. Two unrelated lines of work
now point at the same object, which is worth saying on #116 rather than proposing again.

**The honest limit, which must be stated wherever this is proposed.** Python cannot make
such a statement unforgeable. Anyone can construct one by hand and pass it. What changes is
that skipping verification stops being the default path and becomes a deliberate act that
reads as one in review. That is the same class of improvement as the rule registry in #148 —
an unregistered check cannot run — and it is weaker than that one, because a registry is
enforced by the interpreter and a convention about who builds an object is not.

---

## 3. Refuted: the C2PA assertion is not missing a version field

**Measured against the same commit. Recorded so nobody investigates it twice.**

The assertion looked like it carried no version, which would have meant a consumer parsing
a future assertion shape best-effort. It does carry one, in `data.version`, and unknown
versions are refused rather than parsed:

```python
"version": ASSERTION_VERSION,                    # content_marking.py:98, emitted
if data.get("version") != ASSERTION_VERSION:     # content_marking.py:134, checked
    raise ContentMarkingError(
        f"unknown assertion version {data.get('version')!r}; expected {ASSERTION_VERSION}. "
        "An unknown version is rejected rather than parsed best-effort."
    )
```

**Not a gap.** The field is nested one level deeper than the eye expects, which is the whole
of why it looked like one.
