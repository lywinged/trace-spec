# Draft normative text: format versioning and verifier compatibility (#116)

**Status:** draft, not submitted. Written so the text exists before it is needed, not
because it is scheduled to go anywhere.

**Target:** a new section in `docs/verification.md`.

**Governance:** this is normative text — every requirement below uses an RFC 2119 keyword
and would bind every implementation. Under `GOVERNANCE.md` it needs an organizational
sponsor, or a Maintainer willing to carry it with the proposer credited. Neither has been
sought. Nothing here is proposed for merge in its current state.

**Conformance vectors** for these requirements already exist and need no sponsor:
`examples/verifier-compatibility/`, seven fixtures, run by
`tests/test_verifier_compatibility_fixtures.py`.

---

## Draft text

<!-- CHANGED: #116 - verifier obligations on format versioning -->

### Format versioning and verifier compatibility

Compliance evidence is verified long after it is issued. A Trust Record routinely
outlives the verifier build that reads it, and the profile surface continues to change:
the v0.2 cutover replaced the profile URI outright, and further profile versions are
anticipated. A verifier that meets a record written under semantics it does not implement
has two ways to be wrong, and only one of them is visible. It can refuse a record it could
have read, orphaning valid evidence. Or it can accept a record under semantics it does not
implement, which produces a verification result that means nothing and says nothing about
meaning nothing.

The requirements below make the second failure non-conformant.

**Profile presence.** Every Trust Record MUST carry an `eat_profile` claim identifying the
profile it was written under. A verifier MUST NOT infer a profile for a record that does
not state one, and MUST NOT default to the profile it implements.

**Declared support.** A conformant verifier MUST declare the set of profile URIs it
implements. On receiving a record whose `eat_profile` is not in that set, a verifier MUST
refuse verification. It MUST NOT verify on a best-effort basis, and MUST NOT downgrade the
result to a warning. A valid signature over semantics the verifier does not implement is
not evidence, and reporting it as a qualified success misrepresents what was established.

Refusal under this rule is distinct from a verification failure. A record refused for an
unimplemented profile has not been shown to be invalid; it has not been examined. A
verifier SHOULD report the two distinguishably, so that a relying party can tell "this
record is bad" from "this reader cannot read it".

**Statement content.** A verification result MUST identify the profile the record was
verified under. Where the result is machine-readable, the profile URI MUST appear as a
distinct field rather than being implied by the verifier's identity or version. A result
that does not name its profile cannot be re-interpreted later, which is the situation this
section exists to prevent.

A verification result SHOULD additionally state which checks were performed, so that a
check that did not run is distinguishable from a check that passed. In particular, a
result produced without consulting revocation status MUST NOT be reported in a form that
implies the signing key is still trusted (see the revocation requirements in §3.2.1 and
the boundary stated in `LIMITATIONS.md`).

**Disclosed fallback.** A verifier MAY implement more than one profile. Where it verifies
a record under a profile that is not the most recent it implements, the verification
result MUST disclose that, either by stating the full set of profiles the verifier
declared or by an equivalent explicit marker. Silent fallback to older semantics is
non-conformant.

This permits an implementation to support an older profile deliberately, while making the
support visible in the artifact rather than resident in the verifier's configuration where
a later reader cannot see it.

---

## Notes on the draft

**Why "refuse", not "warn".** The issue asks for refusal, and the reason is worth keeping
in the text: a warning is a result, and results get stored, aggregated, and eventually
read by someone who was not there. A refusal is not a result. The distinction survives
serialisation; a severity level does not.

**Why the statement obligation is separate from the refusal obligation.** A verifier could
satisfy the refusal rule perfectly and still emit a result that no future reader can
interpret, because it never says which semantics it applied. The two failures are
independent and both are live.

**What is deliberately not required.** No field name is mandated for the machine-readable
statement. TRACE does not define a verification-result format, and inventing one inside
this section would be a larger change than the one being argued for. The requirement is on
the information, not the encoding.

**Relationship to #114.** That issue proposes widening a decision enum behind a new profile
version. If it lands, these requirements are what make the widening safe: a verifier that
does not implement the widened profile refuses records under it rather than reading the new
values as if they were old ones.

**Known cost.** A deployment running a pinned old verifier against newly issued records
will start seeing refusals where it previously saw successes. That is the intended
behaviour and it is a real operational change; it should be called out in release notes
rather than discovered.
