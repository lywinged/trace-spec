# RFC Proposal: passkey-signed approvals

**Status:** Draft proposal. Binds nothing.
**Scope:** A detached approval artifact whose signature is a WebAuthn authentication assertion,
the rules a verifier applies to one, and how it composes with `references[rel=approval-outcome]`
(§3.1.2). No schema change, no new `rel` value, no change to any record.
**Target:** Informative. If the rules are adopted, the artifact gets a versioned schema (where:
open question 2) and this file becomes a pointer to where the rules went. If they are not, the
set is removed as one unit: this file, `examples/webauthn-approval/`, the two test modules and the
margins file, and the entries naming them in `tests/test_adequacy_all_sets.py`,
`examples/README.md` and `mkdocs.yml`.
**Conformance material:** `examples/webauthn-approval/`: 72 vectors, generator, published seed,
and one artifact captured from a browser (§8). Conformance here means agreeing with the
reference verifier's results on the vectors, which is all an informative profile can mean by the
word.

Requirement keywords are lowercase throughout, on the line `CONTRIBUTING.md` draws: normative
text lives in the specifications, and informative text binds no implementation. Where this
document quotes a requirement from another specification, it cites the section on the same line
of the source, which `tests/test_requirement_keywords_are_attributable.py` checks.

---

## 1. What exists today

`approval-outcome` is a registered value of `references[].rel`, "an attributable human approval
attached to a step-up or defer decision" (§3.1.2). The references registry defines the referenced
object through the documents it cites, and the one committed mapping, to CHAP review decisions,
states the gap this proposal is about: its fixtures run without CHAP's signing profile, "so
envelopes carry no Ed25519 signatures, and the chain proves consistency with an exported head, not
authorship". No TRACE mapping binds an approver's signature to an approval today.

#191 proposes what attribution takes. Approval evidence is "signed by a key the record's subject
does not control", and separation of duties is machine-checkable: "the approval key must not be
the record's `cnf` confirmation key, and the approver principal must not resolve to the record's
`subject` under the verifier's identity policy". The Project Lead's comment there of 7 September
settled where such evidence goes: "The existing approval-outcome reference plus digest resolves the
container question." What the reference points at is still open. This is one candidate, for an
approver who holds a passkey or a security key.

What the relying party verifies is fixed by WebAuthn Level 3 §7.2: that the signature "is a valid
signature over the binary concatenation of authData and hash", where `hash` is the SHA-256 of
`clientDataJSON`. The authenticator never sees the relying party's object. The one member of
`clientDataJSON` the relying party chooses is the challenge, so an assertion can be tied to an
approval only through the challenge.

W3C Secure Payment Confirmation (SPC) names what that costs when nothing specifies it. Its §1.1.1
lists three issues with carrying payment details in a plain WebAuthn challenge: "It is a misuse of
the challenge field (which is intended to defeat replay attacks)"; "There is no specification for
this", so each relying party devises its own format; and "Plain [webauthn-3] does not provide for
this display". This profile answers the first two for approvals and leaves the third open. The
challenge still defeats replay of the ceremony, because the approval it commits to carries a fresh
random nonce (§3.1). The format is what this document specifies. Display it does not provide (§9):
SPC puts the payment details in the client data itself, under a `type` of `payment.get`, and has
the browser present them to the user. WebAuthn Level 1 defined two extensions that had the
authenticator itself display a prompt, `txAuthSimple` and `txAuthGeneric` (§10.2 and §10.3 of the
Level 1 Recommendation), and Levels 2 and 3 contain neither, so nothing equivalent exists for a
general approval today.

Without such a format, a deployment that approves with a passkey has two choices, and each loses
something. It can hold a software key that a passkey ceremony unlocks and sign with that, which
makes the artifact attributable to a key the software holds and leaves the ceremony out of it. Or
it can keep the assertion beside the approval with no binding rule, and then a verifier can check
that the passkey signed something and cannot check that it signed this.

## 2. The verification model

A verifier is given the artifact, the relying party's configuration and, when a record cites the
artifact, that record. The configuration is context the verifier supplies; nothing in it comes
from the artifact.

| Context | Why it is not in the artifact |
|---|---|
| `credentials` | The credential registry. For each credential id: the public key as a JWK and its COSE algorithm, the RP ID and origins it is registered for, the approver it belongs to, its attestation grade, and optionally its recorded backup eligibility and last stored signature counter. An artifact that could name its own key could name one that agrees with it. |
| `supported_algorithms` | What the verifier can compute, which is not what a registry may hold. The reference verifier refuses a configuration that declares an algorithm it has no implementation for, before it reads the artifact. |
| `policy.require_uv_for_deny` | Whether a deny needs user verification. An allow always does (§5.5). |
| `now`, `clock_skew_seconds` | The time the window is judged at, and how far the relying party's clock may differ from the one `now` was read from (§5.7). |
| `identity` | The directory that resolves an approver identifier to a principal, which W-23 and W-24 need. |

The registry holds each key as a JWK, converted from the COSE_Key the authenticator returned at
registration, because the citing record's `cnf` holds a JWK and W-22 compares the two. The
attestation grade is `attested` where the relying party verified an attestation at registration
and `self-asserted` where it did not. A verifier reports no grade (`null`) when it stops at the
gate (W-1 or W-2, §4), because it has read no credential, and when the registry does not hold the
credential.

The verifier returns one of four outcomes, a sorted list of codes, and the credential's
attestation grade. Each rule has a class: `invalid` when something the verifier checked was
contradicted, `unverifiable` when it could not check something, `decision` for the one rule whose
finding is the decision itself (W-11), and `advisory` for a finding that is reported and decides
nothing.

| Outcome | When |
|---|---|
| `approval-invalid` | A rule of class `invalid` fired. |
| `approval-unverifiable` | A rule of class `unverifiable` fired, and none of class `invalid`. |
| `not-an-approval` | The decision rule fired, and no rule of class `invalid` or `unverifiable`. |
| `approval-valid` | No rule of class `invalid`, `unverifiable` or `decision` fired. Advisory codes, `counter_not_checked` included, may be present. |

A contradiction outranks an inability to check, and both outrank a refusal: a deny whose
signature is broken is invalid, not a valid refusal. `approval-unverifiable` is kept apart from
`approval-invalid` on the reading §3.3.2 gives receipts, "A receipt whose issuer key is unknown
to the verifier is unverified, not invalid", and #279 tracks the same discipline for absence in
general. Collapsing the two turns a missing registry entry into an accusation.

## 3. The artifact

```json
{
  "profile": "tag:agentrust-io.com,2026:webauthn-approval-v1",
  "approval": {
    "approval_id": "approval/valid-es256",
    "decision": "allow",
    "approver": "approver-ops-lead",
    "credential_id": "uuJmzignzdZuvymZi-gx-g",
    "rp_id": "approvals.example.org",
    "origin": "https://approvals.example.org",
    "subject_kind": "pic-trace-bridge-authorization",
    "subject_digest": "sha256:…",
    "nonce": "…",
    "issued_at": 1790067480,
    "expires_at": 1790068080
  },
  "assertion": {
    "authenticator_data": "…",
    "client_data_json": "…",
    "signature": "…",
    "alg": -7
  }
}
```

| Member | What it is |
|---|---|
| `profile` | The profile identifier. The one above is a placeholder in the project's own `tag:agentrust-io.com,2026:` form; the identifier is the project's to assign. It is inside every challenge, so changing it regenerates every vector. |
| `approval.approval_id` | The relying party's identifier for this approval. A citing record names it as the reference's `id`. |
| `approval.decision` | `allow` or `deny`. |
| `approval.approver` | An opaque identifier for the person, which the relying party's directory resolves. #191's candidate direction has portable records carry "a scoped pseudonymous approver identifier". |
| `approval.credential_id` | The WebAuthn credential id, base64url without padding. |
| `approval.rp_id`, `approval.origin` | Where the ceremony was to happen. |
| `approval.subject_kind`, `approval.subject_digest` | What was approved: the kind of object, and the SHA-256 of its RFC 8785 form. `pic-trace-bridge-authorization` names the complete `authorization` object of a PIC/TRACE bridge artifact; an absolute URI names another profile's object. |
| `approval.nonce` | At least 16 random bytes, drawn by the relying party for each ceremony, base64url. The shape holds it to 16 bytes (W-2, vector 62). |
| `approval.issued_at`, `approval.expires_at` | The validity window, in seconds since the Unix epoch, as integers in the range §3.2.2 holds every canonicalized integer to. `issued_at` is when the relying party issued the challenge, which is before the approver acts, and `expires_at` is later than it. |
| `assertion` | The WebAuthn response: authenticator data, client data and signature, base64url without padding, and the COSE algorithm the artifact names for the signature, which W-16 compares with the registry's. An ECDSA signature is ASN.1 DER, as WebAuthn Level 3 §6.5.5 requires of assertion signatures, not the fixed-length form JOSE uses; an EdDSA signature is the raw 64 bytes. |

The artifact's three objects are closed, for the reason the PIC/TRACE bridge gives: "Unknown
fields are rejected so an implementation cannot silently ignore a new security meaning." The
artifact never carries a key, for the bridge's other reason: "A plugin, runtime, or gateway cannot
bootstrap its own authority by embedding a key in the signed object." The client data inside
`client_data_json` is WebAuthn's structure, not this profile's, and it stays open. WebAuthn Level 3
§5.8.1: "it's critical when parsing to be tolerant of unknown keys and of any reordering of the
keys". Vector 21 carries a client data member no rule reads, and it is valid.

### 3.1 The challenge

The relying party sets the WebAuthn challenge to

```
SHA-256( RFC 8785( {"profile": <profile>, "approval": <approval>} ) )
```

and a conforming client writes its base64url encoding, without padding, into
`clientDataJSON.challenge`. `assertion` is outside the pre-image, as a signature is outside its
own pre-image in §3.2.2. Nothing in `approval` is outside it, because a member a verifier reads
and the challenge does not cover is a member anyone can rewrite after the ceremony. Vector 17
moves `expires_at` a day later and the assertion still verifies; only the challenge sees it.

The pre-image fixes one thing about the ceremony itself. Because it covers `approver` and
`credential_id`, the relying party identifies the approver and chooses the credential before the
ceremony, and asks for an assertion from that credential alone, with `allowCredentials` naming it
and nothing else. An approver who reaches for a different registered authenticator, a backup
security key for instance, fails the ceremony. A discoverable-credential flow, in which the
relying party learns the credential from the response, needs an identifying ceremony first and
this one after it. Open question 7 asks whether `credential_id` should leave the pre-image.

WebAuthn Level 3 §13.4.3 requires that challenges "MUST be randomly generated by Relying Parties
in an environment they trust (e.g., on the server-side)", and recommends at least 16 bytes. A
derived challenge meets the purpose of that requirement rather than its letter: the relying party
draws the nonce at random, server-side, for each ceremony, so the challenge is exactly as
unpredictable as the nonce and is never reused, and the digest adds the binding. The same section
asks the relying party to hold the challenge until the ceremony completes and to check the
response against it, and nothing here changes that. The profile adds a second check, one that can
run later and offline from the artifact alone, because the challenge can be recomputed from what
the artifact carries.

### 3.2 What the artifact does not read

No rule reads the approved object. `subject_digest` commits the approval to it, and whether the
action that executed is that object is the comparison the component enforcing the approval makes.
The CHAP mapping draws the same line for its own decisions: binding the draft to what executed
"is the same gate's job". The committed vectors therefore carry a digest with no object behind it.

## 4. The rules

24 rules, each with a stable code and a class. The last column lists the vectors whose result,
the outcome or the codes, changes when the rule is deleted from the reference verifier. Deleting a
rule, or weakening its check, changes what that rule reports and nothing else: the verifier still
stops at the gate and still skips the stages whose inputs are missing, so a deletion changes what
is reported, never what is read. Every rule has at least two vectors. For each of the 22 rules
that can decide an outcome, at least two of its vectors change outcome and not only codes; the two
advisory rules change codes only.

| # | Code | Class | Rule | Vectors |
|---|---|---|---|---|
| W-1 | `profile_not_supported` | unverifiable | `profile` is the identifier this verifier implements, compared exactly. | 06, 07, 61 |
| W-2 | `artifact_malformed` | invalid | The artifact has the profile's shape: every required member, of its type, and no other, so every object is closed; `decision` is `allow` or `deny`; the base64url, digest and nonce patterns, the nonce at least 16 bytes; times and `alg` in the §3.2.2 range; `expires_at` later than `issued_at`; and assertion members that decode to authenticator data of at least 37 bytes, client data that is a JSON object, and a signature. | 12, 13, 14, 15, 62 |
| W-3 | `credential_unknown` | unverifiable | `credential_id` names a registry entry, compared exactly. | 08, 09 |
| W-4 | `challenge_mismatch` | invalid | `clientDataJSON.challenge` is the base64url encoding, without padding, of the §3.1 challenge, compared as a string. | 16, 17, 18, 49 |
| W-5 | `client_data_type` | invalid | `clientDataJSON.type` is `webauthn.get`. | 19, 20, 64 |
| W-6 | `cross_origin_not_expected` | invalid | `crossOrigin` is not true and `topOrigin` is absent. | 22, 23 |
| W-7 | `user_not_present` | invalid | The UP flag is set. | 30, 31 |
| W-8 | `user_not_verified` | invalid | The UV flag is set when the decision is `allow`, and when it is `deny` under a policy that requires it for denials. | 32, 33 |
| W-9 | `backup_state_inconsistent` | invalid | If the BE flag is clear, the BS flag is clear. | 34, 35, 66 |
| W-10 | `outside_validity_window` | invalid | `issued_at - skew <= now < expires_at + skew`. | 42, 43 |
| W-11 | `decision_not_allow` | decision | `decision` is `allow`. | 31, 33, 46, 47, 66 |
| W-12 | `origin_not_expected` | invalid | `clientDataJSON.origin` is one of the credential's registered origins and equals `approval.origin`. | 24, 25, 65 |
| W-13 | `rp_id_mismatch` | invalid | `approval.rp_id` is the credential's registered RP ID, and the first 32 bytes of the authenticator data are its SHA-256. | 26, 27 |
| W-14 | `approver_not_registered` | invalid | `approval.approver` is the approver the registry holds for the credential, compared exactly. | 28, 29 |
| W-15 | `backup_eligibility_changed` | invalid | Where the registry records the credential's backup eligibility, the BE flag agrees with it. | 36, 37 |
| W-16 | `algorithm_mismatch` | invalid | `assertion.alg` is the algorithm the registry holds for the credential. | 38, 39, 67 |
| W-17 | `algorithm_unsupported` | unverifiable | The registry's algorithm is one the verifier declares it can compute. | 10, 11, 67 |
| W-18 | `counter_not_checked` | advisory | Reported when the verifier holds no stored counter and the authenticator reports a nonzero one. | 57, 58 |
| W-19 | `counter_not_increasing` | advisory | Reported when a stored counter is held, either value is nonzero, and the reported value is not greater. | 59, 60, 72 |
| W-20 | `signature_invalid` | invalid | The signature verifies under the registry's key and algorithm, over the authenticator data followed by the SHA-256 of the client data. | 40, 41, 68 |
| W-21 | `reference_digest_mismatch` | invalid | A citing record's digest, when it carries one, is over the RFC 8785 form of the whole artifact. | 48, 49, 50 |
| W-22 | `approval_key_is_record_key` | invalid | The credential's public key is not the citing record's `cnf` key, compared on the members a JWK thumbprint is taken over for the key's type: `crv`, `kty`, `x` and `y` for EC and `e`, `kty` and `n` for RSA (RFC 7638 §3.2), `crv`, `kty` and `x` for OKP (RFC 8037 §2), and `alg`, `kty` and `pub` for AKP (RFC 9964 §6); for any other type, the whole JWK. | 51, 52 |
| W-23 | `approver_is_record_subject` | invalid | The approver, resolved through the directory, is not the citing record's `subject`. An approver identifier that is the subject verbatim needs no directory to compare. | 53, 54 |
| W-24 | `approver_unresolved` | unverifiable | The directory resolves the approver to a principal, so that W-23 can be judged. | 55, 56 |

On five vectors a deletion changes the codes and not the outcome, because another rule also fires
on them: deleting W-11 leaves 31, 33 and 66 invalid under W-7, W-8 and W-9, deleting W-17 leaves
67 invalid under W-16, and deleting W-4 or W-21 leaves 49 invalid under the other. The vectors
whose outcome W-11 alone decides are 46 and 47, W-4's are 16, 17 and 18, W-17's are 10 and 11,
and W-21's are 48 and 50.

Nine rules carry a step of WebAuthn Level 3 §7.2, with the expected values supplied by the
approval, the registry or the policy: W-4 (the challenge), W-5 (the type), W-7 and W-8 (the UP and
UV flags), W-9 (BS without BE), W-12 (the origin), W-13 (the RP ID hash), W-14 (the user account
that holds the credential, for a user identified before the ceremony) and W-20 (the signature).
Three carry a step whose outcome §7.2 leaves to the relying party: W-6 its cross-origin steps, for
a relying party that does not expect to be framed, W-15 its backup-state step, and W-19 its
counter step. The other 12 are this profile's: W-1, W-2, W-3, W-10, W-11, W-16, W-17, W-18 and
W-21 to W-24. W-18 is among them because §7.2's counter step assumes a stored count, and W-18
names its absence.

The rules run in stages. W-1 and W-2 are a gate: what they check, the profile and the shape,
decides whether anything further is read. After the gate, whether a stage runs depends on the
artifact and the configuration, never on which rules fired:

1. W-1, and then W-2. Either one ends the evaluation. A verifier reads nothing further in an
   artifact under a profile it does not implement, or in one that does not have the profile's
   shape, because every later rule decodes something. The profile is asked first, because
   another version's artifact is not malformed for having another version's shape.
2. W-3, and W-4 to W-11, which need the artifact and the configuration only.
3. W-12 to W-19, when the registry holds the credential.
4. W-20, when the registry holds the credential and its algorithm is one the configuration
   declares. A signature the verifier does not compute is not a signature that failed: vector 10
   is genuinely signed, and the verifier says it did not check it.
5. W-21 to W-24, when a record cites the artifact by its `approval_id`. W-22 also needs the
   registry's key, and reports nothing when the registry does not hold the credential, which W-3
   has already made unverifiable.

## 5. Decisions the rules depend on

### 5.1 The challenge is compared as a string

The comparison that looks equivalent is to decode both sides and compare bytes. §7.2 says "Verify
that the value of C.challenge equals the base64url encoding of pkOptions.challenge", which is a
comparison of strings, and a conforming client never pads, because WebAuthn's base64url encoding
has "all trailing '=' characters omitted" (§3). Vector 18 carries the right digest with
`=` padding: it decodes to the expected bytes and fails. This is a question of conformance, not of
security, since the padded string is inside the client data the approver's key signed. A verifier
that compares bytes accepts every spelling of one challenge, and a profile that means to be tested
by vectors needs one answer; §7.1 shows an independent library giving the other.

### 5.2 BS without BE fails, whatever the policy

§7.2: "If the BE bit of the flags in authData is not set, verify that the BS bit is not set." The
step is unconditional. The next step, comparing the flags with what the relying party recorded, is
the one conditional on the relying party using backup state, and it is W-15. WebAuthn Level 3
§6.1.3 lists BE clear with BS set as "not allowed", and says the value of the BE flag "MUST NOT
change", so W-15 fires in both directions: vector 36 is a credential losing eligibility and vector
37 a device-bound credential now reporting that it can be synced. Reading the whole paragraph as
policy makes W-9 optional; vector 35, a credential whose eligibility the registry never recorded,
is the case only the flag rule catches.

### 5.3 The counter is reported, not decided

§7.2 calls a counter that is not greater "a signal, but not proof, that the authenticator may be
cloned", and whether the relying party fails the ceremony on it "is Relying Party-specific". A
relying party may fail it, and §7.1 shows a library that does. This profile reports it instead,
and W-18 and W-19 travel with the outcome without changing it, for a reason particular to checking
an artifact after the fact: the stored counter moves with every later ceremony, so an approval
judged after its credential's next use reports a count that is not greater than the stored one,
whatever happened at its own ceremony. A decisive rule would invalidate every approval made before
the credential's last use, wherever the authenticator keeps a counter.

A verifier that holds no counter says so, because an absence nobody names reads as a check that
passed, and a null counter in the registry is an absence like a missing one (vector 58). Zero after
zero is exempt, because "Authenticators that do not implement a signature counter leave the
signCount in the authenticator data constant at zero" (WebAuthn Level 3 §6.1.1); vector 05 is that
case.

### 5.4 The registry holds the key, the algorithm, the RP ID and the origins

The artifact names a credential, and everything the verifier checks the assertion against comes
from the registry entry for it. Vector 12 carries the key that actually signed it and names a
credential registered to someone else; the shape check refuses it before any key is read. Vector
26 names an RP ID the credential is not registered for, and its authenticator data hashes the same
RP ID, so the artifact agrees with itself throughout and only the registry disagrees. The
artifact's `alg` is compared with the registry's rather than used: vector 39 names -257 (RS256),
which no credential in the set holds, over a signature the verifier can compute, and a verifier
that skips the comparison for algorithms it does not recognise accepts it.

The identifiers are WebAuthn's: -7 (ES256), -8 (EdDSA) and -35 (ES384). RFC 9864 (October 2025)
marks these "Deprecated" in the IANA COSE registry, in favour of fully specified identifiers that
include -9 (ESP256), -19 (Ed25519) and -51 (ESP384). WebAuthn Level 3 keeps the older ones for
`pubKeyCredParams` and marks the newer ones "NOT RECOMMENDED" there (§5.4). It says that within
WebAuthn each pair represents the same thing, and that the pairs are nonetheless "not
interchangeable in practice", because many implementations support -7, -8 and -35 and not the
fully specified ones; py_webauthn 3.0.0 is one (§7.1). This profile compares identifiers exactly,
so a registry holding -19 and an artifact naming -8 disagree under W-16 (vector 67); open question
8 asks whether the pairs should be treated as one.

### 5.5 Every allow needs user verification

§7.2 leaves user verification to the relying party's options. An approval is attributable to a
person only if the authenticator verified the person, so an allow requires UV. A deny requires it
when the policy says so, because a refusal is not an approval and a relying party may accept one
on presence alone. UP is required regardless, and UV does not imply it: vector 30 has UV set and
UP clear.

### 5.6 The window is half-open, and the tolerance widens both ends

With no tolerance, an approval is usable from the second of `issued_at` (vector 70) and stops
being usable at `expires_at`, not a second later (vector 42), which is where the PIC/TRACE bridge's
reference implementation puts its own expiry. The clock tolerance moves both ends:
vectors 44 and 45 are an approval issued thirty seconds ahead of the verifier's clock and one
expired thirty seconds ago, both inside a sixty-second tolerance and both valid. The tolerance is
also why the window's order is a shape check (W-2) and not left to W-10: vector 15's window closes
before it opens, both of its ends lie within the tolerance of `now`, and W-10 alone would pass it.

### 5.7 What `now` is

The window is judged at `now`, and which time that is depends on who is asking. A component
enforcing the approval reads its own clock at the moment it acts, and `clock_skew_seconds` is the
difference it tolerates between that clock and the relying party's. An auditor reading the
artifact years later cannot use its own clock, or every approval would be outside its window; it
needs the time the action was taken. The citing record's `iat` is the obvious source, and it is
only as trustworthy as that record's claim, or, for a Level 2 record, as the anchor's ordering:
§3.2.3 declines to trust a timestamp for revocation for the same reason. The reference verifier
takes `now` from the configuration and does not choose between the two; open question 6 asks
whether the profile should.

### 5.8 The attestation grade is reported, not required

The registry records at registration whether the credential came with an attestation the relying
party verified. The verifier reports that grade with every outcome past the gate and decides
nothing on it.
Which authenticators a relying party accepts is its policy, and a profile that required attested
ones would be making that choice for it.

### 5.9 An approver the directory cannot resolve is unverifiable

W-23 asks whether the approver is the record's subject under the verifier's identity policy, which
is #191's wording. When the directory has no entry for the approver, or an entry that resolves to
no one, as a deprovisioned account's does, the verifier cannot answer, and W-24 says so rather
than letting the silence read as a pass. Vector 55's approver has no entry and vector 56's has one
that resolves to no one; an implementation that takes an entry's presence as a resolution passes
56.

## 6. Composition with `approval-outcome`

A record that acted under an approval cites it as

```json
{"rel": "approval-outcome", "id": "<approval_id>", "resolver": "<party>",
 "digest": "sha256:<RFC 8785 SHA-256 of the whole artifact>", "retention": "P10Y"}
```

The four rules of §3.1.2 hold unchanged: (1) `references` does not affect `runtime.platform`;
(2) the record signature covers `references`; (3) a verifier does not reject a record because an
entry cannot be resolved, and does not treat a resolved reference as attested evidence; (4) a
producer that cannot name a `resolver` omits the entry. Every citing record in the set is
schema-valid and its signature verifies whatever its artifact's outcome, the refusal and the
invalid and unverifiable artifacts included, so a record's verification never depends on what its
reference resolves to, which is consistent with rule 3. The records are checked without the
maximum age §3.2.2 sets, because the fixtures are dated, and no vector has a reference that fails
to resolve.

W-21 to W-24 are this profile's composition rules, and they are findings about the artifact as
evidence for that record, never about the record. W-22 and W-23 restate #191's separation of
duties as checks on this artifact, W-24 names the case where W-23 cannot be judged, and none of
them decides anything #191 holds. W-21 is not separation of duties: it takes the digest over the
whole artifact, assertion included, because a digest over `{profile, approval}` identifies the
approval and not the assertion, and any other assertion over the same approval would match it
(vector 48). It is also what catches a resolver that returns a
different approval under the cited identifier: vector 50's artifact is a good approval, reissued
under the same `approval_id` with a new nonce and subject, and only the digest tells it from the
one the record cited.

With the PIC/TRACE bridge, `subject_kind` is `pic-trace-bridge-authorization` and the digest is
over the bridge's `authorization` object. The bridge's signature stays the bridge's. What this
artifact adds is that a credential registered to a person signed a challenge committing to that
object's digest, with the window and flags the artifact records.

## 7. The conformance corpus

`examples/webauthn-approval/` holds 72 vectors from a generator that derives every key from one
published seed by label. Each vector carries its artifact, its configuration, the citing record
where there is one, and its expected outcome, codes and attestation grade, written in the
generator's case table and never computed by the verifier. Every assertion carries a real
signature by a software key derived from the seed, over authenticator data in the WebAuthn Level 3
§6.1 layout; none was captured from a browser or a hardware authenticator, and the authenticator
data is constructed. §8 describes one artifact that was captured, which is not a vector. The
credentials are ES256 and
EdDSA, and ES384 for one credential, which no vector's configuration declares, so that vector 10
is unverifiable; vector 67's registry holds an EdDSA key under -19. ECDSA is signed
deterministically under RFC 6979, so the set regenerates byte for byte. Of the 72, 17 are valid,
2 are refusals, 9 are unverifiable and 44 are invalid, and 11 carry a citing record.

`tests/test_webauthn_approval_vectors.py` is the reference verifier, a registry of the rules above
with a single point where codes are emitted. `tests/test_webauthn_approval_completeness.py` holds
the set to #124. Deleting any one rule changes the result of at least two vectors, and twelve
rules carry more: W-2 and W-11 five each, W-4 four, and W-1, W-5, W-9, W-12, W-16, W-17, W-19,
W-20 and W-21 three each.

49 implementation defects are declared, each a check a reviewer could write and read as correct,
and each fails at least one vector. A defect replaces one rule's check and nothing else, so, as
with a deleted rule (§4), the gate and the stages run as before. Of the 46 on rules that can
decide an outcome, 43 change the outcome of every vector they fail, as the suite measures it, and
3 change only the codes of vectors whose outcome another rule decides:
`challenge_skipped_when_cited` on 49, `decision_reported_only_when_otherwise_sound` on 31, 33 and
66, and `supported_set_read_through_aliases` on 67; the three on the counter rules change codes
only, which is all an advisory rule can change.

For every rule, at least one declared defect fails some of the rule's vectors and not the others.
That is #124's criterion, which asks for one defect that splits a rule's vectors and not for one
per pair, and one rule's vectors are not all told apart: no declared defect separates 31, 33 and
66 from one another under W-11. They are the three on which deleting W-11 changes the codes and
not the outcome, and the rules that decide their outcomes are W-7, W-8 and W-9, one each.

42 of the 49 fail only vectors the rule they weaken is load-bearing for. The other 7 are stricter
than their rule and fail only valid controls: `client_data_closed` fails 21 by holding the client
data to the members WebAuthn defines, `canonical_form_escapes_non_ascii` fails 63,
`tolerance_ignored` fails 44 and 45, `tolerance_at_the_start_only` fails 45,
`unusable_at_issuance` fails 70, `unrecorded_eligibility_read_as_false` fails 71, and
`client_data_reserialized` fails 69.

Three of the defects are readings of WebAuthn Level 3 that look right and are ruled out by its
text: comparing the challenge as decoded bytes (vector 18), treating BS without BE as policy
(vector 35), and reporting a counter only when it goes down (vector 59).

Vectors 61 to 72 are near misses. Each sits beside vectors its rule already had and differs from
them in one respect that a plausible shortcut gets wrong. For each, the defects in its row take
that shortcut, pass every vector numbered below 61, and fail it:

| Vector | What it holds | Defects |
|---|---|---|
| 61 | The profile identifier with `.1` appended | `profile_prefix_match` |
| 62 | A nonce of 15 bytes | `nonce_length_unchecked` |
| 63 | An `approval_id` outside ASCII, which RFC 8785 writes as UTF-8 and Python's `json.dumps` escapes by default | `canonical_form_escapes_non_ascii` |
| 64 | Client data of type `payment.get`, the type SPC gives its assertions | `payment_confirmation_accepted` |
| 65 | An origin that begins with the registered one and is another host | `origin_prefix_match` |
| 66 | A deny with BS set and BE clear | `backup_state_checked_for_allows_only` |
| 67 | A registry holding -19 for the EdDSA key the artifact names as -8 | `fully_specified_identifiers_aliased`, `supported_set_read_through_aliases` |
| 68 | An ES256 signature as the 64 bytes of `r` and `s` | `either_signature_encoding_accepted` |
| 69 | Client data with a space after each separator, signed as serialized | `client_data_reserialized` |
| 70 | `now` equal to `issued_at`, with no clock tolerance | `unusable_at_issuance` |
| 71 | A synced passkey whose backup eligibility the registry never recorded | `unrecorded_eligibility_read_as_false` |
| 72 | A reported counter of zero where the relying party holds four | `zero_read_as_no_counter` |

The corpus does not test:

- a citation with no digest, which is open question 3;
- a record whose only `approval-outcome` entry names a different approval;
- most of W-2's clauses. It exercises five, one vector each: a member outside the closed top level
  (12), the digest pattern (13), the upper end of the integer range, on `expires_at` (14), the
  window's order (15) and the nonce's length (62). It does not exercise the required members, the
  member types, the `decision` values, the minimum lengths of `approval_id`, `approver`, `rp_id`,
  `origin` and `subject_kind`, the base64url patterns, the nonce's alphabet, the closure of
  `approval` and `assertion`, the lower end of the range on `expires_at`, the range on `issued_at`
  and `alg`, or the decoding clauses: in every vector the assertion members decode, the
  authenticator data is 37 bytes, and the client data is an object;
- an artifact with no `profile` member;
- authenticator extensions, and the AT and ED flags, which no rule reads;
- related origins under WebAuthn Level 3 §5.11: a verifier here accepts exactly the origins the
  registry lists;
- an `rp_id` that differs from the registered RP ID only in letter case, a client data origin that
  differs from a registered origin only in letter case, or a `topOrigin` member whose value is
  null. The reference verifier compares RP IDs and origins exactly and reads a null `topOrigin` as
  present, and no vector tells it apart from a verifier that does neither.

### 7.1 What an independent WebAuthn library makes of the set

The rules above have one implementation, written with the vectors. To see whether the vectors'
WebAuthn layer reads the same way to an implementation that knows nothing of this profile, each
vector's assertion was given to py_webauthn 3.0.0 (the relying-party library `webauthn` on PyPI),
with what a relying party would hold: the challenge derived from the artifact's own
`{profile, approval}`, the registered RP ID and origins, the registered key as a COSE_Key, the
stored counter, and whether user verification was required. It judges only the WebAuthn layer, so
it says nothing about the gate, the window, the decision, the artifact's `alg`, the algorithms the
verifier declares, the approver or the citing record.

It ran on 66 of the 72. The other six were not put to it: 06, 07 and 61 are under another profile,
whose challenge this document does not define, 08 and 09 name no registered credential, and 14
has no canonical form, so no challenge. Of the 66, it:

- refuses 20 on the step this profile's code for them names: 16, 17 and 49 on the challenge, 19,
  20 and 64 on the type, 24 and 65 on the origin, 26 and 27 on the RP ID hash, 30 and 31 on UP, 32
  and 33 on UV, 34, 35 and 66 on BS without BE, and 40, 41 and 68 on the signature;
- accepts 14 of the 17 valid vectors, and refuses 59, 60 and 72 on the counter, failing the
  ceremony on it as §7.2 allows where this profile reports it and decides nothing (§5.3);
- accepts the 18 this profile decides by a rule outside the WebAuthn layer: 11, 13, 15, 38, 39,
  42, 43, 46, 47, 48, 50 to 56, and 62;
- accepts 8 that this profile refuses at the WebAuthn layer. Vector 18: it compares the challenge
  as decoded bytes, a step both take and read differently (§5.1). 22 and 23: it does not implement
  §7.2's `crossOrigin` and `topOrigin` steps. 25: it accepts any origin in the list it is given,
  and the harness gives it the credential's registered origins; given the one `approval.origin`
  names, it refuses 25. 28 and 29: §7.2's step for a user identified before the ceremony, that the
  account holds the credential, is the relying party's lookup, and the harness hands the library
  the credential. 36 and 37: it has no comparison of the flags with recorded backup eligibility;
- refuses 3 that this profile decides elsewhere. Vector 10, unverifiable here, with "Unrecognized
  EC2 signature alg -35": it has no ES384. Vector 67, invalid here under W-16, with "OKP public key
  with alg -19 and crv 6 is not supported": it has -8 and not -19. Vector 12, which this profile
  refuses on its shape, on the counter, which it checks before the signature; with the counter set
  aside, it refuses 12 on the signature.

## 8. One artifact from a browser

The vectors show that the rules hold together, not that a browser produces what they expect,
since their client data and authenticator data are constructed.
`examples/webauthn-approval/browser-capture/` holds one artifact whose assertion a browser
produced, with the script that captured it. The script runs headless Chromium 141 through
Playwright with a DevTools virtual authenticator (CTAP2, internal transport, user verification),
registers an ES256 credential without attestation, builds an approval naming that credential,
derives the challenge as §3.1 does, and calls `navigator.credentials.get` with that challenge and
with `allowCredentials` naming the credential alone. The client data is the browser's:
`{"type":"webauthn.get","challenge":"…","origin":"http://localhost:42509","crossOrigin":false}`.
The virtual authenticator keeps a counter, 1 at registration and 2 at the assertion, and the
registry holds the 1 as the stored count, so neither counter rule has anything to report.

The reference verifier finds the artifact valid, with no codes and a self-asserted grade. Moving
`expires_at` a day later makes it `challenge_mismatch`, and changing one bit of the signature
makes it `signature_invalid`; the test module checks all three. py_webauthn 3.0.0, given it as
§7.1 gives the vectors, accepts it. It is not a vector: the virtual authenticator draws its key at
registration, and the nonce and the times are fresh on every run, so it cannot be regenerated. It
is evidence about one browser and one software authenticator, not about security keys or
platform authenticators.

## 9. What this proposal does not do

- It is not a display attestation. The artifact commits to the digest of an object, not to what
  the approver was shown (§1).
- It does not bind an approval to a run, so two records can cite one approval and it is valid for
  both. Single use is the enforcing component's to guarantee; #191 asks for consumption and this
  artifact alone does not provide it.
- It does not bind the state the approver evaluated. Predecessor binding stays in #191.
- It does not establish that the action that executed is the approved object (§3.2).
- It does not make the person behind the credential anyone in particular. The registry says who
  registered the credential and at what grade; the artifact says that credential signed.
- Attribution is as good as the credential registry and the directory, which the relying party
  keeps and the artifact does not carry. A relying party run by the record's subject could register
  its own credential under an approver's name, and no rule here would see it.
- It judges an approval against the registry as it stands when the verifier reads it. A
  credential removed after it approved something makes that approval unverifiable.
- It changes nothing about the ceremony itself, beyond the constraint in §3.1 that the credential
  is chosen before it.
- It does not make approvals unlinkable. Every approval a credential signs carries its
  `credential_id`, so whoever holds two artifacts can tell that one credential signed both,
  whatever `approver` says. A scoped pseudonymous `approver`, #191's direction, does not change
  that.
- It is not post-quantum: every credential in the set is elliptic-curve. No rule names an
  algorithm, and W-22's key comparison already reads RFC 9964's `AKP` members (§4), but no vector
  holds an ML-DSA credential and nothing here has been run against one.

## 10. Open questions

1. The profile identifier.
2. The home: `docs/rfcs/`, or `docs/integration/` beside the bridge, with a schema file if adopted.
3. A citation with no digest. The corpus leaves it unexercised and the verifier reports nothing
   about it. Under #279's discipline the absence should have a name: whether it is advisory, like
   W-18, or makes the approval unverifiable for that record is the question.
4. A registry with history, so that an approval can be judged against the registry as it stood at
   `issued_at`.
5. Whether `approver` should be constrained, to a URI or a DID.
6. What `now` is at audit time (§5.7), and whether the profile should name a default clock
   tolerance.
7. Whether `credential_id` should leave the challenge's pre-image, so that one challenge serves
   every credential an approver holds (§3.1). W-20 would still tie the signature to the named
   credential's key, since the signature verifies under no other.
8. Whether the fully specified identifiers of RFC 9864 should be accepted as the WebAuthn
   identifiers they correspond to (§5.4).

## 11. Related

- `spec/trace-v0.2.md` §3.1.2 (`references`, `approval-outcome`), §3.2.2 (canonical bytes and
  the integer range), §3.2.3 (why a timestamp is not trusted), §3.3.2 (unverified, not invalid).
- [`docs/references-registry.md`](../references-registry.md) and
  [`docs/crosswalks/chap-review-decisions.md`](../crosswalks/chap-review-decisions.md).
- [`docs/integration/pic-trace-bridge-v1.md`](../integration/pic-trace-bridge-v1.md): the trust
  boundary this profile keeps.
- [`docs/rfcs/a2a-delegation-profile.md`](a2a-delegation-profile.md): the shape of the reference
  verifier and its completeness suite.
- #191 (attributable approval outcomes), #226 (the relation registry), #279 (absence named per
  surface), #124 (vector adequacy).
- W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 3*, Recommendation,
  25 August 2026, <https://www.w3.org/TR/2026/REC-webauthn-3-20260825/>: §3, §5.4, §5.8.1,
  §5.11, §6.1, §6.1.1, §6.1.3, §6.5.5, §7.2, §13.4.3.
- W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 1*,
  Recommendation, 4 March 2019, <https://www.w3.org/TR/2019/REC-webauthn-1-20190304/>: §10.2,
  §10.3.
- W3C, *Secure Payment Confirmation*, Candidate Recommendation Draft, 2 July 2026,
  <https://www.w3.org/TR/2026/CRD-secure-payment-confirmation-20260702/>: §1.1.1.
- RFC 8785 (JSON Canonicalization Scheme), RFC 6979 (deterministic ECDSA), RFC 7638 (JWK
  thumbprint), RFC 8037 (the `OKP` key type), RFC 9864 (fully specified algorithms for JOSE and
  COSE), RFC 9964 (ML-DSA for JOSE and COSE), and the IANA COSE Algorithms registry for the
  identifiers named in §5.4 and -257.
- py_webauthn 3.0.0, the relying-party library `webauthn` on PyPI (§7.1), and Playwright with
  Chromium's DevTools virtual authenticator (§8).
