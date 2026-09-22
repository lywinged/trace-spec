# Passkey-signed approvals

An approval artifact pairs an approval object with a WebAuthn authentication assertion, and
the relying party derives the assertion's challenge from the approval, so the passkey signs a
challenge that commits to the approval without the authenticator ever seeing it. These vectors are
the conformance material for the proposal in
[`docs/rfcs/webauthn-approval-profile.md`](../../docs/rfcs/webauthn-approval-profile.md).
Informative: the artifact is not a Trust Record, and nothing here is normative until the
proposal is.

Each file is one vector:

| Member | What it is |
|---|---|
| `id`, `name`, `description` | The vector's identifier, its name as in the filename, and what it isolates |
| `spec` | The document whose rules it exercises |
| `context` | The relying party's configuration: clock, clock tolerance, policy, supported algorithms, credential registry and approver directory, and the record signer's key when a record is present |
| `artifact` | The approval artifact under test |
| `record` | Where present, a signed v0.2 Trust Record citing the artifact as `rel: "approval-outcome"` |
| `expected` | The outcome, the sorted codes and the credential's attestation grade a verifier following the proposal reports |

Every `expected` block is written by hand in the generator's case table, never computed by
a verifier. [`tests/test_webauthn_approval_vectors.py`](../../tests/test_webauthn_approval_vectors.py)
is the reference verifier and checks every vector against its block;
[`tests/test_webauthn_approval_completeness.py`](../../tests/test_webauthn_approval_completeness.py)
deletes and weakens each rule in turn and holds the set to two load-bearing vectors per rule
and a declared defect that tells them apart (#124).

## The cases

| Vectors | What they exercise |
|---|---|
| `01` to `05` | Controls: an ES256 security key, an EdDSA passkey with no counter, a synced passkey, an approval cited by a record, and a counter of zero after zero |
| `06` to `11` | What the verifier cannot read: another profile, an unregistered credential or one named in the wrong case, an algorithm it cannot compute |
| `12` to `15` | The artifact's shape: an extra member carrying a key, a digest in uppercase, a time past the integer range, a window that closes before it opens |
| `16` to `18` | The challenge: derived without `profile`, the approval rewritten after the ceremony, the right bytes in a padded string |
| `19` to `29` | The client data, one control among them with a member no rule reads, then the origin, the RP ID and the approver |
| `30` to `37` | The authenticator flags: presence, verification, backup eligibility and backup state |
| `38` to `41` | The algorithm and the signature |
| `42` to `45` | The validity window, and the clock tolerance at both ends |
| `46` and `47` | A deny, alone and cited by a record |
| `48` to `56` | The citing record: its digest, including a resolver that returns another approval under the cited id; the record's own key; the record's subject as approver; and an approver the directory cannot resolve |
| `57` to `60` | The signature counter: no state, a null count, an equal count, a lower count |
| `61` to `72` | Near misses, each beside vectors its rule already has: a profile identifier with a suffix, a 15-byte nonce, an `approval_id` outside ASCII, Secure Payment Confirmation's client data type, an origin that extends the registered one, a deny with BS set and BE clear, a registry holding RFC 9864's -19, an ECDSA signature in the fixed-length form, client data with whitespace, an approval judged in the second it was issued, a synced passkey whose eligibility was never recorded, and a counter reset to zero |

Every citing record verifies as a Trust Record whatever its artifact's outcome, checked
without the maximum record age because the fixtures are dated, so a record's verification
never depends on what its reference resolves to. That is consistent with §3.1.2 rule 3, which
says a verifier does not reject a record because a reference cannot be resolved and does not
treat a resolved one as attested evidence; no vector has a reference that fails to resolve.
The test module checks each record.

## Keys

Every key derives from the published seed `trace-spec examples/webauthn-approval 2026-09-22`
by label, in [`gen_webauthn_approval_vectors.py`](gen_webauthn_approval_vectors.py), so
anyone can reissue any vector. No private key is committed. Every assertion carries a real
signature by a software key derived from the seed, over authenticator data constructed in the
WebAuthn Level 3 layout; none was captured from a browser or a hardware authenticator. ECDSA
signatures are deterministic (RFC 6979), so the generator reproduces the committed files byte
for byte:

```bash
python examples/webauthn-approval/gen_webauthn_approval_vectors.py
```

The approved object itself is not committed. `subject_digest` is a labelled derivation from
the seed, because no rule reads the object: whether the action that executed is the approved
one is the comparison the component enforcing the approval makes.

## One artifact from a browser

`browser-capture/` is not a vector. `browser-capture.json` is one approval artifact whose client
data and authenticator data came from a browser, headless Chromium 141 with a DevTools virtual
authenticator, over a challenge derived as the proposal's §3.1 says, with the configuration it is
judged under. `capture.js` is the script that produced it, run through Playwright:

```bash
NODE_PATH="$(npm root -g)" node examples/webauthn-approval/browser-capture/capture.js
```

The virtual authenticator draws a new key at registration and the approval's nonce and times are
fresh, so a run writes a different file and the committed one cannot be regenerated. The test
module checks that the reference verifier finds it valid, and that moving `expires_at` or
changing one bit of the signature makes it invalid. What it shows is that one browser's client
data and one software authenticator's output meet the rules; it says nothing about security keys
or platform authenticators.
