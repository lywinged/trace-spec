# Decisions

Append-only decision records, newest first. Each entry is a **Tier 2 / historical**
document: true when written, not maintained. Read it for intent, and re-check the code
before acting on any file, flag, or command it names. To reverse a decision, append a new
entry that names the one it supersedes; do not edit the old entry.

---

## 2026-08-05 — This project's own release evidence is Level 0, and is never described as attested

**Recorded by:** Claude (Opus 5)
**Decision-maker:** Louie Lu
**Status:** PROPOSED — drafted for approval; the boundary in point 2 is the part that needs a decision-maker, not the tooling

**Decision:**

1. **trace-spec publishes an evidence chain for its own releases.** Shipped now: SLSA v1
   build provenance over every distribution file, plus a signed SBOM bound to those same
   digests, both via `actions/attest@v4` — short-lived Sigstore certificates, logged to
   Rekor, verifiable by anyone with `gh attestation verify`. A project that defines
   `build_provenance.provenance_uri` and points it at "a Sigstore/Rekor or compatible log"
   should be able to produce one for itself.

2. **That evidence is Level 0, and is never presented as anything else.** GitHub-hosted
   runners are not a TEE. Nothing in this pipeline is hardware-rooted, and
   `LIMITATIONS.md` already states that Level 0 is "suitable for development and audit
   trail tooling only — not for third-party verification". Public wording about the
   project's own releases says what it is: *the build is provenance-signed and
   transparency-logged; it is not hardware-attested.* No release note, README line, slide,
   or demo says or implies otherwise.

3. **If a self-describing Trust Record is emitted later, `runtime.platform` is
   `software-only`.** That enum value exists precisely so a dev-mode record cannot be
   mistaken for hardware-backed evidence by a consumer that only inspects
   `runtime.platform` (see the comment in `models.py`). Using it makes the honesty
   structural rather than a disclaimer someone has to read.

4. **Deferred, not rejected:** a hash-chained release ledger (each release naming the
   digest of its predecessor) and a real TRACE Trust Record emitted per release by the
   library itself. Both are worth doing; neither is done. They are listed here so a later
   session does not mistake the current partial state for the intended end state.

**Rationale:**

The value of TRACE is the precision of what a record does and does not prove. A project
that overstates its own evidence has argued against its own thesis, and the overstatement
would be found by exactly the audience — auditors, CISOs, standards reviewers — the
project is trying to convince. The same discipline applies wherever a
certification is quoted: one that belongs to a chip does not transfer to the operating
system running on it, nor to the application above that. Different scopes, different
claims.

The tooling half is nearly free, which is what makes the claim discipline the real
decision rather than the engineering.

**Implementation:** `.github/workflows/publish.yml` — the `Attest build provenance` and
`Attest SBOM` steps in the `build` job, plus the `attestations: write` permission they
need.

**Corrections to the assessment that preceded this decision** (recorded so a later session
does not redo the analysis and reach the same wrong conclusions):

- **PyPI already has PEP 740 attestations for every release**, 0.1.0 through 0.5.1.
  `pypa/gh-action-pypi-publish` defaults `attestations: true` under Trusted Publishing, so
  this has been happening without anyone configuring it. Verify with the PyPI simple API
  (`Accept: application/vnd.pypi.simple.v1+json`) and read the `provenance` field. The
  action input is now stated explicitly in the workflow, which changes nothing today and
  keeps the guarantee if the upstream default ever moves.
- **SBOMs are already attached to GitHub releases.** `anchore/sbom-action` defaults
  `upload-release-assets: true`, so the `release: published` path in `sbom.yml` has never
  been the "evaporates after 90 days" case. Only the `push: main` path is artifact-only.
- What was genuinely missing was the *signing and binding*: an SBOM that no one signed,
  and no build provenance in the repository's own attestation store.

**Supersedes:** nothing.
