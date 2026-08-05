# Roadmap

## Shipped

**v0.1 — 23 June 2026.** Announced at Confidential Computing Summit, San Francisco.

- Full Trust Record schema: `subject`, `model`, `runtime`, `policy`, `data_class`, `tool_transcript`, `build_provenance`, `appraisal`, `transparency`, `cnf`
- Wire formats: EAT/JWT and CBOR-COSE
- Hardware roots: NVIDIA H100/Blackwell, Intel TDX, AMD SEV-SNP, Azure MAA, GCP Confidential Space, AWS Nitro
- JSON Schema and hardware example records
- Reference implementation: cMCP Phase 1 (Cedar policy enforcement, TRACE Level 2 emission)

**v0.2 — 28 July 2026.** A correction release, not the feature milestone this document previously labelled "v0.2". Its one normative change is the EAT profile URI: `tag:agentrust-io.com,2026:trace-v0.2` replaces `tag:agentrust.io,2026:trace-v0.1`, which named a domain the project does not control and was invalid under RFC 4151. No field was added, removed, or re-typed. See [CHANGELOG.md](CHANGELOG.md) and [spec/trace-v0.2.md](spec/trace-v0.2.md).

Also landed across the 0.1–0.5 library releases, additively:

- `subject` accepts DID URIs alongside SPIFFE SVIDs, so DID-native runtimes need no parallel SPIFFE identity
- The optional `delegation` block (`parent_record_hash` + `credential_id`) — the foundation of the A2A profile
- `azure-cvm-sev-snp` platform, hardware-validated on a live Azure SEV-SNP VM
- RFC 8785 (JCS) canonicalization, replacing a non-conformant `json.dumps` form
- Verification hardening: an explicit trusted key is required, freshness and nonce binding are enforced, and revocation is checked at verification time
- **OWASP Agentic AI Top 10 cross-walk** — which TRACE claim evidences which control for each of the 10 ASIs

## Next — v0.3

The feature scope previously listed here under "v0.2", renumbered because the shipped v0.2 consumed that number for the profile-URI correction. Driven by founding-member feedback and the open questions in §7 of the spec.

No target date is set. [CHARTER.md](CHARTER.md) still lists the MCP and A2A profiles for Q3 2026; none of that work has started as of this writing, so the two need reconciling by the maintainers rather than here.

- **MCP profile** — normative claim shape and binding rules for MCP tool-call transcripts (`tool_transcript`); proposed for upstream contribution to MCP spec governance
- **A2A profile** — normative binding rules over the `delegation` block. A2A is stable at v1.x and the link block has landed, so the remaining work is the rules that say when a hop MUST populate it and how a verifier walks the chain
- **Vendor platform annexes** — co-authored informative claim-mapping docs for NVIDIA NRAS, Intel Trust Authority, AMD CoRIM, Azure MAA, GCP Confidential Space
- **MITRE ATLAS cross-walk** — TRACE claim coverage mapped to relevant ATLAS tactics
- **Encrypted claims envelope** — normative profile for JWE / COSE-Encrypt when `data_class` requires confidential transport to verifiers (open question §7 Q5)
- **Reference to IETF AIIP** — coordinate with draft-ritz-aiip and determine disposition (open question §7 Q7)
- **cMCP Phase 2** — policy enforcement and `tool_transcript` binding; first full Trust Records

## Later — v1.0 standard (2027)

- TSC governance under CoSAI / Linux Foundation
- All §7 open questions resolved
- Complete conformance certification program
- Post-quantum signature profile (ML-DSA, tracking NIST SP 800-208)
- MCP and A2A profiles ratified and proposed to respective upstream governance bodies
- AAIF-assigned canonical profile URI replacing the provisional tag URI
- Multi-language verification libraries (Python, TypeScript, Go, Rust)

## What TRACE will not do

- Replace RATS, EAT, SLSA, SPIFFE, SCITT, or MCP — TRACE is a profile of these
- Specify a centralized Trust Record registry — verification is designed to work without one
- Build a TEE platform — hardware support targets open silicon (TDX, SEV-SNP, NVIDIA CC) and any platform that produces RATS-conformant evidence
- Adjudicate model alignment or output correctness — TRACE proves what executed and what was in force; correctness is out of scope

## Influencing the roadmap

Open a GitHub issue with the `spec` or `roadmap` label. Contributor and community feedback from the CC Summit period (June–September 2026) has priority for v0.3 scope.
