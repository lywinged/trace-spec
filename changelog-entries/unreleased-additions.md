- **Acta receipt verifier: JWK, signature hex, and JSON input hardening.**
  `tools/acta_receipt_verifier.py` now rejects JWKs carrying private or symmetric key
  parameters (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) or non-canonical unpadded
  base64url `x` values in `issuer_key` (`malformed_key_set`), requires `signature.sig`
  in `signature_verifies` to be 128 lowercase hex characters without whitespace
  (`signature_invalid`), rejects duplicate JSON object keys and catches `RecursionError`
  in `_read_json` (`malformed`), and handles uncanonicalizable or deeply nested payloads
  and predecessors in `signature_verifies` and `chain_link_matches` (#605, by @drk-ram).

- **`tdx_collateral` and `snp_collateral`: TCB status validation, minimal DER integer
  decoding, and policy input validation.** `tdx_collateral._converge` now validates both
  `platform` and `other` against `_STATUS_TO_QV` while preserving Intel DCAP QVL's
  `convergeTcbStatuses` (`EvaluateTcb.cpp:187-225` at `d12717e3`) convergence semantics,
  and `tdx_collateral` rejects non-minimal DER length and integer encodings in PCK SGX
  extensions. `snp_collateral._der_uint` now rejects negative, non-minimal, and
  out-of-range (`> 255`) DER integers in VCEK TCB extensions, and `TcbFloor`,
  `CollateralPolicy`, `appraise_collateral`, and `tcb_component` validate their input
  types and fail closed with `CollateralDenied` (#603, #610, by @drk-ram; review by
  @dinakarjs and @lywinged).

- **Registry Anchor Format v1 §1 states the five canonical JSON rules and excludes unpaired UTF-16 surrogates (#536, #448 items 3, 16, 19).**
  `spec/registry-anchor-v1.md` §1 now states the five language-independent canonical JSON
  serialization rules (recursive Unicode code-point key sorting, `","` and `":"` separators
  with no whitespace, string and surrogate-pair escaping rules including `\u007f` for ASCII
  DEL `U+007F`, integer zero `0` without a minus sign, and no trailing newline), excludes
  unpaired UTF-16 surrogates (`U+D800` to `U+DFFF`) in strings and object keys from the
  anchor-leaf profile alongside non-integer numbers and unsafe integers, and narrows §0's
  equality boundary to ASCII other than DEL (`U+007F`). Both `agentrust_trace.sign.anchor_bytes`
  (`UnanchorableValue`) and `trace_tests.inclusion.canonical_claim_bytes` (`InclusionError`)
  now refuse unpaired UTF-16 surrogates in string values and object keys. Also updates
  `examples/verifier-compatibility/README.md` to reflect that Obligations 2 and 3 of #116 are
  normative in `spec/trace-v0.2.md` §3.3, and attributes external-evidence fields and
  verification in `docs/crosswalks/acta-decision-receipts.md` to §3.3.2 and §3.3.3 (by
  @drk-ram, with review companion from @dinakarjs).

- **`intent_bridge` and `successor_observation`: entry validation and observation isolation.**
  `verify_bridge` and `verify_successor_artifact` now validate `trusted_authorizer_jwk`
  and `trusted_observer_jwk` with `_pubkey_from_jwk` and validate caller options (`now`,
  `declaration`, `tool_call`, `pic_intent_digest`, `pic_args_digest`, `trusted_observer`,
  `authorization_id`) at entry before comparing key identifiers, checking signatures, or
  classifying a signed `deny` as `AuthorizationDenied`; `_bind_successor_observation`
  validates `expected_successor_digest` before inspecting `after`; and
  `evaluate_successor_observation` passes `copy.deepcopy(observation)` to `predicate` so
  a caller predicate cannot mutate `after["observation"]` in place (#617, by @drk-ram).

- **`adapters`: validate `data_class`, policy/appraisal/SLSA fields, URI formats, and
  UTF-8 string boundaries in `TraceAGTAdapter`, `TraceSandboxAdapter`, and
  `SandboxAttestation`.** Both adapters now reject empty, non-string, or lone-surrogate
  `data_class` and string configuration values, validate `PolicyInfo`, `Appraisal`, and
  `BuildProvenance` at both `__init__` and `build_trust_record`, and enforce RFC 3986
  URI format (matching `validate_json`) on `transparency`, `appraisal_verifier`,
  `appraisal_policy_ref`, `build_provenance_uri`, `policy_uri`, and
  `SandboxAttestation.rim_uri` (#615, by @drk-ram).

