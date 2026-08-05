# Changelog

All notable changes to the Auditable MCP specification are documented here. The project uses a `MAJOR.MINOR.PATCH` scheme. While the version is below `1.0.0`, minor and patch revisions may introduce breaking changes, as is conventional for `0.x` drafts.

This changelog is informative. Normative force (the RFC 2119 keywords) lives only in the specification; the summaries below merely describe it.

## v0.2 - 2026-07-25

Redefines `egress` semantics and advances the wire `spec_version` to `auditable-mcp/0.2`. Driven by production dogfooding: a physical-network definition of `egress` marks nearly every operation in a zero-trust / cloud-native deployment as egress, destroying its value as a DLP signal.

### Breaking changes

- **`spec_version` advances `auditable-mcp/0.1.1` -> `auditable-mcp/0.2`.** The version string is part of the canonical event bytes, so all golden digests change; there is no on-the-wire compatibility window between draft versions. New digests: Level-1 sealed chain `242e6f5c...`, Level-2 signed chain `e04f3afb...`.

### Changed (normative)

- **§4.2 `egress` is redefined against a logical data-governance boundary, not physical network topology.** A tenant-governed system or SaaS platform (e.g., a corporate Google Workspace or Salesforce instance) is inside the boundary even when reached over an external HTTP request; `egress` is `true` only when tenant context leaves the organization's governance scope (a public search engine, a public or unmanaged third-party API). A tool sets `egress` from the DLP risk of exfiltration, not from the presence of network transmission.
- **§7.5 governance-boundary reconciliation is re-based on the governance boundary.** A host that performs reconciliation derives its observations from a control that classifies destinations by governance scope - a Layer-7 control such as a CASB, DLP engine, or secure web gateway - rather than a raw L3/L4 network gateway, which cannot tell a call to a tenant-managed SaaS apart from an out-of-governance egress. `unreported-egress` (§7.6) fires on an observed out-of-governance egress with no correlated self-reported `egress: true` event. The concrete CASB/DLP integration remains outside protocol scope. §10.2 and §10.7 wording aligned to "out-of-governance egress".

### Reference alignment

- `spec/schema/audit-event.schema.json` pins `spec_version` to `auditable-mcp/0.2`; the TypeScript and Python reference implementations and `spec/vectors/*.json` are regenerated at v0.2. The reference demo models the v0.2 egress semantics - an internal `db.query` (no egress), an external `ext.geocode` enrichment (the egress), and an internal `db.write` - so the Level-1 chain vector reflects §4.2; the per-event fixtures in `events.json` keep their byte-coverage values, non-normative per §8.4. Both reference ports reproduce both digests.

## v0.1.1 - 2026-07-21

First revision after two independent reference implementations (TypeScript and Python) were completed end to end. Every change below traces to a concrete "the spec did not say, so the implementation had to decide" gap surfaced by that work, followed by a standards-review hardening pass. The JSON Schemas, reference implementations, and conformance vectors are aligned to v0.1.1 (see "Reference alignment" below).

### Breaking changes

- **Renamed the Level-2 tool counter `sequence` -> `signer_seq`** (§4, §5, §7, §10). The old name was one character away from the host-assigned ledger `seq` and denoted a different scope (per-`key_id` signer counter vs per-partition ledger index); the two were repeatedly conflated during implementation. Because the field name is part of the canonical event bytes, this changes the wire format, so `spec_version` advances to `auditable-mcp/0.1.1`.

### Backward compatibility

- **`spec_version` advances `auditable-mcp/0.1` -> `auditable-mcp/0.1.1`.** A v0.1.1 host expects `auditable-mcp/0.1.1` events and does not accept `auditable-mcp/0.1` events, and vice versa. There is no on-the-wire compatibility window between the two draft versions; `0.x` drafts are expected to break. The new `spec_version` capability field (§6.1) lets participants detect the mismatch during negotiation instead of at first event.

### Added (normative)

- **§7.6 Reason and anomaly code vocabulary (two-tier).** A tool branches on an abort reason and an independent verifier reads anomaly kinds from a ledger authored by a different implementation, so an ad-hoc "RECOMMENDED, extensible" vocabulary was too weak on exactly the codes that drive control flow. Replaced by a two-tier model:
  - **Tier 1 (fixed, normative):** host reject/unavailable codes (`schema-invalid`, `replay-detected`, `signature-invalid`, `l2-unsigned`, `unknown-key`, `internal-error`), tool abort codes (`hash-mismatch`, `host-rejected`, `host-unavailable`), and cross-implementation anomaly kinds (`schema-invalid`, `record-hash-mismatch`, `digest-mismatch`, `seq-gap`, `signer-seq-gap`, `signature-invalid`, `orphaned-outcome`, `unreported-egress`). The set is a closure: every reject, unavailable, abort, and anomaly condition maps to exactly one Tier-1 code. `seq-gap` (host ledger index) and `signer-seq-gap` (per-key signer counter) are deliberately distinct.
  - **Tier 2 (local diagnostics):** finer reasons (e.g. a numeric-domain violation, a specific missing field) MUST roll up into a Tier-1 code; the finer detail is a host-local, out-of-band diagnostic and is not carried on the wire or sealed into the ledger.
- **§5.1 Signature algorithms and key binding.** The event carries `key_id` and `signature` but no algorithm, which left a mixed fleet undispatchable. The algorithm is bound to the `key_id` through the out-of-band registry (no new payload field), and this version defines `Ed25519` and `ECDSA_P256_SHA256` - the latter for KMS/PKI deployments such as AWS KMS, which does not offer Ed25519. The `signature` wire encoding is pinned to standard base64 (with padding).
- **§8.1 Receive-boundary numeric enforcement.** The `|n| <= 2^53-1` domain MUST be enforced before a lossy native parse: some runtimes (e.g. ECMAScript `JSON.parse`) silently round a larger integer to a double during parsing, making post-hoc detection impossible. A host MUST reject at ingestion via a precision-preserving parser or a raw-token screen.
- **§8 Hash-path byte-exactness.** Integrity rests on hashing the exact bytes the tool emitted, so an implementation MUST NOT route an event through a typed model (native UUID / date / reformatted number) that re-serializes it before hashing. Audit fields on the hashing path SHOULD be pattern-validated strings.
- **§6.1 `spec_version` capability field.** Capability negotiation now carries `spec_version`, so participants establish a common version before exchanging events (which themselves carry `spec_version`).
- **§10.8 Attempt/outcome completeness.** An accepted attempt with no correlated terminal outcome is a completeness gap: `audit/outcome` is a fire-and-forget notification whose loss `seq` cannot expose. A verifier MAY flag it after a settling period but MUST NOT treat it as a chain-integrity failure; assured delivery is a deployment concern (an out-of-band acknowledgement), not a `seq` guarantee.

### Clarified

- **§7.4 `signer_seq` gap detection is partition-scoped.** A gap is authoritative evidence of suppression only when the `key_id` is bound to a single partition; where a key spans partitions the interleaving produces benign gaps, so gap detection is advisory there while replay remains a hard reject. The first `signer_seq` observed for a `key_id` establishes the baseline and is never treated as a gap.
- **§8.2 Chain-hash algorithm is version-pinned.** The bare-hex chain hash (vs the algorithm-prefixed `action_context_hash`) is intentional; the chain hash algorithm MUST NOT vary within a `spec_version`.
- **§7.2 Polluted Stop at Level 1.** The host returns `record_hash` on every `accept`, so a Level-1 tool MAY opt into Polluted Stop; it is OPTIONAL at Level 1 and REQUIRED at Level 2.
- **§6.1 `attempt: "request"`.** Documented as a forward-compatibility placeholder reserving the field for a possible future non-blocking mode, retained rather than inlined.

### Standards-review hardening (RFC-grade pinning)

A standards-track review and a from-spec-only interoperability audit surfaced normative gaps that the prose-only revision left half-reconciled; these are now closed:

- **`record_hash` includes `signature` under Level 2 (§8.2).** Made explicit that the preimage's `event` is the complete sealed event (signature retained); the signature-removal rule applies only to signature computation. Added a signed-chain conformance vector (`chain-signed.json`) so both ports pin it byte-for-byte - the case that forks Level-2 Polluted Stop.
- **Tier-1 vocabulary is schema-enforced, on every code-valued field (§7.6).** The Attempt Response `reason` is pinned to the Tier-1 reject enum (plus `internal-error` for `unavailable`); the sealed outcome-event `reason` is pinned to the Tier-1 abort codes (`hash-mismatch` / `host-rejected` / `host-unavailable`), closing the last free-string hole; anomaly `kind` is Tier-1. Tier-2 codes are re-scoped as local diagnostics (not on the wire or in the ledger), with a vendor-prefix namespace, resolving the `additionalProperties: false` / `detail` contradiction. Domain failure detail moves to `action_context`.
- **`signer_seq` baseline fix.** A first observation with `signer_seq > 0` is the baseline and MUST NOT be flagged as a gap; the reference hosts previously flagged it. Regression tests added in both ports.
- **Verifier anomaly kinds are Tier-1 (§7.6).** The reference verifiers now emit `seq-gap` / `record-hash-mismatch` / `orphaned-outcome` (sub-kind in a local detail), not the earlier non-Tier-1 strings.
- **§5.1 signature encoding pinned:** PureEdDSA; ECDSA P-256 as big-endian, 32-byte zero-padded `r || s` (not DER); standard base64 (schema pattern); malformed/wrong-length signatures map to `signature-invalid`.
- **§8.2 signature bytes are hashed verbatim (no malleability normalization).** A host MUST NOT apply cryptographic normalization (e.g. ECDSA low-S coercion) to a `signature` before hashing it; coercing `s` before sealing would compute a `record_hash` divergent from the tool's Polluted Stop preimage and fork the Level-2 chain, even though both signatures verify. Complements the §5.1 verifier rule (accept both low-S and high-S without normalization).
- **§6 message binding:** JSON-RPC `params` is the event object directly; the capability is declared under `capabilities.experimental["auditable-mcp"]`; invalid `audit/outcome` notifications are silently dropped and flagged. Audit decisions (accept/reject/unavailable) are always a JSON-RPC `result`, never a JSON-RPC `error` (reserved for transport faults). `audit/attempt` MUST NOT be batched; batched outcomes seal in array order.
- **§8.1 numeric rule reworded** to match the `2^53-1` boundary reality (post-parse detection is sufficient because out-of-domain integers round to non-safe doubles).
- **§10.9 Key Lifecycle** added: rotation (a new `key_id` starts a fresh `signer_seq` baseline; re-registering a `key_id` with a new key is forbidden) and revocation (forward-only, `unknown-key` thereafter; sealed records stay valid evidence, adjudicated out-of-band).
- **§12 Extensibility and Registries** added: signature-algorithm identifiers, the closed Tier-1 vocabulary, and the Tier-2 vendor-prefix namespace (with ABNF), all governed by `spec_version`.
- **Conformance vectors extended:** `error-cases.json` (events a host MUST reject, each paired with its Tier-1 reason, incl. the numeric-domain boundary) and an aborted-outcome case in `events.json` pinning the abort-reason byte form.
- **`ts`/`host_ts` pinned to UTC `Z` (and MUST be re-served verbatim, not reconstructed); `key_id` non-empty; `call_id` is the string form of the JSON-RPC id; normative references added** ([RFC-8259], [RFC-9562], [RFC-5234], [RFC-1123], W3C Trace Context, [RFC-8126]).

### Retained (implementer-affirmed)

- Golden conformance vectors and RFC 8785 (JCS) canonicalization. Cross-language byte-identity was unachievable without them.

### Reference alignment (completed)

- `spec/schema/*.json`, the TypeScript and Python reference implementations, and `spec/vectors/*.json` are aligned to v0.1.1: the `signer_seq` rename, `spec_version` bump, capability field, Tier-1 vocabulary, and Ed25519 + ECDSA P-256 signing. The Level-1 golden digest is `ad146486...`; the Level-2 signed-chain digest is `d19cf80d...`. Both reference ports reproduce both byte-for-byte (TypeScript and Python test suites).

## v0.1 - initial draft

- Initial draft of the Auditable MCP extension: tool-internal self-attestation of domain operations, sealed by the host into a tamper-evident, hash-chained ledger; two conformance levels (L1 trusted, L2 Ed25519-signed); RFC 8785 canonicalization with cross-language golden vectors; TypeScript and Python reference implementations.
