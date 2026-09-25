# Changelog

All notable changes to the Auditable MCP specification are documented here. The project uses a `MAJOR.MINOR.PATCH` scheme. While the version is below `1.0.0`, minor and patch revisions may introduce breaking changes, as is conventional for `0.x` drafts.

This changelog is informative. Normative force (the RFC 2119 keywords) lives only in the specification; the summaries below merely describe it.

## v0.3 - 2026-09-25

Makes the extension real on the MCP wire, and makes it survive the wire changing. Driven by three findings: [SEP-2133] made `capabilities.extensions` the place an extension declares itself (shipping in MCP protocol version `2026-07-28`); MCP `2026-07-28` removed both the initialization handshake and server-initiated requests, the two things an in-call audit exchange had rested on; and a tool with no documented fallback would fail closed against every host that does not speak this extension - which is every ordinary MCP host.

### Breaking changes

- **`spec_version` advances `auditable-mcp/0.2` -> `auditable-mcp/0.3`.** The version string is part of the canonical event bytes, so all golden digests change; there is no on-the-wire compatibility window between draft versions. New digests: Level-1 sealed chain `b518c79e...`, Level-2 signed chain `fd6e0e2f...`.
- **The event's `call_id` is replaced by `session_id`**, a UUID the host issues for each audited `tools/call` (§4, §6.3). A JSON-RPC id is chosen by the sender, is not unique across connections, and changes on every Multi Round-Trip retry, so it could not name the call an event belongs to.
- **`signer_seq` is numbered per key within an audit session, from 0** (§7.4), instead of per key across the key's lifetime. The first-observation baseline and the partition-binding condition on gap detection are gone.
- **Signatures are base64url without padding, and the ECDSA identifier is `ES256`** (§5.1). The algorithm identifiers are the fully-specified JOSE names ([RFC-9864]): `Ed25519` was already one; `ECDSA_P256_SHA256` becomes `ES256`. The encoding is the one JWS uses, so a key held as a JWK and a signature are written alike.
- **The capability object gains a REQUIRED `countersign` field**, `"none"` or `"host"` (§5.2, `schema/audit-capability.schema.json`). A v0.2 capability object no longer validates.
- **The Attempt Response's `unavailable` variant loses `retryable`**, whose single permitted value carried no information; §7.1's idempotent retry says what a tool may do after `unavailable`.
- **The declaration moves from `capabilities.experimental["auditable-mcp"]` to `capabilities.extensions["com.timberlandchapel/auditable-mcp"]`** (§6.1).

### Added (normative)

- **§6 separates the exchange from its bindings.** The exchange - an attempt answered by an Attempt Response, an outcome answered by nothing - is defined once. **§6.4** binds it to MCP `2026-07-28`: the tool ends a round of the `tools/call` with an `InputRequiredResult` carrying its events in `_meta`, and the host answers in the `_meta` of the Multi Round-Trip retry; no new JSON-RPC method is defined, and the host's declaration travels with every request. **§6.5** binds it to the MCP versions with an initialization handshake, as `audit/attempt` (a server-to-client request) and `audit/outcome` (a notification). A change to MCP revises a binding and nothing else. New schemas: `schema/audit-request-meta.schema.json` and `schema/audit-result-meta.schema.json`.
- **§6.3 audit session.** One `tools/call` is one audit session. The host issues its `session_id`, the tool carries it in every event, the host rejects an event carrying another, and the session ends with the call. Because `session_id` is inside the signed and hashed event, an event recorded for one call cannot be recorded again as another's (§10.7).
- **Idempotent retry** (§7.1). A byte-identical repeat of a sealed attempt is answered with the original Attempt Response and seals nothing; an attempt id repeated with different bytes is a replay. A tool that received `unavailable`, or no answer, may send the identical attempt again.
- **Refusals are sealed** (§7.2, §10.4). The `aborted` outcome of an attempt the host did not accept is sealed as the record of an operation the tool declined to perform, and under Level 2 accounts for the `signer_seq` its unsealed attempt consumed; §11.4 gives verifiers one deterministic procedure for that accounting, which reports each run of unaccounted values as one gap and never enumerates them.
- **`unresolved-attempt`** (§6.3, §7.6, §10.8). The host issued the call, so it observes the call's end; an accepted attempt with no sealed terminal outcome at that point is recorded. A trailing outcome's loss, which v0.2 could not detect, now is.
- **At most once** (§6, §6.4, §10.11). A tool performs an operation at most once however many `accept`s reach it: an attempt sent again is answered again, a binding can deliver an answer late or twice, and a Multi Round-Trip `requestState` is attacker-controlled and can be replayed.
- **Polluted Stop wherever a countersignature is required** (§7.2). The countersignature binds the host-assigned fields to `record_hash`, and only Polluted Stop binds `record_hash` to the tool's own event, so a tool that requires the one performs the other at either level.
- **§6.2 Graceful degradation.** A call is *audit-negotiated* only when both parties declared the extension, the comparison succeeded, and the host issued an audit session. For any other call a tool sends no audit message and serves `tools/call` exactly as a build without this extension would. Two postures are admissible - **degraded** (serve, and record into an audit host the tool provides for itself; RECOMMENDED default) and **mandatory** (refuse to serve, as [SEP-2133] permits). Serving a call while silently recording nothing is not conformant. A degraded tool SHOULD make that state observable to its operator ([NIST-SP-800-53] AU-5).
- **§5.2 the countersignature axis, orthogonal to the conformance level.** The level says how strongly a tool's attestation resists forgery; the countersignature says who sealed it. A countersigning host signs the host-assigned fields an `accept` already returns, together with the `log_id` naming its ledger, and persists `host_signature`, `host_key_id`, and `log_id` with every sealed record, outcomes included (§7.1, §7.2). The countersignature is established per record, by evidence, never by declaration. It is deliberately not called a *witness*: in transparency-log practice a witness is independent of the log's operator, and the host is the operator ([RFC-9338] names the relationship).
- **§10.10 identity binding in shared storage.** A chain proves authorship and internal consistency, never whose chain it is, so a deployment holding records for several principals MUST bind identity - by giving each principal's partition its own `log_id` and countersigning every record, or by sealing each record inside an enclosing record that binds the principal - and a verifier MUST check the binding against an expectation supplied out-of-band.
- **Tier-1 vocabulary** (§7.6): abort reasons `host-uncountersigned` and `host-signature-invalid`; anomaly kinds `unresolved-attempt`, `host-signature-invalid`, `principal-mismatch`, and `replay-detected` (two sealed records sharing a `signer_seq`, or an outcome the host dropped as a replay). An outcome the host drops is recorded under the anomaly kind for the condition (§6).
- **Round affinity** (§6.4, §10.11). Under Streamable HTTP every request of an audited call carries `Auditable-Mcp-Session`, mirroring its `session_id` as MCP mirrors `Mcp-Name`; the body is the source of truth and a disagreeing header is `-32020 HeaderMismatch`. A retry carries the request metadata headers of the request it repeats. A tool that keeps a call's state in one of several instances delivers every retry to that instance - by an intermediary routing on the header (which intermediaries pass through), or by forwarding - or refuses it without acting. Any request of an audited call carrying a `requestState` is a retry, the tool's own rounds included, and is never served as a first request; a first request for a call already held is refused; an altered `requestState` can cause nothing worse than the request's failure.
- **One call, one comparison** (§6.1, §6.4). Under `2026-07-28` the comparison is made on the call's first request and holds for every retry of the call.
- **UUIDs are lowercase and compared as strings** (§4); a `session_id` is never the nil UUID. **The Level-2 fields appear together or not at all.** **Strings are Unicode scalar values** (§8.1), so a lone surrogate is `schema-invalid`.
- **One terminal record per operation**, correlated by `session_id` and `id` together (§7.2, §11.4).
- **Keys** (§10.9): a tool signs a whole session under one key; a revoked key keeps its registry entry so the records it signed still verify; the tool and host registries share no key.
- **Bindings** (§6, §6.4, §6.5): an answer that fails the Attempt Response schema is no answer; under §6.5 an event arrives on the related call, or on a call in flight on the same connection whose session the host issued; a round's events are processed one by one.
- **Registries** (§5.1) refuse an entry whose key and algorithm disagree when they are loaded.
- **Verifiers** (§11.4) accept an out-of-band requirement that a chain be countersigned, and report an uncountersigned record under it; match identity on `log_id` together with the countersigning `host_key_id`; report an earlier-version record sealed after a later one; report a malformed sealed record without stopping, validate a record against the schema of the version it was sealed under, and report two sealed records sharing a `signer_seq`.
- **Abort `reason` precedence** (§7.2): `status`, then the countersignature, then the hash; the first that applies wins, so two implementations seal the same `reason`.
- **§3 defines Audit session, Countersignature, Binding, and Verifier; §11.4 Verifier Conformance.**
- **§9 positions this extension against SCITT, transparency-log witnesses, sequence-numbered protocols, and JOSE.** The Verifiable Accept plays a Receipt's part without being one; a deployment MAY anchor the ledger by registering the tail record's countersignature preimage in a SCITT Transparency Service.

### Changed (normative)

- **§7.1's validation order** is structure, session, signature, uniqueness, sequence; a duplicate id is checked after its signature, so its `signer_seq` counts as received.
- **§7.1's validation order** applies to outcomes as well, and an outcome is correlated only after it passes.
- **§7.4's host tracker** keeps, per key and session, the set of `signer_seq` values it has decided (a value in it is a replay; `unavailable` adds nothing) and the highest received with a verifying signature (the gap bound). This is the anti-replay window of IPsec and DTLS ([RFC-4303], [RFC-9147]), sized to the session, so an attempt sent again after `unavailable` is processed even when later operations of the session went ahead.
- **§6.4's call end** is the host's decision, since no request is in flight between rounds: a host that does not retry a round ends the session. A call that ends in a JSON-RPC error delivers its remaining outcomes in one more round. A host bounds a round's processing by one deadline and retries when it passes, answering `unavailable` to what it has not decided; it does not hold the call's result on its own audit work, and removes this extension's member from a result before passing it to its caller. A tool keeps the answer of a call it concluded while a round was out until that round's retry arrives.
- **JSON-RPC batching is not used** (§6.5); MCP removed it in `2025-06-18`.
- **§3** no longer defines the Host as the MCP client or orchestrator alone: the degraded posture has the tool provide one for itself.
- **§8.3** does not seal a byte-identical event twice, outcomes included.
- **§12.1** draws algorithm identifiers from the IANA JOSE registry.

### Backward compatibility

- **The countersignature does not move `record_hash`.** It is computed over the host-assigned fields and stored beside them, outside the §8.2 preimage, so a chain sealed with one and the same chain sealed without one hash identically.
- The digests change because `spec_version`, `session_id`, and the signature encoding are inside the hashed event.

### Reference alignment

- `spec/schema/*.json` and `spec/vectors/*.json` are regenerated at v0.3 from the TypeScript reference's Zod source of truth.
- **`chain-signed.json` and `chain-countersigned.json` carry real signatures**, made with fixed Ed25519 seeds and verifiable against the public keys each file publishes as a JWK. `chain-countersigned.json` pins the countersignature preimage, `log_id` included, and the same `record_hash` values as `chain.json`.
- **`signer-seq-accounting.json`** pins the runs §11.4's procedure reports, **`signer-seq-replay.json`** pins §7.4's replay tracker, and **`verifier-cases.json`** pins the verifier's inputs (a required countersignature, an expected identity) and its version- and correlation-order findings.
- **References:** [SEP-3004] moves to Informative (it was closed on 2026-09-22 to proceed through an MCP Working Group). Added: [MCP-2026-07-28], [MCP-MRTR], [RFC-7515], [RFC-7518], [RFC-9864] (normative); [RFC-7493], [RFC-7517], [RFC-9338], [RFC-8446], [RFC-4303], [RFC-9147], [RFC-5848], [KIP-98], [MCP-2025-06-18], [SEP-414], [MCP-TOA], [SCITT], [RFC-9162], [C2SP], [NIST-SP-800-53] (informative).

### Reference implementations

- **Both ports are at v0.3.** They carry audit sessions (the host issues and closes them, and records `unresolved-attempt`), idempotent retry, sealed refusals, the `signer_seq` tracker, the countersignature triple with `log_id`, base64url signatures, the `ES256` identifier, and the §11.4 accounting procedure. They reproduce every committed vector byte-for-byte and verify the signatures in them. Their MCP wiring demonstrates the §6.5 binding; the §6.4 binding is demonstrated by the SDKs.

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
