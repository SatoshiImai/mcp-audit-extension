# Auditable MCP

- **Status:** Draft proposal. Experimental below 1.0: the wire contract may change between draft revisions, signalled by `spec_version` (§6.1).
- **Version:** `auditable-mcp/0.3`
- **Author:** Satoshi Imai
- **License:** MIT

> **v0.3 (draft).** See [CHANGELOG.md](../CHANGELOG.md) for the changes from v0.2 and the backward-compatibility notes.

## Abstract

Auditable MCP is a proposed extension to the Model Context Protocol (MCP). It defines a mechanism for an MCP tool server to self-attest its internal domain operations, such as database transactions and downstream API requests executed within a tool call. These operations are emitted as structured audit events, which the host subsequently records in a tamper-evident ledger.
While existing MCP auditing capabilities are limited to the orchestrator-visible call boundary, this extension addresses the unobservable interior by relying on the tool's self-attestation. This protocol is complementary to SEP-3004 (Tamper-Evident Audit Record Contract) [SEP-3004].

Two properties shape how it is adopted. A tool that speaks this extension remains usable by hosts that do not: where the extension was not negotiated, the tool sends no audit message and serves the call as an ordinary MCP tool, under one of two named postures (§6.2). A record also states who recorded it: a host that confirms sealing signs for having done so, so a verifier can tell a chain a distinct host confirmed from one a tool recorded for itself (§5.2).

## 1. Motivation

When an MCP tool executes a `tools/call`, the host can observe the call boundary, including the tool name, arguments, and result. However, the host cannot observe the tool's internal execution. While operators can directly instrument the internals of first-party tools, third-party tools remain opaque. Regulatory record-keeping frameworks, such as Article 12 of the EU AI Act [EU-AI-Act], mandate traceability and the automatic recording of events (logs) for high-risk AI systems. Observations restricted to the call boundary are insufficient to provide this level of detail.

Existing approaches terminate at the orchestrator-visible boundary:

- **SEP-3004** standardizes a tamper-evident, hash-chained audit record contract that is strictly scoped to the call boundary [SEP-3004].
- **OpenTelemetry** GenAI semantic conventions trace call attributes (arguments, results, latency) but rely on separate instrumentation for domain operations executed within a tool [OTel-GenAI].
- **Gateways**, by architectural design, log only the network traffic that crosses them.

Auditable MCP addresses this gap with a tool-to-host self-attestation mechanism for internal, domain-semantic operations, which the host anchors into a tamper-evident ledger (§4-§8).

## 2. Scope and non-goals

The objective of this specification is to provide a mechanism for accountability (detective control) rather than authorization (preventive control).

**In Scope:**

- Defining a protocol for an MCP tool to voluntarily report its internal domain operations.
- Establishing the host's mechanism to anchor these reported events into a tamper-evident ledger.
- Enforcing ledger integrity by strictly refusing to record events that fail cryptographic or structural verification.
- Defining what a tool does when the extension was not negotiated, so that speaking it does not make the tool unusable with ordinary MCP hosts (§6.2).
- Distinguishing a record a distinct host confirmed sealing from one whose only backing is the tool's own attestation (§5.2).

**Out of Scope:**

- Defining real-time access control policies or authorization gateways for domain actions.
- Evaluating or guaranteeing the inherent trustworthiness of a tool. (Dangerous or unauthorized tools are assumed to be excluded out-of-band via the orchestrator's allowlist.)

Architecturally, the host acts as a "monitoring camera" over tools that have already been vetted by the orchestrator - except in the degraded posture (§6.2), where the tool provides the camera for itself and §10.2 bounds what the resulting chain establishes. Via this extension protocol, the host is not expected to evaluate or authorize the semantic execution of a tool's internal actions. Therefore, within this document, when the host "rejects" or "blocks" a record, this exclusively refers to refusing the ingestion of an invalid audit record - ensuring a fail-closed posture for ledger integrity - and never implies the real-time interception or prevention of the domain action itself.

## 3. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC-2119] [RFC-8174] when, and only when, they appear in all capitals, as shown here.

- **Tool** - A specific capability exposed by an MCP Server, whose internal operations are subject to audit via this specification.
- **Host** - The party that receives audit events and anchors them into the ledger. Ordinarily the MCP client or orchestrator; in the degraded posture (§6.2) the tool provides one for itself, which is what the witness axis (§5.2) distinguishes.
- **Verifier** - A party that reads a sealed ledger, recomputes its chain, and reports anomalies (§7.6, §11.4). It need not have taken part in the exchange that produced the records, and may be the host, the tool, or an independent auditor.
- **Event** - One audit record describing one internal operation (§4).
- **Ledger** - The host's append-only, hash-chained, tamper-evident store of attested events.
- **Boundary** - The standard `tools/call` interface which the host can directly observe.
- **Governance boundary** - The logical data-governance boundary defined in §4.2: the perimeter of the organization's own data governance, not a physical network boundary. Distinct from the observable call **Boundary** above.
- **Self-attestation** - A tool's voluntary reporting of its internal domain actions to the host (cryptographically verifiable under Level 2).
- **Witness signature** - A host's signature over the host-assigned fields of a record it sealed, made with a key an out-of-band registry binds to that host (§5.2, §7.1). Distinct from a tool's Level-2 event `signature`, which covers the event the tool emitted.
- **Domain Action** - An execution step performed internally by a tool (e.g., executing a SQL query, invoking an external API) that is opaque to the host at the boundary.
- **Partition** - A logical isolation boundary defined by the host (e.g., per tenant or session) within which the ledger's hash chain, `seq`, `signer_seq` tracking, and anomaly set are scoped (§10.5). It is a host-side ledger concern; the tool is unaware of it.

## 4. The audit event

An event is a JSON object [RFC-8259]. Its normative schema is
[`schema/audit-event.schema.json`](schema/audit-event.schema.json).

| Field                 | Type              | Presence | Notes                                                                                                                                                                                                                                                                                            |
| --------------------- | ----------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`                  | UUID              | REQUIRED | Tool-generated UUID [RFC-9562] (SHOULD be version 4 or 7; the nil UUID SHOULD NOT be used). Correlation key for one operation: the `attempt` and its terminal `outcome` share it. De-duplication key for attempts (§7.1).                                                                        |
| `spec_version`        | string            | REQUIRED | MUST be `auditable-mcp/0.3`.                                                                                                                                                                                                                                                                     |
| `ts`                  | ISO-8601 datetime | REQUIRED | Tool-observed time (advisory; host time is authoritative). MUST be UTC with a `Z` suffix, no numeric offset (per the schema pattern).                                                                                                                                                            |
| `call_id`             | string            | REQUIRED | The parent `tools/call` JSON-RPC request id, as a string. A numeric id MUST be encoded as its decimal string form (e.g. `42` -> `"42"`), since `call_id` is hashed into the event and must not diverge across ports.                                                                             |
| `traceparent`         | string            | OPTIONAL | W3C Trace Context [W3C-Trace-Context] `traceparent` header value.                                                                                                                                                                                                                                |
| `action_type`         | string            | REQUIRED | §4.1.                                                                                                                                                                                                                                                                                            |
| `mutates`             | boolean           | REQUIRED | Whether the operation changes state. §4.2.                                                                                                                                                                                                                                                       |
| `egress`              | boolean           | REQUIRED | Whether the operation crosses the logical data-governance boundary. §4.2.                                                                                                                                                                                                                        |
| `target_resource`     | object            | REQUIRED | The operation's domain target (sub-fields below).                                                                                                                                                                                                                                                |
| `outcome`             | enum              | REQUIRED | `attempted` &#124; `success` &#124; `failed` &#124; `aborted` (§7.2).                                                                                                                                                                                                                            |
| `reason`              | string            | OPTIONAL | REQUIRED on an `aborted` outcome (enforced by schema): a Tier-1 abort code `hash-mismatch` &#124; `host-rejected` &#124; `host-unavailable` &#124; `host-unwitnessed` &#124; `host-signature-invalid` (§7.2, §7.6). SHOULD be omitted on other outcomes; domain detail goes in `action_context`. |
| `action_context`      | object            | OPTIONAL | Cleartext metadata about the internal operation, redacted at the tool's discretion (§4.3).                                                                                                                                                                                                       |
| `action_context_hash` | string            | OPTIONAL | `sha256:<hex>` commitment to the exact internal context (§4.3).                                                                                                                                                                                                                                  |
| `signer_seq`          | integer           | OPTIONAL | Level 2. Per-`key_id` monotonic signer counter (distinct from the host-assigned ledger `seq`, §7.1).                                                                                                                                                                                             |
| `key_id`              | string            | OPTIONAL | Level 2. Identifies the signing key; binds the signature algorithm via the registry (§5.1).                                                                                                                                                                                                      |
| `signature`           | string            | OPTIONAL | Level 2. Detached signature, standard base64 (§5.1, §8.2).                                                                                                                                                                                                                                       |

The `target_resource` object identifies the domain target of the operation:

| Field        | Type   | Presence | Notes                                                                                                                   |
| ------------ | ------ | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| `kind`       | string | REQUIRED | The class of resource - an open vocabulary, opaque to this specification (e.g., `table`, `file`, `endpoint`, `secret`). |
| `ref`        | string | REQUIRED | The specific resource reference (e.g., a table name, file path, or URL).                                                |
| `scope_hint` | string | OPTIONAL | Finer-grained domain scope within the resource (e.g., `row:consent_basis=marketing`).                                   |

The `signer_seq`, `key_id`, and `signature` fields are OPTIONAL in the schema, so a single schema covers both levels; see §5 for the resulting validity direction.

### 4.1. Action Type

The `action_type` field MUST be a non-empty string.

This specification treats `action_type` as an opaque identifier. It makes no attempt to define, constrain, or validate the vocabulary, syntax, or semantics of this field. The specific values used are entirely delegated to the tool's internal domain and the broader MCP ecosystem.

### 4.2. Operational Effects (`mutates` and `egress`)

While `action_type` is an opaque label, the state-changing and data-movement impact of an operation is carried by two booleans: `mutates` and `egress`.

- **`mutates` (boolean):** Indicates whether the operation is intended to modify the state of the target resource. A value of `true` denotes a state-altering action (e.g., database INSERT, file write, API POST); `false` denotes a read-only operation.
- **`egress` (boolean):** Indicates whether the operation transmits data across the **governance boundary** to reach the target resource. That boundary is defined by organizational data governance, *not* by physical network topology (a LAN or VPC): systems and SaaS platforms operated under the tenant's own governance (for example, a corporate Google Workspace or Salesforce instance) are strictly _inside_ it, even when reached over an external HTTP request. A tool MUST set `egress` from the data-loss-prevention (DLP) risk of exfiltrating tenant context outside the organization's governance scope, not from the mere presence of network transmission.
  - `egress` is `true` when tenant context leaves that governance scope - for example, transmitting context to a public search engine, or sending data to a public or unmanaged third-party API.
  - `egress` is `false` when the operation stays within that scope - for example, reading resources from a tenant-managed SaaS platform (even via an external HTTP request), or querying an internal or tenant-controlled remote database.

In a zero-trust or cloud-native deployment nearly every operation crosses a physical network boundary, so a network-topology definition would make `egress` almost always `true` and remove its value as a DLP signal.

These fields are orthogonal to standard MCP tool annotations (such as `readOnlyHint`). While standard annotations provide static, tool-level hints during initialization, `mutates` and `egress` provide a dynamic, per-operation attestation of what actually occurred at runtime. For example, a conceptually "read-only" tool may still emit an event where `mutates` is `false` but `egress` is `true`, accurately reflecting that data crossed the governance boundary to perform the read.

### 4.3. Audit context and data minimization

Ledger integrity and context confidentiality are distinct concerns. The host enforces ledger integrity via the hash chain (§8), independently of any context field. Confidentiality is the responsibility of the emitting tool. A tool attests its internal execution context, which is distinct from the `tools/call` parameters already known to the host. The host records the provided event as-is and does not inspect context for policy.

A tool describes an operation through either, both, or neither of two independent, optional fields:

- `action_context` (OPTIONAL): cleartext metadata about the internal operation, such as the database tables an internally generated query touched. The tool SHOULD redact or omit any field whose disclosure is not warranted before emission.
- `action_context_hash` (OPTIONAL): the `sha256:<hex>` digest of the canonical form (§8) of the exact internal context (the `sha256:` prefix names the hash algorithm; only SHA-256 is defined in this version). It seals a commitment to what the tool did without disclosing it. The commitment is opened later, becoming verifiable when the exact context is revealed (whether disclosed by the tool itself or reconstructed from independent records such as egress or downstream logs).

These fields do not need to correspond. A host MUST NOT require `action_context_hash` to match the hash of the possibly-redacted `action_context`. A tool SHOULD provide at least one of them if the internal context carries audit value.

Irrespective of a tool's disclosure policy, credentials, secret values, and raw authentication tokens MUST NOT appear in any field of an event. Personally identifiable information (PII) SHOULD be redacted or omitted in accordance with the operator's policy. The ledger is append-only; tools SHOULD use `action_context_hash` for sensitive context to prevent irreversible plaintext disclosure.

## 5. Conformance levels and the witness axis

Auditable MCP defines two conformance levels to provide a progression from basic self-reporting to cryptographically verifiable auditing. Level 2 adds cryptographic signatures to prevent forgery and a monotonic `signer_seq` to detect event loss. A `signer_seq` gap may indicate that an emitted event failed to reach the host (§7.4, §10.5).

Both levels share one event schema; the Level-2 fields (`signature`, `key_id`, `signer_seq`) are OPTIONAL. The validity relationship is directional: every Level-2 event is also a valid Level-1 event (a safe downgrade - an event carrying a signature is still accepted where none is required), whereas an unsigned Level-1 event does not satisfy a Level-2 host, which rejects it (§7.4).

| Feature               | Level 1                                                                        | Level 2                                                                                                 |
| :-------------------- | :----------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------ |
| **Tamper Resistance** | None                                                                           | Cryptographic signature and sequencing                                                                  |
| **Tool Obligation**   | Emits the core event.                                                          | Adds `signature`, `key_id`, and monotonic `signer_seq`; MUST perform Polluted Stop verification (§7.2). |
| **Host Obligation**   | Records the event after schema and uniqueness validation (no signature check). | MUST verify signatures, reject invalid ones, and detect `signer_seq` gaps.                              |

Level 2 provides evidentiary strength to the audit record (non-repudiation and detection of lost events); it does not imply authorization of the domain action.

The level is one of two independent axes. It states how strongly a tool's attestation resists forgery, and says nothing about who recorded it; §5.2 carries that second question. On each axis the party that performs the obligation declares what it does, and the other declares what it needs.

### 5.1 Signature algorithms and key binding

A Level-2 `signature` is a detached signature over the canonical event (§8.2), produced by an algorithm bound to the `key_id` by the out-of-band key registry (§7.4), not carried in the event. This version defines two algorithms, each producing a fixed-length raw signature:

- **`Ed25519`** - PureEdDSA over Curve25519 [RFC-8032] (not Ed25519ph/ctx), encoded as the raw 64-byte signature.
- **`ECDSA_P256_SHA256`** - ECDSA over NIST P-256 with SHA-256 [FIPS-186-5], encoded as the fixed-length IEEE P1363 `r || s` form (*not* ASN.1/DER): `r` and `s` are each the 32-byte big-endian, left-zero-padded unsigned integer, concatenated to 64 bytes. A verifier MUST accept both low-S and high-S signatures (no low-S normalization is required, since signatures are verified, not reproduced).

The `signature` field MUST be the standard base64 encoding (with padding, [RFC-4648] §4) of these raw signature bytes; implementations MUST NOT use base64url on the wire, so that a foreign verifier decodes the field unambiguously. The normative schema pins the field to `^[A-Za-z0-9+/]+={0,2}$`. A `signature` that is undecodable base64, or that decodes to the wrong length for the bound algorithm, is treated as a failed verification and rejected as `signature-invalid` (§7.6), not `schema-invalid`. The schema sets no maximum length on `signature` (or other string fields); bounding message size against oversized-input resource exhaustion is a transport/SDK responsibility (§7.3), not a canonicalization concern.

**Key registry.** The registry is provisioned out-of-band at onboarding and is deployment-specific, but its entries have a normative shape: each maps a non-empty `key_id` to exactly one algorithm identifier from the set above and one public key, and that public key MUST be a key of that algorithm. An entry whose key and algorithm disagree is not a conforming entry and MUST be refused where it is provisioned, not carried to verification time: every event bound to it then fails to verify and is rejected `signature-invalid` (§7.6), which names a forged signature - a different fact from a misprovisioned registry, and one that sends an operator looking for the wrong thing. Because the event carries no algorithm field, a host selects the verifier from the `key_id`'s registry entry, which lets one host verify a heterogeneous fleet - Ed25519 tools alongside KMS-hosted ECDSA P-256 tools - without an in-band algorithm negotiation. A `key_id` with no registry entry is rejected as `unknown-key` (§7.6). New algorithm identifiers are added only by a future version of this specification (§12). Key rotation and revocation are covered in §10.9.

### 5.2 Witness

A Level-2 chain that carries no witness signature is strongly signed and independently unconfirmed; a Level-1 chain that carries one is weakly signed and independently confirmed. These are different properties, so this specification keeps them on separate axes rather than folding one into the other.

The **witness** axis states what a record carries, not who the parties were:

| Witness signature      | What the record establishes                                                                                                                                                                                                                              |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| absent                 | Only the tool's own attestation stands behind the record (§10.2). Whether a separate host sealed it and declined to sign, or the tool acted as its own host (§6.2), is not determinable from the record - and the record establishes no more either way. |
| present, and verifying | The host named by `host_key_id` confirmed sealing this record with a **witness signature** over it, made with a key the verifier's registry binds to that host (§7.1).                                                                                   |

The capability values `none` and `host` (§6.1) declare which of these a participant provides or requires. They are declarations of policy; the record's own state is the row above, and a verifier reads it from the record alone (§11.4).

**A witness is established per record, by evidence, never by declaration.** A record is host-witnessed when it carries a `host_signature` that verifies against the `host_key_id`'s registry entry, and is unwitnessed otherwise. A tool cannot manufacture the host-witnessed state, because it holds no key the verifier's registry binds to a host. This holds as long as the tool does not control the verifier's registry. Where one operator controls both, the distinction is administrative rather than cryptographic and §10.2 applies to the whole chain; separating registry control from tool operation is the deployment condition under which the witness axis is evidence.

A participant declares its position on this axis in the capability object (§6.1): a host declares `host` when it signs, and a tool declares `host` when it requires a signature. The declaration tells each side what to expect; it is not evidence. A tool that requires a witness enforces the requirement at runtime (§7.2), exactly as a host enforces the level at runtime (§7.1).

The witness axis does not alter the record hash. The witness signature is computed over the sealed record's host-assigned fields and stored alongside them (§7.1), outside the §8.2 preimage, so a chain sealed without a witness and the same chain sealed with one produce identical `record_hash` values, and a chain sealed before this axis existed is unaffected by it.

## 6. Protocol

Auditable MCP requires tool-to-host communication while a `tools/call` is being processed. It adopts the established MCP elicitation pattern for this exchange. However, the audit exchange itself is deterministic and does not employ human-in-the-loop semantics: the host's audit subsystem processes requests automatically, and execution is not suspended awaiting human input. (Human-in-the-loop consent MAY occur at capability negotiation (§6.1), never within the per-event audit exchange.)

**Scope of these obligations.** This section defines the exchange for an *audit-negotiated* session - one in which both parties declared this extension at `initialize` and the capability comparison succeeded (§6.1). In an unnegotiated session the tool sends no audit message at all and serves the call as an ordinary MCP tool; §6.2 is normative for that case. In particular, the fail-closed rules below MUST NOT be triggered by a peer that never declared the extension.

The protocol defines two messages:

- **`audit/attempt`:** A tool-to-host JSON-RPC request sent immediately before an internal operation, carrying an event with the `outcome` set to `attempted`. This is strictly an audit recording request, not an authorization request. The tool MUST await the response and MUST NOT perform the operation unless the response is `accept`. Bounding this wait (e.g., a transport-level timeout that fails closed) is a transport/SDK responsibility. The host rejects an attempt only when ledger integrity cannot be guaranteed (e.g., invalid signatures or sequence violations). If the host suffers a persistence failure, it replies with an `unavailable` status.
- **`audit/outcome`:** A tool-to-host JSON-RPC notification reporting how the operation resolved, carrying an event with the `outcome` set to `success`, `failed`, or `aborted`. Tools MAY bundle multiple such notifications into a single transmission using a standard JSON-RPC 2.0 Batch array; no Auditable-MCP-specific array payload is defined.

**Message binding.** In both messages the JSON-RPC `params` member IS the audit event object (§4) directly - not a wrapper object. The method names are the literal strings `audit/attempt` and `audit/outcome`. The `audit/attempt` result is the Attempt Response object (§7.1); `audit/outcome`, being a notification, has no result.

**Result vs JSON-RPC error.** Every audit-layer decision - accept, reject, or unavailable - MUST be returned as a JSON-RPC `result` carrying the Attempt Response (§7.1), never as a JSON-RPC `error`. A rejected or unavailable attempt is a normal, well-formed audit outcome the tool branches on (§7.2), not a protocol fault. JSON-RPC `error` responses are reserved for transport- and protocol-level faults (unparseable message, unknown method, malformed envelope); a tool receiving a JSON-RPC `error` for an `audit/attempt` MUST treat it as a failure to record and fail closed, exactly as for `unavailable`.

**Batching.** An `audit/attempt` MUST NOT appear in a JSON-RPC Batch array: it is a blocking request whose `accept` must be awaited before the tool acts (a batched request's response would arrive only with the whole batch, defeating audit-before-act). Only `audit/outcome` notifications MAY be batched; within a batch the host seals them in array order (§8.3).

**Invalid outcome notifications.** Because `audit/outcome` is a notification, it has no response channel: the host cannot `reject` it. A host that receives an outcome failing structural, numeric-domain, signature, or sequence validation (§7.1, §7.4) MUST NOT seal it, and MUST record the failure in its anomaly set (§7.6); from the tool's perspective it is silently dropped. Only an outcome carrying a terminal `outcome` (`success`, `failed`, `aborted`) and correlating to an accepted attempt is sealed (§8.3); an `attempted` outcome on the `audit/outcome` channel is treated as invalid and dropped.

Because `audit/outcome` may be the final event of a tool call, its loss cannot reliably be detected via sequence gaps. Tracking incomplete operation lifecycles (e.g., applying an `expired` state due to execution timeouts) and managing tool process termination upon a rejected attempt are SDK implementation responsibilities.

Consequently, states such as `denied` (Boundary-level allowlist rejection) and `expired` (abandoned or timed-out execution) are host-side lifecycle concepts. A tool-internal event never carries these states.

### 6.1 Capability negotiation

Auditable MCP is an MCP extension in the sense of [SEP-2133], and it integrates with the standard MCP `initialize` phase where the host and the tool exchange capabilities bidirectionally. Each party declares this extension under the `extensions` member of its capabilities - `ClientCapabilities` for the host, `ServerCapabilities` for the tool - keyed by the extension identifier:

```
com.timberlandchapel/auditable-mcp
```

The value at that key is the capability object, serving as this extension's [SEP-2133] settings object. The host declares the audit capability it requires; the tool declares the audit capability it supports. Both use the [`schema/audit-capability.schema.json`](schema/audit-capability.schema.json) object. (The reference implementations exercise the negotiation logic and the per-event wire, not this `initialize` handshake, which is a thin MCP-transport binding; see the reference READMEs.)

**Identifier and version.** The identifier names the extension; `spec_version` names the wire version. [SEP-2133] requires a breaking change to take a new identifier, and defines one as a modification that would cause existing compliant implementations to fail or behave incorrectly. A `spec_version` change does not meet that definition here: the field is REQUIRED in the settings object and is compared during negotiation, so an implementation built against an older revision neither fails nor behaves incorrectly - it declines to negotiate, visibly, before any audit message is exchanged (§6.2). This extension also advertises itself as experimental below 1.0, as [SEP-2133] contemplates an extension doing: its wire contract may change between draft revisions, and `spec_version` is how a peer detects that. A modification that could instead leave an older implementation running incorrectly would take a new identifier.

The host enforces its own required `level` at runtime (§7) regardless of what the tool offers: when the host requires Level 1 and the tool offers Level 2, the host still validates only at Level 1 (it does not demand signatures); when the host requires Level 2, the host validates every event at Level 2. The offered level only decides whether the connection is admitted (below).

**The witness axis runs the other way.** On the `level` axis the tool produces and the host requires; on the `witness` axis (§5.2) the host produces and the tool requires. A host declaring `host` offers to sign; a tool declaring `host` requires that it be signed. A host declaring `none` therefore cannot satisfy a tool that requires `host`, and that is knowable at `initialize` rather than one call at a time: the comparison fails, exactly as a level shortfall does. A tool declaring `none` imposes no requirement, and a host declaring `host` signs whatever the tool asked for. The tool performs this comparison, because it holds the requirement, just as the host performs the `level` comparison for the same reason: each party enforces the axis on which it is the one requiring.

The capability object declares the operational parameters of the audit subsystem. `spec_version`, `level`, `attempt`, and `witness` are all REQUIRED.

| Field          | Type   | Presence | Notes                                                                                                                                                                                                                                                                                                                   |
| -------------- | ------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec_version` | string | REQUIRED | The Auditable MCP version the participant supports (e.g., `auditable-mcp/0.3`). Enables a cross-version handshake, since events carry `spec_version` (§4) but negotiation must establish a common version first.                                                                                                        |
| `level`        | string | REQUIRED | MUST be `"L1"` or `"L2"`. The negotiated assurance level.                                                                                                                                                                                                                                                               |
| `attempt`      | string | REQUIRED | MUST be `"request"`. `audit/attempt` is a blocking, fail-closed request. A single permitted value in this version; it is a forward-compatibility placeholder reserving the field for a future non-blocking mode.                                                                                                        |
| `witness`      | string | REQUIRED | MUST be `"none"` or `"host"` (§5.2). `"host"` means records in this session carry a witness signature - a host declaring it will sign, a tool declaring it requires one. `"none"` means they do not. Unlike `level`, the obligation on this axis falls on the host, so the roles of requirement and offer are reversed. |

When either participant's declared `spec_version` is not mutually supported, or a tool's declared `level` does not meet the host's requirement (e.g., the host requires Level 2 but the tool supports only Level 1), or the host's declared `witness` does not meet the tool's requirement, resolving the mismatch is an orchestrator or SDK implementation responsibility. The orchestrator MAY terminate the connection, or it MAY seek human-in-the-loop consent to admit the tool at a lower assurance level and record that decision in its allowlist. Whatever the orchestrator decides, the session is unnegotiated until a comparison succeeds, so §6.2 governs the tool: it sends no audit message in the meantime. A decision to admit a tool at a lower assurance level takes effect by the parties declaring capabilities that fit and comparing again, never by an out-of-band override of a comparison that failed - *negotiated* always means a comparison succeeded, which is what keeps the tool's rule mechanical.

A tool might falsely declare a higher capability than it possesses. The protocol does not verify a declaration's truthfulness during negotiation. Instead, the host enforces its required level at runtime (§7). If a tool fails to emit events compliant with the enforced level - for example, omitting a signature under Level 2 - the host's runtime validation rejects those events. Consequently, ledger integrity holds irrespective of the initial declaration.

### 6.2 Graceful degradation

Where one party supports an extension and the other does not, [SEP-2133] requires (MUST) that the supporting party either revert to core protocol behavior or, for a mandatory extension, reject the request, and recommends (SHOULD) that the extension document its expected fallback behavior. This section is that document.

A session is **audit-negotiated** when both parties declared the extension identifier (§6.1) at `initialize` and the resulting capability comparison succeeded. Every other session is **unnegotiated**: the peer declared no `extensions` member, or declared other extensions but not this one, or declared it with a `spec_version`, `level`, or `witness` that does not fit (§6.1).

**In an unnegotiated session a tool MUST NOT send `audit/attempt` or `audit/outcome`.** A host that did not declare this extension has not agreed to receive them, and an ordinary MCP host answers an undeclared method with a JSON-RPC `error` (method not found), which §6 requires the tool to read as a failure to record. A tool that sends regardless therefore fails closed against a peer that has done nothing wrong, and is unusable with ordinary MCP hosts. The obligation rests on the tool because only the tool knows whether the exchange was negotiated.

**A tool MUST serve an unnegotiated session as an ordinary MCP tool.** Its `tools/list` and `tools/call` behavior, and the content of its results, MUST NOT differ from a build without this extension. Auditable MCP adds to what a tool reports about itself; it never changes what the tool does.

**Postures.** How a tool spends an audit obligation it can no longer discharge against the host is an operator configuration, established out-of-band and not negotiated on the wire. Two postures are admissible, and the degraded posture is RECOMMENDED as the default:

| Posture       | On an unnegotiated session                                                                                                 | When to choose it                                                                                                                                 |
| ------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Degraded**  | Serve the call, and record the internal operations into an audit host the tool provides for itself, applying §7 unchanged. | The tool stays usable by every MCP host, and its interior is still recorded.                                                                      |
| **Mandatory** | Refuse to serve, as [SEP-2133] permits for a mandatory extension.                                                          | Deployments where a record the host never saw has no value - for example where the operator's obligation is discharged only by the host's ledger. |

**A tool in the degraded posture SHOULD make that state observable to its operator** - through a log record, a metric, a startup banner, or whatever channel the deployment already watches - so that the absence of a host's witness is noticed rather than merely discoverable after the fact. Alerting personnel, and deciding what else to do about an audit failure, is an organizational control rather than a protocol behavior ([NIST-SP-800-53] AU-5); this specification requires only that a tool not conceal the state from the operator who owns that control.

AU-5(4) invokes a full shutdown, a partial shutdown, or a degraded operational mode on an audit logging failure, *unless an alternate audit logging capability exists*. The two postures here sit on opposite sides of that rule: the degraded posture is the alternate capability, and the mandatory posture is the invoked response. The word *degraded* is this specification's own and denotes continuing to serve; AU-5's "degraded operational mode" denotes reduced functionality, which is the opposite side of the same rule.

**A tool MUST NOT take a third posture, in which it serves a call in an unnegotiated session, records nothing, and reports nothing about the omission.** That combination restores the opaque interior of §1 while the tool continues to advertise this extension to hosts that ask.

**A self-hosted chain carries no independent confirmation.** A tool acting as its own host issues and records the same chain, so no record in it is confirmed by a second party; §10.2 governs what such a chain does and does not establish. A verifier tells such a chain from one a distinct host confirmed by the witness signature alone (§5.2, §11.4).

## 7. Host behavior and tool obligations

The host's audit subsystem is a deterministic recording engine. It does not authorize domain actions; it strictly validates ledger integrity requirements (§5) before sealing records.

### 7.1 Attempt processing

Upon receiving an `audit/attempt` event, the host MUST perform the following validations before sealing:

1.  **Structural Validity:** The event MUST conform to the shared schema, `outcome` MUST be `attempted`, and every numeric value MUST lie in the canonicalization domain (§8.1). An event failing any of these is rejected, not sealed.
2.  **Cryptographic Integrity (Level 2):** If the negotiated capability is Level 2, the host MUST verify the `signature` against the registered public key for the `key_id`.
3.  **Sequence Verification (Level 2):** The host MUST ensure the `signer_seq` is strictly greater than the last accepted `signer_seq` for that `key_id`, subject to the baseline and partition scoping of §7.4. (A gap may indicate a suppressed event and is flagged as an anomaly, but the event is accepted if the signature is valid.)
4.  **Uniqueness (both levels):** The host MUST reject an `audit/attempt` whose `id` duplicates an already-accepted attempt (a replay), and MUST NOT seal a second attempt record for that `id`. The terminal `audit/outcome` reuses its attempt's `id` as the correlation key (§4) and is not subject to this attempt-uniqueness check.

If validation passes, the host seals the record into the ledger (§8) and replies with `status: "accept"` and the host-assigned `seq`, `host_ts`, `previous_hash`, and `record_hash` (see Verifiable Accept below).
If validation fails, or if the host suffers a persistence failure, it replies with `status: "reject"` or `status: "unavailable"`, respectively.

**Atomic sealing.** A host MUST assign `seq` and `previous_hash`, seal the record, and commit it to the partition's chain atomically with respect to every other record being sealed into the same partition (§10.5). Two seals that interleave read the same chain tail, and the host issues two records claiming the same predecessor and the same `seq` - a broken chain it has already answered `accept` for twice, so the operations it cleared proceed on records the ledger cannot hold. The obligation falls on the host because no other party can detect the condition: each `accept` is individually well-formed and passes Polluted Stop (§7.2), and the break surfaces only later, to a verifier reading the chain (§11.4). Stated as the ledger shows it: no two records in one partition may carry the same `seq`, and none may carry the same `previous_hash` as another.

This constrains the property, not the mechanism. A host MAY serialize seals with a per-partition lock, elect a single writer per partition, or commit under an isolation level that aborts and retries a seal that interfered with another. A host that cannot complete a seal atomically has not recorded the event and MUST reply `unavailable` rather than seal it anyway; failing to record is a state this protocol already carries (§7.2), and a chain break is not. Nothing here constrains ordering *across* partitions, nor which of several concurrent attempts takes the earlier position - only that they take different ones, linked in the order they took them. Where an order is already pinned, it still holds: the notifications in an `audit/outcome` batch are sealed in array order (§8.3).

Nothing here constrains the tool's concurrency. §6 makes an `audit/attempt` blocking for the operation that sent it; a tool MAY have several operations in flight, and a host that seals atomically serves them all. Their records are ordered; their operations are not. Under Level 2 the tool carries an obligation of the same shape at its own end - §7.4 requires it to number and emit atomically per `key_id` - so concurrent operations sharing one key leave in one order.

A log that answers a submission with a promise rather than a position can defer this. [RFC-9162] returns a Signed Certificate Timestamp and allocates the tree index later, within its Maximum Merge Delay, and [SCITT] states the append-only property of the verifiable data structure without constraining how concurrent registrations reach it. Auditable MCP cannot defer it: the Verifiable Accept hands the tool its position at the moment of the reply, because the tool reconstructs the preimage from `seq` and `previous_hash` to perform Polluted Stop (§7.2) *before* it acts. A protocol that returns the position owes the guarantee that the position is the record's own.

**Verifiable Accept:** On an `accept` response, the host MUST return the full set of host-assigned fields required for the tool to reconstruct the hash preimage (§8.2): `seq`, `host_ts`, `previous_hash`, and the resulting `record_hash`. Without these, the tool cannot perform the mandatory Polluted Stop verification (§7.2).

**Witness signature (witness `host`).** A host that declares `witness: "host"` (§5.2) MUST additionally return `host_signature`, a detached signature over the RFC 8785 canonical form (§8.1) of the accept's host-assigned fields

```json
{
  "host_ts": "<ISO-8601 string assigned by host>",
  "previous_hash": "<hex-encoded string>",
  "record_hash": "<hex-encoded string>",
  "seq": <integer>
}
```

together with the `host_key_id` identifying the signing key. The algorithm is bound to `host_key_id` by a registry of the same normative shape as §5.1's, provisioned out-of-band; the same algorithm identifiers and the same standard-base64 encoding apply. This signature preimage carries no signature field, so there is no self-reference, and it is not part of the §8.2 record-hash preimage: a record sealed with a witness signature and the same record sealed without one have the same `record_hash`.

A host that declares `witness: "none"` MUST NOT return `host_signature` or `host_key_id`. The response schema cannot enforce this, because the response does not carry the negotiated capability; it is a host obligation (§11.2). A host that signs MUST persist `host_signature` and `host_key_id` alongside the sealed record, so a verifier reading the ledger later establishes the witness (§5.2) without the live exchange.

**Attempt Response.** The host's reply to the `audit/attempt` JSON-RPC request is a JSON object forming a tagged union discriminated on `status`. Its normative schema is [`schema/audit-attempt-response.schema.json`](schema/audit-attempt-response.schema.json).

| Field            | Type    | Notes                                                                                                                                                                                                      |
| ---------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `status`         | string  | `"accept"`, `"reject"`, or `"unavailable"`. The discriminator.                                                                                                                                             |
| `seq`            | integer | REQUIRED when `status` is `"accept"`. Partition-monotonic ledger index assigned by the host (distinct from the tool's `signer_seq`, §4).                                                                   |
| `record_hash`    | string  | REQUIRED when `status` is `"accept"`. Hex-encoded SHA-256 of the sealed record (§8.2).                                                                                                                     |
| `host_ts`        | string  | REQUIRED when `status` is `"accept"`. Authoritative host timestamp, ISO-8601 UTC with a `Z` suffix (no offset); it is part of the §8.2 preimage, so its exact string is hashed.                            |
| `previous_hash`  | string  | REQUIRED when `status` is `"accept"`. The preceding record's `record_hash` (64-zero genesis for the first record).                                                                                         |
| `reason`         | string  | REQUIRED when `status` is `"reject"` or `"unavailable"`. Machine-readable cause.                                                                                                                           |
| `host_signature` | string  | REQUIRED when `status` is `"accept"` and the host declares `witness: "host"` (§5.2); otherwise absent. Detached witness signature, standard base64.                                                        |
| `host_key_id`    | string  | REQUIRED whenever `host_signature` is present, and MUST be absent when it is not - the two fields appear together or not at all. Identifies the host signing key and binds its algorithm via the registry. |
| `retryable`      | boolean | REQUIRED when `status` is `"unavailable"`; MUST be `true`.                                                                                                                                                 |

A conformant host MUST NOT return fields outside those permitted for the resolved `status`; the accept, reject, and unavailable variants are mutually exclusive.

### 7.2 Tool verification and the `aborted` state

The `audit/outcome` event records the terminal state of the tool's execution lifecycle. The protocol defines four core states for `outcome`:

- `attempted` - the pre-action record emitted by `audit/attempt` (§6).
- `success` - the internal action was performed and completed successfully.
- `failed` - the internal action was performed but did not complete successfully.
- `aborted` - the internal action was not performed (fail-closed; e.g., the attempt was not accepted, or Polluted Stop detected tampering).

An `audit/outcome` that correlates to an accepted attempt (by shared `id`) is sealed as a record in the same partition chain (§8.3), subject to the same Level-2 signature and sequence validation as an attempt (§7.4). An `aborted` outcome for a never-accepted or rejected attempt is not sealed into the chain and is not a tampering anomaly (§10.4); the host MUST flag a `success` or `failed` outcome that references no accepted attempt as an anomaly.

**A witnessing host signs sealed outcome records too.** A host that declares `witness: "host"` MUST compute a witness signature over every sealed outcome record's host-assigned fields, exactly as for an attempt (§7.1), and persist it with the record. `audit/outcome` is a notification and has no response channel, so this signature is never returned to the tool; it is written into the ledger, where a verifier reads it (§11.4). Without it every terminal outcome in a witnessed chain would be unwitnessed, placing the conclusion of every operation outside what the host confirmed (§5.2).

An `aborted` outcome MUST carry a `reason`, and it MUST be one of the Tier-1 abort codes `hash-mismatch`, `host-rejected`, or `host-unavailable` for the corresponding condition (§7.6); the event schema pins `reason` to this closed set. Because the outcome event is sealed into the ledger, its `reason` is part of the interoperable, hashed contract and admits no free-form value. Domain-specific failure detail (for a `failed` outcome, or additional context for an `aborted` one) belongs in `action_context`/`action_context_hash` (§4.3), not in `reason`.

To guarantee that the host recorded the exact event the tool emitted, the tool MAY (and under Level 2 MUST) recompute the record hash (§8) using the host-assigned `seq`, `host_ts`, and `previous_hash`, then compare it against the `record_hash` returned in the `accept` response; this recompute-and-compare check is termed **Polluted Stop** verification. Because the host returns `record_hash` on every `accept` (§7.1) regardless of level, a Level-1 tool MAY opt into Polluted Stop; the check is OPTIONAL at Level 1 and REQUIRED at Level 2.

The tool fails closed on any of the following, evaluated in this order:

- If the host replies with `reject` or `unavailable`, the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "host-rejected"` for a `reject` or `reason: "host-unavailable"` for an `unavailable`.
- If the tool requires `witness: "host"` (§5.2) and the `accept` carries no `host_signature`, the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "host-unwitnessed"`.
- If a `host_signature` is present but does not verify against the `host_key_id`'s registry entry, the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "host-signature-invalid"`. A tool that does not require a witness MAY omit this verification; a tool that performs it MUST apply this bullet, whether or not it required a signature.
- If the hashes do not match (indicating ledger pollution or host compromise), the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "hash-mismatch"`.

These conditions are listed in precedence order: the response's `status` first, then the witness signature that authenticates the host-assigned fields, then the hash computed over them. Where more than one holds, the tool MUST emit the `reason` of the first that applies, so that two implementations seal the same `reason` for the same response. The `reason` is sealed into the ledger and compared across implementations (§7.6), so leaving the choice open would make the record implementation-dependent.

### 7.3 Protocol limits and environmental enforcement

The protocol establishes the tool's obligation to halt execution - the `MUST NOT perform the internal action` of §7.2 - when an attempt is rejected, is unavailable, returns without the witness signature the tool requires, carries one the tool cannot verify, or fails hash verification. However, the Auditable MCP protocol itself operates via JSON-RPC messages and cannot physically restrain a rogue tool that violates this obligation.

Detecting and physically terminating a rogue tool (e.g., sending process kill signals, or dropping unauthorized network-layer egress traffic - distinct from the §4.2 `egress` attestation flag - via a network gateway) is outside the scope of this protocol and remains the responsibility of the host's runtime environment, orchestrator, or infrastructure.

### 7.4 Level-2 detection

Under Level 2, the host MUST verify each `signature` against a public key registered out-of-band for the `key_id`. The registry entry binds the signature algorithm (§5.1); an unregistered `key_id` is rejected as `unknown-key` (§7.6). The host MUST track the monotonic `signer_seq` per `key_id`.
The host MUST reject events with missing or invalid signatures, and MUST reject events with a `signer_seq` less than or equal to the last accepted `signer_seq` for that `key_id` (replay). A forward gap may indicate a suppressed event; the host MUST flag the anomaly (a `signer-seq-gap`, §7.6) but MUST NOT reject the current valid event.

**Every signed event consumes a `signer_seq`.** A tool increments `signer_seq` once per emitted event for that `key_id` - attempts AND their terminal outcomes alike - so an accepted attempt at `signer_seq` N and its signed outcome at N+1 are contiguous. A verifier MUST count both when checking continuity; assuming attempts-only would flag every attempt-to-attempt transition as a spurious gap. The host's tracker advances only on a sealed (accepted) event: an event the host rejected or dropped does not advance the last-accepted `signer_seq`, so the tool's next event is checked against the last value actually sealed.

**Atomic numbering.** A tool MUST assign `signer_seq` and emit the event atomically with respect to every other event it signs under the same `key_id`. `signer_seq` is the order the tool emitted in, not the order it happened to finish signing in: a tool that numbers two events 1 and 2 and emits 2 before 1 has told the host that its own event 1 is a replay, and the host - correctly, by the rule above - rejects it and records the anomaly against the tool. Where a tool signs remotely, the signing latency falls inside this section, because that is where the reordering happens.

This is the tool's half of §7.1's atomic sealing, and like it, it constrains the property rather than the mechanism. It does not forbid concurrent operations; it means their events leave in one order under one key. A deployment that wants them independent of each other as well gives each stream its own `key_id`: `signer_seq` is per key, so separate keys are separate sequences. Gap detection stays authoritative for each of them as long as it is bound to one partition (below).

**Baseline (first observation).** The first `signer_seq` observed for a `key_id` establishes the baseline: the host accepts it as-is and MUST NOT treat it as a gap, because the host has no prior value to compare against. Only subsequent events are checked for replay (`<=` baseline) and gaps (`>` baseline by more than one).

**Partition scoping of gap detection.** `signer_seq` gap detection is reliable only when a `key_id` is bound to a single partition (§10.5). Because a host maintains its `signer_seq` tracker per partition (§11.2) but a tool increments one `signer_seq` per `key_id`, a key reused across partitions produces forward gaps in each partition's view for events the tool emitted to other partitions. Therefore a host MUST NOT treat a `signer_seq` gap as evidence of suppression when the `key_id` is not partition-bound; in that configuration gap detection is advisory only (a flag for out-of-band, cross-partition correlation), whereas replay (`<=` the last accepted value within the partition) remains a hard reject. Binding one `key_id` to one partition is the deployment condition under which gap detection is authoritative, and is RECOMMENDED where suppression detection is required.

### 7.5 Reconciliation with governance-boundary observations

A host MAY independently observe a tool's operations and compare those observations against the tool's self-reported ledger records to detect event suppression (omissions). Because `egress` is defined against the governance boundary (§4.2), not physical network topology, a host that performs this reconciliation MUST derive its observations from a control that classifies each destination by governance scope - a Layer-7 control such as a CASB, DLP engine, or secure web gateway that distinguishes tenant-governed destinations from external ones. A raw L3/L4 network gateway does not provide a usable egress signal: it observes every call to a tenant-managed SaaS as network traffic and cannot tell it apart from an out-of-governance egress. Reconciliation looks for an observed egress to an out-of-governance destination that has no correlated self-reported `egress: true` event. The handling of the resulting reconciliation anomalies, and the concrete integration with a specific CASB/DLP control, are outside the scope of this protocol and are the responsibility of the host's runtime environment or orchestrator.

### 7.6 Reason and anomaly code vocabulary

A reject `reason` (§7.1), an outcome `reason` (§7.2), and a ledger anomaly kind (§7.4, §10) are all machine-readable codes. Because a tool branches on a reject/abort code and an independent verifier processes anomaly kinds in a ledger authored by a different implementation, an unconstrained "RECOMMENDED, extensible" vocabulary is too weak: two implementations would coin divergent strings and interoperability would fail on exactly the codes that drive control flow. This version therefore defines a two-tier vocabulary.

**Tier 1 (Normative, fixed).** The following codes are control-flow- or verification-critical. A conforming implementation MUST use these exact strings for the stated conditions, MUST NOT repurpose a Tier-1 string for a different meaning, and MUST map any Tier-2 condition onto the applicable Tier-1 code.

Host reject / unavailable `reason` codes (the host returns one to the tool; the tool branches on it):

| Code                | Meaning                                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `schema-invalid`    | The event failed structural or canonicalization-domain validation (§7.1, §8.1). The catch-all for malformed input.             |
| `replay-detected`   | A replay: a duplicate attempt `id` (§7.1) or a `signer_seq` at or below the last accepted value for the `key_id` (§7.4).       |
| `signature-invalid` | A Level-2 signature failed verification against the registered key (§7.4).                                                     |
| `l2-unsigned`       | A Level-2 host received an event lacking a required `signature` (§7.4).                                                        |
| `unknown-key`       | The `key_id` has no entry in the out-of-band key registry (§5.1, §7.4).                                                        |
| `internal-error`    | The host could not durably record the event because of its own internal failure; returned with `status: "unavailable"` (§7.1). |

Tool abort `reason` codes (the tool records one on its fail-closed `aborted` outcome, §7.2):

| Code                     | Meaning                                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------------------- |
| `hash-mismatch`          | Polluted Stop found the host's `record_hash` did not match (§7.2).                              |
| `host-rejected`          | The host returned `reject`, so the tool did not perform the action.                             |
| `host-unavailable`       | The host returned `unavailable`, so the tool did not perform the action.                        |
| `host-unwitnessed`       | The tool required a witness signature and the `accept` carried none (§5.2, §7.2).               |
| `host-signature-invalid` | A witness signature was present but failed verification against the registered host key (§7.2). |

Anomaly kinds (a verifier reads these from a possibly foreign ledger):

| Kind                     | Meaning                                                                                                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `schema-invalid`         | A sealed record fails structural or canonicalization-domain validation (a malformed record was sealed).                                                                                                      |
| `record-hash-mismatch`   | A sealed record's recomputed hash does not match its stored `record_hash` (retroactive alteration, §10.7).                                                                                                   |
| `digest-mismatch`        | The recomputed tail digest does not match the anchored digest (§8.3, §10.7).                                                                                                                                 |
| `seq-gap`                | A gap in the host-assigned per-partition ledger `seq` (a lost sealed record, §10.7).                                                                                                                         |
| `signer-seq-gap`         | A forward gap in a `key_id`'s Level-2 `signer_seq` (a possibly suppressed event, §7.4), authoritative only when the key is partition-bound (§10.5); distinct from `seq-gap`, the host-assigned ledger index. |
| `signature-invalid`      | A sealed Level-2 record carries a signature that fails verification (§7.4).                                                                                                                                  |
| `orphaned-outcome`       | A `success` or `failed` outcome references no accepted attempt - never accepted, or after its attempt was rejected (§7.2).                                                                                   |
| `unreported-egress`      | Governance-boundary reconciliation saw an out-of-governance egress with no correlated self-reported event (§7.5, §10.2).                                                                                     |
| `host-signature-invalid` | A sealed record claims a witness it cannot back: a `host_signature` that fails verification against the registered host key, a `host_key_id` with no current registry entry (§10.9), or one of the pair present without the other (§7.1). The absence of *both* is not an anomaly; an unwitnessed record is a state (§5.2). |
| `principal-mismatch`     | A sealed record's bound identity does not match the principal its partition is expected to hold, or it carries no binding where the deployment requires one (§10.10).                                        |

The Tier-1 set is a closure: every reject, unavailable, abort, and anomaly condition this specification defines maps to exactly one Tier-1 code, so an implementation always has a safe, interoperable code to emit. **Every code-valued field on the wire or in the ledger is pinned to Tier-1.** Specifically: the Attempt Response `reason` is pinned by its schema to the Tier-1 reject codes plus `internal-error` for `unavailable` (`schema/audit-attempt-response.schema.json`); the sealed outcome-event `reason` is pinned by its schema to the Tier-1 abort codes (§7.2, `schema/audit-event.schema.json`); and every anomaly `kind` a conformant verifier reports is a Tier-1 anomaly code. None carries an additional free-form field (the wire schemas are `additionalProperties: false`).

The Tier-1 codes are namespaced by the field they occupy - reject/unavailable `reason`, abort `reason`, and anomaly `kind` are three distinct code spaces - so a string such as `signature-invalid` legitimately appears both as a reject reason (a Level-2 host refusing an event) and as an anomaly kind (a verifier finding a sealed record whose signature fails).

**Tier 2 (local diagnostics only).** A finer-grained cause - for example a numeric-domain violation or a specific missing field (under `schema-invalid`), which of the two replay conditions fired (under `replay-detected`), whether an orphan was never-accepted or post-reject (under `orphaned-outcome`), or a specific storage fault (under `internal-error`) - is a **local, out-of-band diagnostic**: an implementation MAY record it in its host-side anomaly log, operator telemetry, or human-readable messages, but it is *not* carried on the wire or sealed into the ledger, which convey only the Tier-1 code. This keeps the interoperable contract (Tier-1) machine-checkable while leaving diagnostics unconstrained. If an implementation surfaces Tier-2 codes across a trust boundary (e.g., in an aggregated audit dashboard), each MUST be namespaced with a vendor prefix (e.g., `example.com/rows-exceeded`) to prevent cross-vendor collision, and MUST NOT collide with a Tier-1 string; a consumer that does not recognize a Tier-2 code MUST fall back to the Tier-1 code's semantics.

## 8. Canonicalization and hashing

The integrity of the ledger, the ability for tools to verify host responses (§7.2), and the cross-platform verifiability by independent auditors depend on a strict, deterministic serialization contract.

**Canonicalize the received structure with JCS; do not first apply any semantic normalization to field values.** Canonicalization (§8.1) is itself a re-serialization of the parsed JSON structure - that is required and deterministic. What an implementation MUST NOT do is route field values through a typed model that reconstructs and re-serializes them (parsing `id` into a native UUID, `ts` into a native datetime, or a number into a re-formatted numeric type) before canonicalizing, because such semantic normalization can silently change a value (case, zero-padding, timezone form, trailing zeros) and split the chain across implementations that would otherwise agree. Audit fields whose exact bytes are hashed SHOULD therefore be modeled as pattern-validated strings, not reconstructed typed values, so the validated value and the canonicalized value are the same string. Validating `id` and `ts` against string patterns rather than parsing them into native UUID or datetime types is how the reference implementations keep the two identical.

### 8.1 Canonical JSON serialization (RFC 8785)

Any JSON object subjected to hashing MUST be serialized according to the JSON Canonicalization Scheme (JCS) defined in **[RFC-8785]**.
This requirement provides byte-for-byte reproducibility across heterogeneous environments (e.g., differing floating-point representations), preventing false-positive ledger integrity failures.

Because JCS serializes numbers as IEEE-754 double-precision values, every numeric value in an event (including within `action_context`) MUST be finite, and every integer-valued number MUST satisfy |n| <= 2^53-1. Beyond that bound a runtime cannot distinguish an exact integer (which loses precision as a double, so one platform rounds it while another rejects it) from a float that happens to be integer-valued, so a conforming implementation MUST reject any such event rather than risk divergent canonicalization.

A conforming host MUST reject any event carrying a non-finite number or an integer-valued number with |n| > 2^53-1, before that value could be sealed. A producer MUST NOT emit such a value; a host reports the rejection under the Tier-1 code `schema-invalid` (§7.6).

Runtimes whose native JSON parser is lossy for large integers (ECMAScript `JSON.parse` rounds an integer beyond 2^53 to the nearest IEEE-754 double) still satisfy this at the `2^53-1` boundary by inspecting the parsed value: any out-of-domain integer rounds to a double `>= 2^53`, which is not a safe integer and is thus still detectable and rejected after parsing - no in-domain value is ever produced by rounding an out-of-domain one. An implementation on such a runtime MUST reject on this post-parse test; one with a precision-preserving parser (big integers) MAY instead screen the raw value. Either way the requirement is that no out-of-domain value is sealed; this boundary is chosen precisely so the check is reliable without a custom parser.

### 8.2 The Record Hash Preimage

To prevent canonicalization attacks, the hash preimage is constructed as a unified JSON object. Implementations MUST construct a JSON object containing the exact fields below, serialize it via RFC 8785 (§8.1), and apply SHA-256 over the resulting UTF-8 bytes:

```json
{
  "event": { ... },
  "host_ts": "<ISO-8601 string assigned by host>",
  "previous_hash": "<hex-encoded string>",
  "seq": <integer>
}
```

The `event` member is the complete audit event as sealed, byte-for-byte. **Under Level 2 this includes the `signature`, `key_id`, and `signer_seq` fields**: the `record_hash` is computed over the full signed event, so tampering with the signature after sealing breaks the chain. The `signature`-removal rule stated below applies ONLY to computing and verifying the signature itself (to avoid self-reference); it does *not* apply to the record-hash preimage, whose `event` retains `signature`. A host's `host_signature` and `host_key_id` (§7.1) are the opposite case: they are not members of the preimage and not members of the `event`, so they never enter `record_hash`, which is what lets a witnessed and an unwitnessed sealing of the same record agree (§5.2).

Because the `signature` bytes are hashed verbatim, a host MUST NOT apply any cryptographic normalization - such as ECDSA low-S (malleability) coercion - to a `signature` before hashing it; the exact wire bytes MUST be used. A host that coerces `s` (or otherwise re-encodes the signature) before sealing would compute a `record_hash` divergent from the tool's Polluted Stop preimage and fork the Level-2 chain, even though the coerced and original signatures both verify. This complements §5.1's rule that a verifier accepts both low-S and high-S signatures without normalization: neither the verifying host nor the hashing host rewrites signature bytes.

The host MUST persist and re-serve the exact `host_ts` string it assigned (in the `accept` response and in the sealed record), byte-for-byte; it MUST NOT round-trip `host_ts` through a datetime type that could renormalize it (fractional digits, offset form), since `host_ts` is hashed into the preimage and any renormalization would break Polluted Stop and cross-verifier agreement. The schema pins `host_ts` to UTC `Z`.

The chain hashes (`record_hash`, `previous_hash`, and the tail digest) are bare hex (lowercase), fixed to SHA-256 by this version of the preimage construction. This differs from `action_context_hash` (§4.3), which carries an algorithm prefix (`sha256:<hex>`): the context hash is a tool-authored commitment that may need to name its algorithm as the field evolves, whereas the chain hash algorithm is version-pinned and needs no self-description. The chain hash algorithm MUST NOT vary within a `spec_version`; changing it is a new `spec_version`, never an in-band negotiation.

If Level 2 signatures are used, the signature MUST be computed and verified over the RFC 8785 canonical form of the event with the `signature` field itself removed, to prevent self-referential forgery.

This preimage is a cryptographic construct assembled locally by each party - by the host when sealing a record, and by the tool when performing Polluted Stop verification (§7.2). It is never transmitted on the wire. Unlike the wire contracts - the §4 audit event, the §6.1 Capability object, and the §7.1 Attempt Response, each bound to a JSON Schema under [`schema/`](schema/) - the preimage is defined solely by its structure in this section, with no accompanying schema. It is assembled from already-validated inputs (the `event` and the host-assigned fields) purely as input to the hash function; schema validation of the preimage is not required.

### 8.3 Ledger Chaining

For each accepted `audit/attempt`, and for each `audit/outcome` that correlates to an accepted attempt and passes the same Level-2 signature and sequence validation (§7.4), the host seals a record and appends it to the partition chain in arrival order (advancing `seq`). Attempt records are de-duplicated by `id` (§7.1); valid outcome records are appended as received and are not de-duplicated. Because outcomes are not de-duplicated, bounding the number of outcomes a tool may emit per correlation `id` (to limit ledger growth) is a host/SDK responsibility (cf. §7.3). Records form a tamper-evident chain by including the `previous_hash` in the preimage object. The first record in a partition uses a genesis hash consisting of 64 zeros. The `record_hash` of the tail record serves as the ledger digest, which SHOULD be anchored out-of-band to a secure medium; without a periodically anchored tail digest, truncation of a chain suffix (including a rewind to genesis) is undetectable, because a truncated prefix is internally consistent.

### 8.4 Conformance Vectors

Golden conformance vectors are published alongside this specification under the `vectors/` directory, covering RFC 8785 canonicalization (`canonicalization.json`), per-event hashes (`events.json`), a complete sealed Level-1 chain (`chain.json`), a sealed Level-2 signed chain that hashes the `signature` into each `record_hash` (`chain-signed.json`, §8.2), a witnessed chain (`chain-witnessed.json`), and negative cases (`error-cases.json`): events that a conformant host MUST reject, each paired with the expected Tier-1 reject `reason` (§7.6). A conforming implementation MUST reproduce the positive vectors byte-for-byte and MUST reject each `error-cases.json` event with the pinned reason.

`chain-witnessed.json` carries the same events and host-assigned fields as `chain.json`, plus the `host_signature`, `host_key_id`, and witness-signature preimage of §7.1. An implementation MUST reproduce each record's `witness_preimage.canonical` byte-for-byte, and MUST produce `record_hash` values and a tail digest identical to `chain.json`'s - that identity is what holds the witness signature outside the §8.2 preimage (§5.2). The `host_signature` in this vector is fixed test data, not a verifiable signature: the chain property under test is that the field does not enter the record hash. The `mutates` and `egress` values in the vectors are chosen for byte-coverage of the event shape, not as normative usage guidance; §4.2 is the sole source of their semantics.

## 9. Relationship to existing standards

**SEP-3004 (Tamper-Evident Audit Record Contract)**
SEP-3004 defines a tamper-evident audit record contract at the orchestrator-visible boundary. Auditable MCP is complementary: it produces the tool-internal domain records, which the host MAY subsequently seal using SEP-3004's contract as the underlying ledger storage format.

**SCITT (Supply Chain Integrity, Transparency and Trust)**
SCITT registers Signed Statements in a Transparency Service and returns a Receipt, a proof of inclusion in a verifiable data structure [SCITT]. A witness signature (§5.2, §7.1) is deliberately not called a Receipt and is not one: it attests that a named host sealed a record at a stated position in a chain, not that the record is included in a published, independently auditable structure. A deployment that wants the stronger property anchors its tail digest (§8.3) into such a structure; this specification does not define that binding.

**Transparency-log witnesses**
In transparency-log vocabulary - [C2SP] `tlog-witness`, and Sigsum - a witness is a party independent of the log operator that cosigns what the operator published. Here the confirming party is the operator of the ledger itself: *witness* names the relationship between the tool and the host, not an independent third party. A deployment that wants the stronger, independent sense adds it outside this protocol, over the anchored tail digest (§8.3).

**Transparency logs that answer with a promise**
A log may answer a submission with a promise rather than a position: [RFC-9162] returns a Signed Certificate Timestamp and allocates the entry's tree index later, within its Maximum Merge Delay, and [SCITT] states the append-only property of the verifiable data structure without constraining how concurrent registrations reach it. That deferral is what lets such a log sequence submissions in its own time. Auditable MCP is in the other class: the Verifiable Accept hands the tool `seq` and `previous_hash` at the moment of the reply, because the tool reconstructs the preimage to perform Polluted Stop (§7.2) before it acts. §7.1 therefore requires the host to seal atomically, which is the obligation that comes with returning the position rather than a promise.

**Cryptographic Ecosystems**
The requirement for deterministic serialization (RFC 8785) prior to hashing and detached signing (§8) is adopted from established supply-chain security and transparency frameworks (e.g., Sigstore, in-toto). This protocol uses these standard primitives rather than defining custom cryptography for the MCP boundary.

## 10. Security and Operational Considerations

### 10.1 Ledger Integrity as the Root of Trust

The host acts as the definitive authority for ledger integrity. Auditable MCP relies on the host's ability to maintain the append-only property and the hash-chain of records. Compromise of the host's ledger storage results in the total loss of auditability. Where the witness is `host`, an attacker who reaches the storage but not the host's witness-signing key cannot re-sign the records it rewrites, so a verifier that checks witness signatures detects the rewrite (§11.4); the signing key is therefore a distinct asset from the ledger and SHOULD be held separately from it.

### 10.2 Limits of Self-Attestation (Omission and Misattestation)

Cryptographic signatures and sequence gaps detect _falsified_ or _lost_ records, but cannot detect an internal action a tool never reports at all (suppression by omission). This residual risk is mitigated only by out-of-band reconciliation (§7.5), which compares self-reported egress against independently observed out-of-governance egress.

A signature proves an event's authorship and integrity in transit, not the truthfulness of its content. A compromised or faulty tool can emit a validly-signed event that misdescribes the operation - a false `mutates`, `egress`, or `outcome`, or a fabricated `target_resource` (misattestation). Signature, sequence, and hash-chain verification do not detect this; reconciliation (§7.5) catches only discrepancies observable at the governance boundary (e.g., an out-of-governance egress the tool never reported). Misattestation of a within-governance, non-egress operation is a residual risk fed to allowlist governance, not a protocol guarantee.

**A record confirmed by the party that produced it adds nothing.** Where the tool and the host are one party - the degraded posture (§6.2), or any deployment in which a single operator controls the tool and the verifier's registry (§5.2) - the chain's internal consistency and its authorship both rest on that party, so no record in it is evidence against that party and the limits above apply to the chain as a whole rather than record by record. The witness axis exists so that a verifier can tell such a chain from one a distinct host confirmed, and §11.4 requires it to make that distinction from the record rather than from a claim.

### 10.3 Data-at-Rest Minimization

Because the host's ledger is append-only, any sensitive value written to `action_context` in cleartext is permanent and cannot be erased (e.g., conflicting with GDPR Right to Erasure). Implementations SHOULD prefer `action_context_hash` for sensitive internal context (§4.3), keeping only a verifiable commitment - not the data - in the immutable ledger.

### 10.4 Handling of Aborted Outcomes

An `aborted` outcome that references a rejected or never-accepted attempt is the tool correctly honoring its fail-closed obligation. A host MUST NOT treat such an `aborted` outcome as a tampering anomaly; it MAY note it out-of-band as an audit signal of a refused action, but MUST NOT seal it into the chain.

### 10.5 Partition Isolation and Sequence Scoping

A partition (§3) is a host-side isolation boundary. A host MUST maintain a separate hash chain, `seq` counter, `signer_seq` tracker, and anomaly set per partition; records, sequences, and anomalies MUST NOT cross partitions, and a partition's chain is verifiable only against its own genesis. That separation is spatial; its temporal counterpart is the atomic sealing of §7.1, without which two concurrent seals may take the same position in one partition's chain.

The host-assigned `seq` is per-partition, but a tool's Level-2 `signer_seq` is per `key_id` (§4, §7.4). If a tool reuses one signing key across partitions, that key's single monotonic `signer_seq` is interleaved across the partitions' independent ledgers, so a host or auditor examining one partition observes forward gaps for events the tool emitted to other partitions. Such a gap is benign and does not by itself indicate suppression; a host or auditor correlating events across partitions (by `key_id`) can distinguish it from a genuine gap. Accordingly, §7.4 makes `signer_seq` gap detection authoritative only when a `key_id` is bound to a single partition and advisory otherwise; replay detection remains authoritative in every configuration.

### 10.6 Scope of the Polluted Stop

The Polluted Stop procedure (§7.2) lets a Level-2 tool detect that the host sealed a record whose body differs from the bytes the tool emitted, by recomputing the `record_hash` from the host's `accept` response. Its coverage is bounded:

- It detects only body substitution where the host honestly reports the hash it sealed. A host that lies consistently - returning a `record_hash` computed over the tool's original bytes while sealing or persisting something else - passes the check undetected.
- It does not cover post-`accept` tampering, nor a host that returns `accept` without durably persisting the record.
- It covers only attempt records: `audit/outcome` is a notification (§6) with no returned `record_hash`, so a tool cannot Polluted-Stop-verify its own outcomes. Outcome integrity rests instead on chain recomputation, the anchored digest, and - where the witness is `host` - the signature the host writes into the ledger for each sealed outcome (§7.2).
- Under Level 1 the tool is not required to verify (§11.3); absent that optional check, an L1 host is trusted unconditionally.

Beyond this scope, detection rests on the host's own ledger integrity (§10.1), independent verification against an out-of-band anchor (§8.3), and governance-boundary reconciliation (§7.5). Post-seal tampering with a sealed Level-2 `signature` is caught by chain recomputation as a `record-hash-mismatch` (the signature is inside the record-hash preimage, §8.2), so an independent verifier detects it without re-running signature verification; the `signature-invalid` anomaly kind (§7.6) is reserved for a verifier that additionally re-verifies signatures against a synchronized key registry, which is optional for a pure ledger auditor.

### 10.7 Threats Detected

As a detective control, the protocol detects the following against the ledger:

- **Replay** - a duplicate attempt `id` is rejected (§7.1).
- **In-flight forgery or modification** - a Level-2 detached signature is verified and an invalid one rejected (§7.4).
- **Event suppression** - a Level-2 forward `signer_seq` gap is flagged as a `signer-seq-gap` (§7.6), subject to the partition-binding condition of §7.4.
- **Retroactive ledger alteration** - recomputation of the hash chain localizes a mutated record that does not re-link the chain (§8.3); a fully re-linked rewrite is detected only against an out-of-band anchor (as with truncation).
- **Ledger truncation or rewind** - detected when the tail digest is anchored out-of-band (§8.3); undetectable without an anchor.
- **Shadow operation (partial)** - a `success` or `failed` outcome referencing no accepted attempt is flagged (§7.2); an action a tool never reports at all is caught only by governance-boundary reconciliation for out-of-governance egress (§10.2).
- **Outcome suppression (partial)** - an accepted attempt with no correlated terminal outcome is a completeness gap a verifier MAY flag, but it cannot be distinguished from in-progress or crashed execution (§10.8).
- **A fabricated or misattributed accept** - where the witness is `host`, the `host_signature` binds the host-assigned fields to a key the registry binds to that host, so an `accept` the named host did not issue fails verification and the tool aborts (§7.2). Polluted Stop alone does not cover this: it detects a response describing a *different* record, not one produced by a *different party* than the tool believed it was talking to.

Content misattestation (§10.2) is outside the reach of cryptographic detection.

### 10.8 Completeness of the Attempt/Outcome Correlation

An `audit/attempt` is a blocking request whose loss the tool observes directly, but an `audit/outcome` is a fire-and-forget notification (§6) whose loss the host cannot detect through `seq`: the outcome is often the final event of a tool call, so no later ledger `seq` exposes its absence. An accepted attempt that never receives a correlated terminal outcome (`success`, `failed`, or `aborted`) therefore leaves a **completeness gap** in the ledger.

A verifier cannot distinguish, from the ledger alone, among three cases: an operation still in progress, one whose tool crashed after acceptance, and one whose outcome was suppressed by a faulty or hostile tool. A verifier MAY flag an attempt that lacks a correlated terminal outcome after a deployment-defined settling period, but MUST NOT treat the missing outcome as a sealed-integrity failure of the chain, since the chain over the sealed records remains internally consistent. Bounding the wait (a completeness sweep, an execution-timeout policy, or an OPTIONAL outcome acknowledgement that lets the tool detect a lost notification) is an SDK/host responsibility and is not defined by this protocol. Where outcome delivery must be assured, deployments SHOULD add such an out-of-band acknowledgement rather than rely on `seq` continuity, which cannot cover a trailing notification.

### 10.9 Key Lifecycle: Rotation and Revocation

Level 2 roots trust in the out-of-band key registry (§5.1). Key rotation and revocation are deployment concerns, but they interact with two protocol mechanisms and must be handled deliberately:

- **Rotation.** A new `key_id` starts a fresh `signer_seq` baseline (§7.4). A tool that rotates keys therefore SHOULD complete the outcomes for in-flight operations under the old `key_id` before switching, so continuity is not falsely broken. Reusing a `key_id` with a new public key is *not* rotation; it is indistinguishable from key compromise and MUST NOT be done - a `key_id` binds one key for its lifetime.
- **Revocation.** Records sealed with a key while it was valid remain valid evidence: the signature and the hash chain still prove authorship and integrity at seal time, and the append-only ledger is not rewritten on revocation. Revocation is forward-looking - after a `key_id` is revoked in the registry, the host MUST reject subsequent events bearing it as `unknown-key` (§7.4). Whether events sealed near the compromise window are trustworthy is a governance judgment made against the anchored digests (§8.3) and the revocation timestamp, not a protocol determination; the protocol preserves the evidence, it does not adjudicate it.

**Both registries are in scope.** The rules above are written for the Level-2 registry that binds a tool's signing keys (§5.1). They apply unchanged, with the roles exchanged, to the witness registry that binds a host's (§7.1): a `host_key_id` binds one key for its lifetime, a host rotating keys completes in-flight operations under the old one first, and a record witnessed under a key that was valid at seal time remains valid evidence. A `host_signature` whose `host_key_id` has no current registry entry - never registered, or revoked - does not establish the witness, and is reported `host-signature-invalid` (§7.6) by a verifier and aborted on under §7.2 by a tool; §7.6 requires such a condition to be mapped onto the applicable Tier-1 code rather than given a new one.

Because the ledger is a detective control (§2), neither rotation nor revocation retroactively rewrites or re-flags sealed records; both are reconciled out-of-band against the registry's own history.

### 10.10 Identity binding in shared storage

The event (§4) carries no field naming the governed identity an operation is attributed to. A partition (§3, §10.5) is a host-side concept the tool is unaware of, and it is not part of the §8.2 preimage, so partition membership is a property of where a record is stored, not of the record's own bytes. A chain therefore proves internal consistency and authorship; by itself it does not prove whose chain it is.

That is sound where one deployment holds one principal's ledger. It is not sound where records for several principals share a store: a record sealed under one principal's partition stays internally consistent when moved into another's, because nothing in its hashed bytes contradicts the new location. A transplant of this kind is out of reach of the chain alone.

A deployment that stores records for more than one principal in a shared medium MUST bind identity by one of the following, and a verifier MUST check whichever was chosen:

1. **Wrap in SEP-3004.** Seal each Auditable MCP record inside a SEP-3004 boundary record, whose protected core binds `principal_id` in the hashed bytes [SEP-3004], and check that `principal_id` against the principal the partition is expected to hold.
2. **Bind inside the sealed record.** Carry the host-assigned identity in the record as sealed, so that it falls inside the record hash, and check it against the same expectation.

Either way, the expectation MUST be supplied out-of-band. It is an input to verification, never a value read from the artifact under verification: a transplanted record carries its own identity with it, so an expectation taken from that record would always match it. A record whose bound identity does not match the expectation, or which carries no binding where the deployment requires one, is flagged `principal-mismatch` (§7.6). The absent case fails closed: an unbound record cannot be shown to belong where it was found.

A single-principal deployment needs neither construction, and this specification does not add an identity field to §4 for it. Identity belongs to the layer that owns the storage boundary, and an optional field in the event would let an implementation satisfy the schema without binding anything.

## 11. Conformance

An implementation (Host, Tool, or Verifier) is considered conformant to the Auditable MCP specification if it fulfills the following normative requirements. An implementation that acts in more than one role meets the requirements of each.

### 11.1 General Requirements

- **Conformance Vectors:** Implementations MUST reproduce every positive golden vector under `vectors/` byte-for-byte, and MUST reject each negative (error-case) vector with its pinned Tier-1 reason (§8.4). Given identical inputs, conformant implementations MUST produce an identical `record_hash` across any language boundary.
- **Canonicalization:** Implementations MUST perform JSON serialization strictly according to RFC 8785 (JCS) prior to any hashing or signing (§8.1).

### 11.2 Host Conformance

A host embedded in a tool for the degraded posture (§6.2) takes part in no MCP session, so the capability requirement below does not apply to it; every other requirement does.

A conformant Host MUST:

- **Capability Enforcement:** Publish its required audit capability under the `extensions` member of its `ClientCapabilities`, keyed by the extension identifier (§6.1), and enforce that level at runtime (§7.1), rejecting events that do not meet the mandated level.
- **Verifiable Accept:** Return `seq`, `host_ts`, and `previous_hash` alongside `record_hash` in the `accept` response (§7.1).
- **Witness Signing:** If it declares `witness: "host"` (§5.2), sign the host-assigned fields of every sealed record - attempt and outcome alike - and persist `host_signature` and `host_key_id` with it; return both in the `accept` response for an attempt, which is the only record kind with a response channel (§7.1, §7.2).
- **Ledger Validation:** Perform the mandatory schema, numeric canonicalization-domain (§8.1), and attempt `id`-uniqueness (both levels), plus `signer_seq` and signature (Level 2), validations before sealing (§7.1); fail closed on integrity violations.
- **Atomic Sealing:** Assign `seq` and `previous_hash`, seal, and commit atomically with respect to any other record being sealed into the same partition, so that two concurrent attempts never take the same position (§7.1, §10.5).
- **Receive-boundary Numeric Enforcement:** Reject a number outside the canonicalization domain at ingestion, before a lossy native parse can corrupt it (§8.1).
- **Anomaly Flagging:** Flag (without rejecting) a forward `signer_seq` gap (`signer-seq-gap`) where the `key_id` is partition-bound (§7.4) and any orphaned `success` or `failed` outcome (`orphaned-outcome`) that references no accepted attempt (§7.2, §7.6).
- **Code Vocabulary:** Use the Tier-1 reason codes for control-flow rejects and the Tier-1 anomaly kinds for cross-implementation ledger inspection, exactly as specified (§7.6).
- **Partition Isolation:** Maintain a separate hash chain, `seq`, `signer_seq` tracker, and anomaly set per partition; never let records, sequences, or anomalies cross partitions (§10.5).

### 11.3 Tool Conformance

A conformant Tool MUST:

- **Audit-before-Act:** Emit an `audit/attempt` and receive a successful `accept` response from the host before performing the corresponding internal domain action (§6).
- **Polluted Stop:** Under Level 2, recompute the `record_hash` upon receiving an `accept` response using the host-provided `seq`, `host_ts`, and `previous_hash`, and abort execution if the hash does not match (§7.2). Under Level 1, this verification is OPTIONAL.
- **Atomic Numbering (Level 2):** Assign `signer_seq` and emit the event atomically with respect to every other event signed under the same `key_id`, so the order the host observes is the order the tool numbered (§7.4).
- **Signature Encoding (Level 2):** Sign with the algorithm bound to the `key_id` by the registry and encode the detached `signature` as standard base64 (§5.1).
- **Abort Signaling:** Upon a `reject`, `unavailable`, or Polluted-Stop hash mismatch, emit an `outcome: "aborted"` event with the appropriate Tier-1 `reason` (§7.6) before completely halting the operation.
- **Witness Enforcement:** If it requires `witness: "host"` (§5.2), verify the witness signature on every `accept` and abort with `host-unwitnessed` or `host-signature-invalid` rather than act on an unwitnessed record (§7.2).
- **Degradation:** In an unnegotiated session (§6.2), send no `audit/attempt` or `audit/outcome`, serve `tools/call` exactly as a build without this extension would, and take one of the two admissible postures, degraded or mandatory. Never serve a call while neither recording the operations nor reporting the omission.

### 11.4 Verifier Conformance

A verifier reads a sealed ledger, possibly written by a different implementation, and reports anomalies (§7.6). A conformant Verifier MUST:

- **Chain Recomputation:** Recompute each record's hash from the §8.2 preimage and its predecessor's `record_hash`, and report `record-hash-mismatch`, `seq-gap`, and, against an anchored tail digest, `digest-mismatch` (§8.3).
- **Record Validation:** Report `schema-invalid` for a sealed record that fails structural or canonicalization-domain validation (§7.1, §8.1).
- **Level-2 Validation:** Where records carry Level-2 fields, report `signature-invalid` for a signature that fails verification, and `signer-seq-gap` for a forward gap in a partition-bound `key_id` (§7.4, §10.5).
- **Correlation:** Report `orphaned-outcome` for a `success` or `failed` outcome referencing no accepted attempt (§7.2).
- **Witness Determination:** Determine a record's witness (§5.2) by verifying `host_signature` against the `host_key_id`'s registry entry. A verifier MUST NOT infer the witness from any other field. A record carrying no `host_signature` is unwitnessed, which is a state and not an anomaly; a signature that is present and fails verification is reported `host-signature-invalid`.
- **Identity Matching:** Where the deployment binds identity (§10.10), compare each record's bound identity against an expectation supplied out-of-band, and report `principal-mismatch` on a mismatch or on a missing binding. The two are compared as values. A deployment that binds a structured identity MUST reduce it to a single primitive before verification (§10.10 binds one `principal_id`): comparing structures is implementation-defined, and two conforming verifiers would return opposite verdicts on one ledger.
- **Code Vocabulary:** Report anomalies using the Tier-1 anomaly kinds, exactly as specified (§7.6).

Level-2 verification and witness determination both require the out-of-band key registries (§5.1, §7.1). A verifier without them MUST report that those checks were not performed, rather than return a result in which their anomalies are simply absent: an unchecked signature and a valid one are not the same finding.

`unreported-egress` is the one Tier-1 anomaly a verifier does not produce by reading a ledger: it arises from governance-boundary reconciliation against an independent observation (§7.5), which is outside this role.

## 12. Extensibility and Registries

This specification defines three extension points. All three are governed by `spec_version`, not by in-band negotiation: a participant declares its supported `spec_version` at capability negotiation (§6.1), and events carry `spec_version` (§4), so a change to any registry is a new `spec_version`.

### 12.1 Signature algorithm identifiers

The algorithm identifiers `Ed25519` and `ECDSA_P256_SHA256` (§5.1) are the complete set for this version. An identifier is an opaque token matching the ABNF [RFC-5234]:

```abnf
alg-id = 1*( ALPHA / DIGIT / "_" )
```

The same identifiers and the same registry shape bind a host's witness-signing key under `host_key_id` (§7.1). A future version MAY add identifiers; when this document graduates to a standards-track process, this registry SHOULD be maintained under a "Specification Required" policy ([RFC-8126]-style), each entry pinning the identifier string, the signature scheme, and the exact raw wire encoding. Identifiers MUST NOT be added or interpreted in-band; a `key_id` bound to an unrecognized algorithm is unverifiable and its events are rejected as `unknown-key` (§7.4).

### 12.2 Tier-1 reason and anomaly vocabulary

The Tier-1 codes (§7.6) are a closed, specification-controlled set; entries are added or changed only by a new `spec_version`. They form the interoperable contract carried on the wire and in the ledger.

### 12.3 Tier-2 diagnostic namespace

Tier-2 codes (§7.6) are local diagnostics and are not centrally registered. To remain collision-free when surfaced across a trust boundary, a Tier-2 code MUST carry a vendor prefix and match the ABNF [RFC-5234]:

```abnf
tier2-code = vendor "/" code
vendor     = label *( "." label )         ; a DNS name the vendor controls [RFC-1123]
label      = ( ALPHA / DIGIT ) *( ALPHA / DIGIT / "-" )   ; RFC-1123 permits a leading digit
code       = ( ALPHA / DIGIT ) *( ALPHA / DIGIT / "-" )   ; no "/", so the prefix is unambiguous
```

For example, `example.com/rows-exceeded`. Because every Tier-2 code contains a `/` and no Tier-1 code does, a Tier-2 code cannot collide with a Tier-1 string. An unrecognized Tier-2 code falls back to its Tier-1 parent's semantics.

## 13. References

### 13.1 Normative References

- **[RFC-2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC-8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC-8259]** Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.
- **[RFC-8785]** Rundgren, A., "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
- **[RFC-8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- **[RFC-4648]** Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006.
- **[RFC-5234]** Crocker, D., Ed. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.
- **[RFC-1123]** Braden, R., Ed., "Requirements for Internet Hosts - Application and Support", STD 3, RFC 1123, October 1989.
- **[RFC-9562]** Davis, K., Peabody, B., and P. Leach, "Universally Unique IDentifiers (UUIDs)", RFC 9562, May 2024.
- **[SEP-2133]** Model Context Protocol, "Extensions framework for MCP", SEP-2133, merged 2026-01-26. The `extensions` capability member it introduces ships in MCP protocol version `2026-07-28`.
- **[SEP-3004]** Model Context Protocol, "Tamper-Evident Audit Record Contract", MCP Issue #3004.
- **[FIPS-186-5]** National Institute of Standards and Technology, "Digital Signature Standard (DSS)", FIPS PUB 186-5, February 2023.

### 13.2 Informative References

- **[RFC-8126]** Cotton, M., Leiba, B., and T. Narten, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 8126, June 2017.
- **[W3C-Trace-Context]** W3C, "Trace Context", W3C Recommendation.
- **[SCITT]** IETF SCITT Working Group, "An Architecture for Trustworthy and Transparent Digital Supply Chains", draft-ietf-scitt-architecture.
- **[RFC-9162]** Laurie, B., Messeri, E., and R. Stradling, "Certificate Transparency Version 2.0", RFC 9162, December 2021.
- **[C2SP]** Community Cryptography Specification Project, "tlog-witness", <https://c2sp.org/tlog-witness>.
- **[NIST-SP-800-53]** National Institute of Standards and Technology, "Security and Privacy Controls for Information Systems and Organizations", SP 800-53 Rev. 5, control AU-5.
- **[OTel-GenAI]** OpenTelemetry, "Semantic Conventions for Generative AI Systems".
- **[EU-AI-Act]** Regulation (EU) 2024/1689 (Artificial Intelligence Act), Article 12: Record-keeping.
