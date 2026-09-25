# Auditable MCP

- **Status:** Draft proposal. Experimental below 1.0: the wire contract may change between draft revisions, signalled by `spec_version` (§6.1).
- **Version:** `auditable-mcp/0.3`
- **Author:** Satoshi Imai
- **License:** MIT

> **v0.3 (draft).** See [CHANGELOG.md](../CHANGELOG.md) for the changes from v0.2 and the backward-compatibility notes.

## Abstract

Auditable MCP is a proposed extension to the Model Context Protocol (MCP). It defines a mechanism for an MCP tool server to self-attest its internal domain operations, such as database transactions and downstream API requests executed within a tool call. These operations are emitted as structured audit events, which the host records in a tamper-evident ledger *before* the tool performs them.
While existing MCP auditing capabilities are limited to the orchestrator-visible call boundary, this extension addresses the unobservable interior by relying on the tool's self-attestation. It is complementary to proposals that record the call boundary itself, such as SEP-3004 (Tamper-Evident Audit Record Contract) [SEP-3004].

Three properties shape how it is adopted. The specification separates what it records from how it travels: the event, the ledger, and their verification (§4, §5, §7-§12) do not depend on the MCP wire, and each supported MCP protocol version has a binding of its own (§6.4, §6.5), so a change to MCP revises a binding and nothing else. A tool that speaks this extension remains usable by hosts that do not: where the extension was not negotiated, the tool sends no audit message and serves the call as an ordinary MCP tool, under one of two named postures (§6.2). And a record states who recorded it: a host that confirms sealing countersigns for having done so, so a verifier can tell a chain a distinct host confirmed from one a tool recorded for itself (§5.2).

## 1. Motivation

When an MCP tool executes a `tools/call`, the host can observe the call boundary, including the tool name, arguments, and result. However, the host cannot observe the tool's internal execution. While operators can directly instrument the internals of first-party tools, third-party tools remain opaque. Regulatory record-keeping frameworks, such as Article 12 of the EU AI Act [EU-AI-Act], mandate traceability and the automatic recording of events (logs) for high-risk AI systems. Observations restricted to the call boundary are insufficient to provide this level of detail.

Existing approaches terminate at the orchestrator-visible boundary, and none records an operation before it happens:

- **SEP-3004** proposes a tamper-evident, hash-chained audit record contract for records a host's governance layers author about the call boundary, evaluated over an exported record set and deliberately off the wire [SEP-3004].
- **OpenTelemetry** GenAI semantic conventions trace call attributes (arguments, results, latency), and MCP propagates their trace context in `_meta` [SEP-414], but relies on separate instrumentation for domain operations executed within a tool [OTel-GenAI].
- **Result attestations** attach evidence to a `tools/call` result after the fact; the host learns what happened once it has happened.
- **Gateways**, by architectural design, log only the network traffic that crosses them.

Auditable MCP addresses this gap with a tool-to-host self-attestation mechanism for internal, domain-semantic operations, which the host anchors into a tamper-evident ledger (§4-§8). It is the only one of these in which the host's record precedes the action: the tool asks the host to record an operation and does not perform it until the host has answered with the record's position (§7.1).

## 2. Scope and non-goals

The objective of this specification is to provide a mechanism for accountability (detective control) rather than authorization (preventive control).

**In Scope:**

- Defining a protocol for an MCP tool to voluntarily report its internal domain operations.
- Establishing the host's mechanism to anchor these reported events into a tamper-evident ledger.
- Enforcing ledger integrity by strictly refusing to record events that fail cryptographic or structural verification.
- Binding the exchange to each supported MCP protocol version, kept apart from the rest of the specification so that a change to MCP is absorbed by its binding (§6.4, §6.5).
- Defining what a tool does when the extension was not negotiated, so that speaking it does not make the tool unusable with ordinary MCP hosts (§6.2).
- Distinguishing a record a distinct host confirmed sealing from one whose only backing is the tool's own attestation (§5.2).

**Out of Scope:**

- Defining real-time access control policies or authorization gateways for domain actions.
- Evaluating or guaranteeing the inherent trustworthiness of a tool. (Dangerous or unauthorized tools are assumed to be excluded out-of-band via the orchestrator's allowlist.)

Architecturally, the host acts as a "monitoring camera" over tools that have already been vetted by the orchestrator - except in the degraded posture (§6.2), where the tool provides the camera for itself and §10.2 bounds what the resulting chain establishes. Via this extension protocol, the host is not expected to evaluate or authorize the semantic execution of a tool's internal actions. Therefore, within this document, when the host "rejects" or "blocks" a record, this exclusively refers to refusing the ingestion of an invalid audit record - ensuring a fail-closed posture for ledger integrity - and never implies the real-time interception or prevention of the domain action itself.

## 3. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC-2119] [RFC-8174] when, and only when, they appear in all capitals, as shown here.

- **Tool** - A specific capability exposed by an MCP Server, whose internal operations are subject to audit via this specification.
- **Host** - The party that receives audit events and anchors them into the ledger. Ordinarily the MCP client or orchestrator; in the degraded posture (§6.2) the tool provides one for itself, which is what the countersignature axis (§5.2) distinguishes.
- **Verifier** - A party that reads a sealed ledger, recomputes its chain, and reports anomalies (§7.6, §11.4). It need not have taken part in the exchange that produced the records, and may be the host, the tool, or an independent auditor.
- **Event** - One audit record describing one internal operation (§4).
- **Audit session** - The scope of one `tools/call`: every event a tool emits while serving that call belongs to it, and nothing else does (§6.3). It is named by a `session_id` the host issues. It is not an MCP session; it begins and ends with the call.
- **Ledger** - The host's append-only, hash-chained, tamper-evident store of attested events.
- **Boundary** - The standard `tools/call` interface which the host can directly observe.
- **Governance boundary** - The logical data-governance boundary defined in §4.2: the perimeter of the organization's own data governance, not a physical network boundary. Distinct from the observable call **Boundary** above.
- **Self-attestation** - A tool's voluntary reporting of its internal domain actions to the host (cryptographically verifiable under Level 2).
- **Countersignature** - A host's signature over the host-assigned fields of a record it sealed, made with a key an out-of-band registry binds to that host (§5.2, §7.1). It is laid over a record whose event the tool already authored, which is the relationship the term names [RFC-9338]. Distinct from a tool's Level-2 event `signature`, which covers the event the tool emitted.
- **Binding** - The mapping of the exchange in §6 onto one MCP protocol version (§6.4, §6.5).
- **Domain Action** - An execution step performed internally by a tool (e.g., executing a SQL query, invoking an external API) that is opaque to the host at the boundary.
- **Partition** - A logical isolation boundary defined by the host (e.g., per tenant) within which the ledger's hash chain, `seq`, and anomaly set are scoped (§10.5). It is a host-side ledger concern; the tool is unaware of it. Every audit session is recorded into exactly one partition.

## 4. The audit event

An event is a JSON object [RFC-8259]. Its normative schema is
[`schema/audit-event.schema.json`](schema/audit-event.schema.json).

| Field                 | Type              | Presence | Notes                                                                                                                                                                                                                                                                                            |
| --------------------- | ----------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`                  | UUID              | REQUIRED | Tool-generated UUID [RFC-9562] (SHOULD be version 4 or 7; the nil UUID SHOULD NOT be used), fresh for each operation. Correlation key for one operation within its audit session: the `attempt` and its terminal `outcome` share it (§7.2). De-duplication key for attempts (§7.1).                                                                        |
| `spec_version`        | string            | REQUIRED | MUST be `auditable-mcp/0.3`.                                                                                                                                                                                                                                                                     |
| `ts`                  | ISO-8601 datetime | REQUIRED | Tool-observed time (advisory; host time is authoritative). MUST be UTC with a `Z` suffix, no numeric offset (per the schema pattern).                                                                                                                                                            |
| `session_id`          | UUID              | REQUIRED | The audit session the event belongs to (§6.3): the `session_id` the host issued for the parent `tools/call`, verbatim; never the nil UUID. Scopes `signer_seq` (§7.4) and binds the event to the call it was emitted for, so an event cannot be replayed into another session (§7.1). |
| `traceparent`         | string            | OPTIONAL | W3C Trace Context [W3C-Trace-Context] `traceparent` header value.                                                                                                                                                                                                                                |
| `action_type`         | string            | REQUIRED | §4.1.                                                                                                                                                                                                                                                                                            |
| `mutates`             | boolean           | REQUIRED | Whether the operation changes state. §4.2.                                                                                                                                                                                                                                                       |
| `egress`              | boolean           | REQUIRED | Whether the operation crosses the logical data-governance boundary. §4.2.                                                                                                                                                                                                                        |
| `target_resource`     | object            | REQUIRED | The operation's domain target (sub-fields below).                                                                                                                                                                                                                                                |
| `outcome`             | enum              | REQUIRED | `attempted` &#124; `success` &#124; `failed` &#124; `aborted` (§7.2).                                                                                                                                                                                                                            |
| `reason`              | string            | OPTIONAL | REQUIRED on an `aborted` outcome (enforced by schema): a Tier-1 abort code `hash-mismatch` &#124; `host-rejected` &#124; `host-unavailable` &#124; `host-uncountersigned` &#124; `host-signature-invalid` (§7.2, §7.6). SHOULD be omitted on other outcomes; domain detail goes in `action_context`. |
| `action_context`      | object            | OPTIONAL | Cleartext metadata about the internal operation, redacted at the tool's discretion (§4.3).                                                                                                                                                                                                       |
| `action_context_hash` | string            | OPTIONAL | `sha256:<hex>` commitment to the exact internal context (§4.3).                                                                                                                                                                                                                                  |
| `signer_seq`          | integer           | OPTIONAL | Level 2. The tool's counter per (`key_id`, `session_id`), starting at 0 (§7.4). Distinct from the host-assigned ledger `seq` (§7.1). |
| `key_id`              | string            | OPTIONAL | Level 2. Identifies the signing key; binds the signature algorithm via the registry (§5.1).                                                                                                                                                                                                      |
| `signature`           | string            | OPTIONAL | Level 2. Detached signature, base64url without padding (§5.1, §8.2). |

The `target_resource` object identifies the domain target of the operation:

| Field        | Type   | Presence | Notes                                                                                                                   |
| ------------ | ------ | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| `kind`       | string | REQUIRED | The class of resource - an open vocabulary, opaque to this specification (e.g., `table`, `file`, `endpoint`, `secret`). |
| `ref`        | string | REQUIRED | The specific resource reference (e.g., a table name, file path, or URL).                                                |
| `scope_hint` | string | OPTIONAL | Finer-grained domain scope within the resource (e.g., `row:consent_basis=marketing`).                                   |

The `signer_seq`, `key_id`, and `signature` fields are OPTIONAL in the schema, so a single schema covers both levels; see §5 for the resulting validity direction. They are present together or not at all: the schema requires each of them when any of them is present.

A UUID in this specification - an event's `id`, a `session_id`, and a key of the `responses` object (§6.4) - is written in the lowercase hexadecimal form [RFC-9562] §4 gives for output, and compared as a string. The schemas accept no other form, so two implementations cannot disagree on whether two spellings name one UUID.

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

## 5. Conformance levels and the countersignature axis

Auditable MCP defines two conformance levels to provide a progression from basic self-reporting to cryptographically verifiable auditing. Level 2 adds cryptographic signatures to prevent forgery and a per-session `signer_seq` to detect event loss. A `signer_seq` gap may indicate that an emitted event failed to reach the host (§7.4).

Both levels share one event schema; the Level-2 fields (`signature`, `key_id`, `signer_seq`) are OPTIONAL. The validity relationship is directional: every Level-2 event is also a valid Level-1 event (a safe downgrade - an event carrying a signature is still accepted where none is required), whereas an unsigned Level-1 event does not satisfy a Level-2 host, which rejects it (§7.4).

| Feature               | Level 1                                                                        | Level 2                                                                                                       |
| :-------------------- | :----------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------ |
| **Tamper Resistance** | None                                                                           | Cryptographic signature and sequencing                                                                        |
| **Tool Obligation**   | Emits the core event.                                                          | Adds `signature`, `key_id`, and the per-session `signer_seq`; MUST perform Polluted Stop verification (§7.2). |
| **Host Obligation**   | Records the event after schema and uniqueness validation (no signature check). | MUST verify signatures, reject invalid ones, and detect `signer_seq` gaps.                                    |

Level 2 provides evidentiary strength to the audit record (non-repudiation and detection of lost events); it does not imply authorization of the domain action.

The level is one of two independent axes. It states how strongly a tool's attestation resists forgery, and says nothing about who recorded it; §5.2 carries that second question. On each axis the party that performs the obligation declares what it does, and the other declares what it needs.

### 5.1 Signature algorithms and key binding

A Level-2 `signature` is a detached signature over the canonical event (§8.2), produced by an algorithm bound to the `key_id` by the out-of-band key registry, not carried in the event. This version defines two algorithms. Their identifiers are the fully-specified JOSE algorithm names [RFC-9864] [RFC-7518], and each produces a fixed-length raw signature:

- **`Ed25519`** - EdDSA using the Ed25519 parameter set: PureEdDSA over Curve25519 [RFC-8032] (not Ed25519ph/ctx), encoded as the raw 64-byte signature. This is the fully-specified identifier [RFC-9864] registers; the polymorphic JOSE identifier `EdDSA`, which that document deprecates, is not an identifier of this specification.
- **`ES256`** - ECDSA using P-256 and SHA-256 ([RFC-7518] §3.4, [FIPS-186-5]), encoded as the fixed-length `r || s` form (*not* ASN.1/DER): `r` and `s` are each the 32-byte big-endian, left-zero-padded unsigned integer, concatenated to 64 bytes. A verifier MUST accept both low-S and high-S signatures (no low-S normalization is required, since signatures are verified, not reproduced).

The `signature` field MUST be the base64url encoding of these raw signature bytes without padding ([RFC-4648] §5, as [RFC-7515] §2 uses it), so that a signature is written the way JOSE writes one, and a key (§5.1's registry entries are commonly exchanged as JWKs [RFC-7517]) and a signature are encoded alike. The normative schema pins the field to `^[A-Za-z0-9_-]+$`. A `signature` that is not decodable under that encoding, or that decodes to the wrong length for the bound algorithm, is treated as a failed verification and rejected as `signature-invalid` (§7.6), not `schema-invalid`. The schema sets no maximum length on `signature` (or other string fields); bounding message size against oversized-input resource exhaustion is a transport/SDK responsibility (§7.3), not a canonicalization concern.

**Key registry.** The registry is provisioned out-of-band at onboarding and is deployment-specific, but its entries have a normative shape: each maps a non-empty `key_id` to exactly one algorithm identifier from the set above and one public key, and that public key MUST be a key of that algorithm. An entry whose key and algorithm disagree - a key on another curve, or key material of the wrong length - is not a conforming entry, and every implementation that loads a registry MUST refuse it when it loads it, not carry it to verification time: every event bound to it would then fail to verify and be rejected `signature-invalid` (§7.6), which names a forged signature - a different fact from a misprovisioned registry, and one that sends an operator looking for the wrong thing. Because the event carries no algorithm field, a host selects the verifier from the `key_id`'s registry entry, which lets one host verify a heterogeneous fleet - Ed25519 tools alongside KMS-hosted ES256 tools - without an in-band algorithm negotiation. A `key_id` with no registry entry is rejected as `unknown-key` (§7.6). New algorithm identifiers are added only by a future version of this specification (§12). Key rotation and revocation are covered in §10.9.

### 5.2 Countersignature

A Level-2 chain that carries no countersignature is strongly signed and independently unconfirmed; a Level-1 chain that carries one is weakly signed and independently confirmed. These are different properties, so this specification keeps them on separate axes rather than folding one into the other.

The **countersignature** axis states what a record carries, not who the parties were:

| Countersignature       | What the record establishes                                                                                                                                                                                                                                       |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| absent                 | Only the tool's own attestation stands behind the record (§10.2). Whether a separate host sealed it and declined to countersign, or the tool acted as its own host (§6.2), is not determinable from the record - and the record establishes no more either way. |
| present, and verifying | The host named by `host_key_id` confirmed sealing this record, at this position in the ledger named by `log_id`, with a **countersignature** made with a key the verifier's registry binds to that host (§7.1).                                                  |

The capability values `none` and `host` (§6.1) declare which of these a participant provides or requires. They are declarations of policy; the record's own state is the row above, and a verifier reads it from the record alone (§11.4).

**A countersignature is established per record, by evidence, never by declaration.** A record is countersigned when it carries a `host_signature` that verifies against the `host_key_id`'s registry entry, and is uncountersigned otherwise. A tool cannot manufacture the countersigned state, because it holds no key the verifier's registry binds to a host. This holds as long as the tool does not control the verifier's registry. Where one operator controls both, the distinction is administrative rather than cryptographic and §10.2 applies to the whole chain; separating registry control from tool operation is the deployment condition under which the countersignature axis is evidence.

**A countersignature is not a witness cosignature.** In transparency-log practice a witness is a party independent of the log's operator that cosigns what the operator published [C2SP]. Here the signing party *is* the operator of the ledger, laying its signature over a record whose event another party authored - the relationship [RFC-9338] names a countersignature. A deployment that wants the independent sense adds it over the anchored tail (§8.3, §9).

A participant declares its position on this axis in the capability object (§6.1): a host declares `host` when it countersigns, and a tool declares `host` when it requires a countersignature. The declaration tells each side what to expect; it is not evidence. A tool that requires a countersignature enforces the requirement at runtime (§7.2), exactly as a host enforces the level at runtime (§7.1).

The countersignature axis does not alter the record hash. The countersignature is computed over the sealed record's host-assigned fields and stored alongside them (§7.1), outside the §8.2 preimage, so a chain sealed without a countersignature and the same chain sealed with one produce identical `record_hash` values.

## 6. Protocol

Auditable MCP requires tool-to-host communication while a `tools/call` is being processed. This section defines that exchange once, independently of the MCP wire, and §6.4 and §6.5 bind it to MCP protocol versions. The audit exchange is deterministic and does not employ human-in-the-loop semantics: the host's audit subsystem processes it automatically and never waits on human input to decide. (Human-in-the-loop consent MAY occur where the orchestrator decides whether to admit a tool (§6.1), never within the per-event audit exchange. Under §6.4 a round that also carries the tool's own `inputRequests` returns its Attempt Responses on the client's retry, which comes when the client has its answers; the delay is the call's, not the audit subsystem's.)

**Scope of these obligations.** This section defines the exchange for an *audit-negotiated call* - one for which both parties declared this extension and the capability comparison succeeded (§6.1), and for which the host issued an audit session (§6.3). For any other call the tool sends no audit message at all and serves the call as an ordinary MCP tool; §6.2 is normative for that case. In particular, the fail-closed rules below MUST NOT be triggered by a peer that never declared the extension.

The exchange carries two kinds of message:

- **Attempt:** tool to host, sent immediately before an internal operation, carrying an event with the `outcome` set to `attempted`. It is strictly an audit recording request, not an authorization request. The host answers it with an Attempt Response (§7.1). The tool MUST NOT perform the operation unless the response is `accept`. Bounding the wait is a binding/SDK responsibility. The host rejects an attempt only when ledger integrity cannot be guaranteed (e.g., invalid signatures or sequence violations); if the host cannot durably record it, it answers `unavailable`.
- **Outcome:** tool to host, reporting how the operation resolved, carrying an event with the `outcome` set to `success`, `failed`, or `aborted`. It has no response.

**Every audit-layer decision is an Attempt Response.** Accept, reject, and unavailable are normal, well-formed audit outcomes the tool branches on (§7.2), not protocol faults, and every binding carries them as an Attempt Response, never as a protocol error. A tool that receives a protocol error, no answer within its bound, or an answer that does not validate against the Attempt Response schema (§7.1) - including an `accept` carrying some but not all of the countersignature fields - in place of an Attempt Response MUST treat it as a failure to record, exactly as for `unavailable`.

**At most once.** A tool MUST NOT perform an operation more than once, whatever number of `accept`s reaches it for it: an attempt sent again (§7.1) is answered again, and a binding can deliver an answer late or twice (§6.4, §6.5). A tool that treated an attempt as unanswered and aborted it MUST NOT act on an `accept` for it that arrives afterwards.

**Order.** The events of one audit session reach the host in the order the tool emitted them, and the host processes them in that order. Under Level 2 that is the order of `signer_seq` (§7.4), except for an attempt the tool sends again (§7.1), which keeps the `signer_seq` it was first sent with.

**Outcomes precede the result.** A tool MUST deliver the outcome of every operation of an audit session no later than the result of the `tools/call` that the session belongs to. The call's end is the one point the host observes directly, because the host issued the call; §6.3 uses it to detect an attempt that was never resolved.

**Invalid outcomes.** Because an outcome has no response, the host cannot `reject` it. A host that receives an outcome failing the validation of §7.2 MUST NOT seal it, and MUST record the failure in its anomaly set under the Tier-1 anomaly kind for the condition (§7.6): `schema-invalid` for a structural or numeric-domain failure, `signature-invalid` for a missing or failing signature or an unknown key, and `replay-detected` for a session or sequence failure or a second, different outcome for one operation (§7.2); a `success` or `failed` outcome with no preceding accepted attempt is `orphaned-outcome` (§7.2). From the tool's perspective it is silently dropped. An outcome carrying `attempted` is invalid and dropped.

States such as `denied` (Boundary-level allowlist rejection) and `expired` (abandoned or timed-out execution) are host-side lifecycle concepts. A tool-internal event never carries these states.

### 6.1 Capability negotiation

Auditable MCP is an MCP extension in the sense of [SEP-2133]. Each party declares it under the `extensions` member of its capabilities - `ClientCapabilities` for the host, `ServerCapabilities` for the tool - keyed by the extension identifier:

```
com.timberlandchapel/auditable-mcp
```

The value at that key is the capability object, serving as this extension's [SEP-2133] settings object. The host declares the audit capability it requires; the tool declares the audit capability it supports. Both use the [`schema/audit-capability.schema.json`](schema/audit-capability.schema.json) object. Where the declarations travel is a property of the MCP protocol version and is defined by its binding (§6.4, §6.5); what they contain and how they are compared is defined here, once.

**The comparison is made per call.** A tool compares the host's declaration in effect for a `tools/call` with its own before it serves that call, and a call is audit-negotiated only when that comparison succeeded (§6.2). Under a binding whose declarations accompany every request (§6.4) the comparison is made on every call, against the declaration the call's first request carries, and its result holds for the whole call; under a binding that exchanges them once for an MCP session (§6.5), the result of that exchange is in effect for each call in it. Either way one call has one result: an audit session is negotiated or it is not, from its first event to its last. Both parties compute the whole comparison, on both axes: each has the other's declaration, and §6.2 puts the obligation to act on an unnegotiated call on the tool, which it cannot discharge from one axis.

**Identifier and version.** The identifier names the extension; `spec_version` names the wire version. [SEP-2133] requires a breaking change to take a new identifier, and defines one as a modification that would cause existing compliant implementations to fail or behave incorrectly. A `spec_version` change does not meet that definition here: the field is REQUIRED in the settings object and is compared before any audit message is exchanged, so an implementation built against an older revision neither fails nor behaves incorrectly - it declines to negotiate, visibly (§6.2). This extension also advertises itself as experimental below 1.0, as [SEP-2133] contemplates an extension doing: its wire contract may change between draft revisions, and `spec_version` is how a peer detects that. A modification that could instead leave an older implementation running incorrectly would take a new identifier.

The host enforces its own required `level` at runtime (§7) regardless of what the tool offers: when the host requires Level 1 and the tool offers Level 2, the host still validates only at Level 1 (it does not demand signatures); when the host requires Level 2, the host validates every event at Level 2. The offered level only decides whether the call is audit-negotiated (below).

**The countersignature axis runs the other way.** On the `level` axis the tool produces and the host requires; on the `countersign` axis (§5.2) the host produces and the tool requires. A host declaring `host` offers to countersign; a tool declaring `host` requires a countersignature. A host declaring `none` therefore cannot satisfy a tool that requires `host`, and that is knowable before any audit message is exchanged: the comparison fails, exactly as a level shortfall does. A tool declaring `none` imposes no requirement, and a host declaring `host` countersigns whatever the tool asked for. What differs is enforcement at runtime: the host enforces the `level` it requires on every event (§7.1), and the tool enforces the countersignature it requires on every `accept` (§7.2). Each party enforces the axis on which it is the one requiring.

The capability object declares the operational parameters of the audit subsystem. `spec_version`, `level`, `attempt`, and `countersign` are all REQUIRED.

| Field          | Type   | Presence | Notes                                                                                                                                                                                                                                                                                      |
| -------------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `spec_version` | string | REQUIRED | The Auditable MCP version the participant supports (e.g., `auditable-mcp/0.3`). Establishes a common version before any event, which carries `spec_version` (§4), is exchanged.                                                                                                              |
| `level`        | string | REQUIRED | MUST be `"L1"` or `"L2"`. The negotiated assurance level.                                                                                                                                                                                                                                  |
| `attempt`      | string | REQUIRED | MUST be `"request"`. An attempt is answered before the tool acts, and the tool fails closed without the answer. A single permitted value in this version; it is a forward-compatibility placeholder reserving the field for a future non-blocking mode.                                    |
| `countersign`  | string | REQUIRED | MUST be `"none"` or `"host"` (§5.2). `"host"` means sealed records carry a countersignature - a host declaring it will countersign, a tool declaring it requires one. `"none"` means they do not. Unlike `level`, the obligation on this axis falls on the host, so the roles of requirement and offer are reversed. |

When either participant's declared `spec_version` is not mutually supported, or a tool's declared `level` does not meet the host's requirement (e.g., the host requires Level 2 but the tool supports only Level 1), or the host's declared `countersign` does not meet the tool's requirement, resolving the mismatch is an orchestrator or SDK implementation responsibility. The orchestrator MAY decline to call the tool, or it MAY seek human-in-the-loop consent to admit the tool at a lower assurance level and record that decision in its allowlist. Whatever the orchestrator decides, a call is unnegotiated until a comparison succeeds, so §6.2 governs the tool: it sends no audit message in the meantime. A decision to admit a tool at a lower assurance level takes effect by the parties declaring capabilities that fit and comparing again, never by an out-of-band override of a comparison that failed - *negotiated* always means a comparison succeeded, which is what keeps the tool's rule mechanical.

A tool might falsely declare a higher capability than it possesses. The protocol does not verify a declaration's truthfulness during negotiation. Instead, the host enforces its required level at runtime (§7). If a tool fails to emit events compliant with the enforced level - for example, omitting a signature under Level 2 - the host's runtime validation rejects those events. Consequently, ledger integrity holds irrespective of the initial declaration.

### 6.2 Graceful degradation

Where one party supports an extension and the other does not, [SEP-2133] requires (MUST) that the supporting party either revert to core protocol behavior or, for a mandatory extension, reject the request, and recommends (SHOULD) that the extension document its expected fallback behavior. This section is that document.

A `tools/call` is **audit-negotiated** when both parties declared the extension identifier (§6.1), the resulting capability comparison succeeded, and the call carries an audit session the host issued (§6.3). Every other call is **unnegotiated**: the peer declared no `extensions` member, or declared other extensions but not this one, or declared it with a `spec_version`, `level`, or `countersign` that does not fit (§6.1), or issued no audit session for the call.

**For an unnegotiated call a tool MUST NOT send an attempt or an outcome.** A host that did not declare this extension has not agreed to receive them. Under §6.5 an ordinary MCP host answers an undeclared method with a protocol error, which §6 requires the tool to read as a failure to record; under §6.4 an ordinary host has no way to answer an attempt at all. A tool that sends regardless therefore fails closed against a peer that has done nothing wrong, and is unusable with ordinary MCP hosts. The obligation rests on the tool because only the tool computes the comparison for the call it is about to serve.

**A tool MUST serve an unnegotiated call as an ordinary MCP tool.** Its `tools/list` and `tools/call` behavior, and the content of its results, MUST NOT differ from a build without this extension. Auditable MCP adds to what a tool reports about itself; it never changes what the tool does.

**Postures.** How a tool spends an audit obligation it can no longer discharge against the host is an operator configuration, established out-of-band and not negotiated on the wire. Two postures are admissible, and the degraded posture is RECOMMENDED as the default:

| Posture       | On an unnegotiated call                                                                                                                         | When to choose it                                                                                                                                 |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Degraded**  | Serve the call, and record the internal operations into an audit host the tool provides for itself, applying §7 unchanged and issuing its own audit session (§6.3). | The tool stays usable by every MCP host, and its interior is still recorded.                                                                      |
| **Mandatory** | Refuse to serve, as [SEP-2133] permits for a mandatory extension.                                                                               | Deployments where a record the host never saw has no value - for example where the operator's obligation is discharged only by the host's ledger. |

**A tool in the degraded posture SHOULD make that state observable to its operator** - through a log record, a metric, a startup banner, or whatever channel the deployment already watches - so that the absence of a host's countersignature is noticed rather than merely discoverable after the fact. Alerting personnel, and deciding what else to do about an audit failure, is an organizational control rather than a protocol behavior ([NIST-SP-800-53] AU-5); this specification requires only that a tool not conceal the state from the operator who owns that control.

AU-5(4) invokes a full shutdown, a partial shutdown, or a degraded operational mode on an audit logging failure, *unless an alternate audit logging capability exists*. The two postures here sit on opposite sides of that rule: the degraded posture is the alternate capability, and the mandatory posture is the invoked response. The word *degraded* is this specification's own and denotes continuing to serve; AU-5's "degraded operational mode" denotes reduced functionality, which is the opposite side of the same rule.

**A tool MUST NOT take a third posture, in which it serves an unnegotiated call, records nothing, and reports nothing about the omission.** That combination restores the opaque interior of §1 while the tool continues to advertise this extension to hosts that ask.

**A self-hosted chain carries no independent confirmation.** A tool acting as its own host issues and records the same chain, so no record in it is confirmed by a second party; §10.2 governs what such a chain does and does not establish. A verifier tells such a chain from one a distinct host confirmed by the countersignature alone (§5.2, §11.4).

### 6.3 Audit session

An audit session is the scope of one `tools/call` (§3). It is what an event's `session_id` names, what `signer_seq` counts within (§7.4), and what the host closes when the call ends.

**The host issues it.** For each `tools/call` it wants audited, the host MUST issue a fresh `session_id` - a UUID [RFC-9562] that it has not issued before, not even for a session that has since ended, of a version from 1 to 8 and SHOULD be version 4 or 7 (so neither the nil nor the Max UUID) - and send it with the call as its binding specifies (§6.4, §6.5). Under a binding in which one call is carried by several requests (§6.4), every request of the call carries the same `session_id`. A call the host sends without a `session_id` is one it did not ask to audit, and is unnegotiated (§6.2).

**The tool carries it.** A tool MUST set every event it emits while serving an audit-negotiated call to that call's `session_id`, verbatim.

**The host checks it.** A host MUST reject, as `replay-detected` (§7.6), an attempt whose `session_id` is not the audit session of the call it arrived on, and MUST NOT seal an outcome whose `session_id` is not; a session that has ended accepts nothing further. Each binding defines which call an event arrived on (§6.4, §6.5). Because `session_id` is inside the signed and hashed event, an event emitted for one call cannot be presented as belonging to another - at this host, at another host, or in another partition.

**The call's end closes it.** An audit session ends when its `tools/call` ends: with its result, with a protocol error, or with its cancellation; each binding defines that moment (§6.4, §6.5). The host processes any events the result carries before the session ends. At that point every outcome of the session has been delivered (§6), so an attempt the host accepted in it that has no sealed terminal outcome is one the tool never resolved. The host MUST record it in its anomaly set as `unresolved-attempt` (§7.6). A host that stops - a restart, a crash - ends every audit session it had open, since no call it issued can continue across it; a host resuming its chain records `unresolved-attempt` for each attempt so left. The record is the host's: it is not sealed into the chain, and a verifier reading the ledger alone cannot produce it (§10.8, §11.4).

**The degraded posture.** A tool acting as its own host (§6.2) issues the `session_id` for each call itself - never one a peer sent with the call - and applies this section unchanged.

A session is recorded into exactly one partition (§3). The partition is chosen by the host and is not visible on the wire.

### 6.4 Binding: MCP protocol version 2026-07-28

This binding applies where the call is made under MCP protocol version `2026-07-28` [MCP-2026-07-28], which has no initialization handshake, carries a client's capabilities on every request, and carries server-to-client interaction within a request through Multi Round-Trip Requests [MCP-MRTR]. It defines no new JSON-RPC method: the exchange rides the `tools/call` itself, in `_meta` members keyed by the extension identifier, which is how [SEP-2133] and MCP reserve `_meta` for extensions.

**Declarations.** The tool declares its capability object in the `server/discover` result, under `capabilities.extensions`. The host declares its capability object on every request, under `extensions` in the client capabilities MCP carries in the request's `_meta` (`io.modelcontextprotocol/clientCapabilities`). A tool MUST make the §6.1 comparison for a `tools/call` against the declaration the call's first request carries, and MUST NOT carry the result over to another call. Every further request of the call - each retry (below) - is served under that result, whatever it declares: the host declared once for the audit session, and a declaration that changed mid-session would leave part of the session under terms the other part was not. A host SHOULD read the tool's declaration from `server/discover` before it calls a tool it audits, so that a mismatch is known to the orchestrator before the call rather than after it.

**Session.** The host sends the audit session in the `tools/call` request's `params._meta["com.timberlandchapel/auditable-mcp"]`, an object with a `session_id` member (the request-side object, [`schema/audit-request-meta.schema.json`](schema/audit-request-meta.schema.json)). Every request of the call carries it. An event arrives on the call whose round carried it; a retry that carries another `session_id`, or none, answers none of the call's attempts, and the tool treats every attempt it was waiting on as unanswered (§6).

**Attempt.** A tool that has an attempt to send ends the current round of the call with an `InputRequiredResult` [MCP-MRTR] (a result whose `resultType` is `input_required`) that carries, in its `_meta["com.timberlandchapel/auditable-mcp"]`, the result-side object ([`schema/audit-result-meta.schema.json`](schema/audit-result-meta.schema.json)): the `session_id` and an `events` array holding every event the tool has emitted since its previous round, in emission order - the pending attempts, and any outcomes. The `InputRequiredResult` MUST carry a `requestState`, which is how the tool resumes on the retry; `requestState` is the tool's alone, is protected as MRTR requires, and carries nothing the host reads. It MAY also carry `inputRequests`, which are independent of this exchange.

**Attempt Response.** The host processes the `events` in array order and one at a time - each attempt under §7.1, each outcome under §7.2 and §8.3; an item that is not a valid event is refused as that event alone would be (an attempt is answered `schema-invalid` under its `id` where it carries one, and otherwise the failure is recorded as `schema-invalid` in the anomaly set), and does not affect the others - and then retries the `tools/call` as MRTR specifies (the same request, a new JSON-RPC id, `requestState` echoed), carrying in the retry's `params._meta["com.timberlandchapel/auditable-mcp"]` the same `session_id` and a `responses` object that maps the `id` of every attempt in the preceding `events` to its Attempt Response (§7.1). A host SHOULD retry whatever the responses are, so that a tool whose attempt was refused can conclude the call; MRTR does not oblige a client to retry, and a tool whose retry never comes performs none of the operations it asked to record. A tool MUST treat an attempt the retry does not answer as unanswered (§6). Because the tool can reply to its caller only on a retry, a host SHOULD bound the whole of a round's processing by one deadline and retry when it passes, answering `unavailable` to every attempt it has not decided by then, rather than hold the retry - and with it the call's result - for as long as its audit subsystem takes. An attempt the audit subsystem takes up only after the deadline is not decided at all - nothing is recorded for it, since the call it belongs to may already have ended - while a decision already under way is not undone, and the tool, told `unavailable`, does not act on it (§7.2); outcomes not yet sealed at the deadline are sealed after the retry is sent. For the same reason a host does not hold the call's final result from its caller while it seals the outcomes that result carries.

A host SHOULD remove this extension's member from a result's `_meta` before passing the result to its caller: the events are the host's audit input, and the caller would otherwise see the audit of a call it asked for as an ordinary tool call - including any cleartext `action_context` (§4.3).

A tool that concluded a call while a round was still out keeps its final answer, and the outcomes it has not delivered, until that round's retry arrives, and answers the retry with them; a retry that comes late is not a replay.

**Outcome.** An outcome travels in the `events` of the tool's next `InputRequiredResult`, or, for the outcomes that remain when the tool concludes the call, in the `events` of the result-side object in the final result's `_meta`. A final result MUST NOT carry an attempt, since no retry follows it to carry a response. A call that concludes with a JSON-RPC error has no result to carry them in: a tool with outcomes remaining ends one more round with an `InputRequiredResult` whose `events` hold only those outcomes, and answers the retry with the error.

**At most once.** A tool MUST NOT perform an operation before the retry carrying its `accept` arrives, and performs it at most once (§6). A client can replay a `requestState` (MRTR requires a server to treat it as attacker-controlled), and a replayed retry - including one that arrives after the tool has concluded the call - MUST NOT cause any part of the call to run again; the tool records server-side which rounds it has consumed, as MRTR requires for any state that must be consumed at most once, and answers a replayed one with a JSON-RPC error.

**Round affinity.** MRTR lets a server keep nothing between rounds, carrying what it needs in `requestState` [MCP-MRTR]; this binding does not require that, and a tool that keeps a call's state between rounds keeps it where it performs the call's operations. Where this binding is carried over the Streamable HTTP transport [MCP-HTTP], every request of an audited call - the `tools/call` that opens the session and each retry - MUST carry the HTTP header `Auditable-Mcp-Session`, whose value is the request's `session_id`. It mirrors a body field into a header as MCP's request metadata headers do, so that an intermediary can route a call's requests without parsing the body, and as with those headers the body is the source of truth: a tool that processes the body MUST reject a request whose `Auditable-Mcp-Session` header is absent while the body carries a `session_id`, present while it carries none, or different from it, with HTTP `400 Bad Request` and the JSON-RPC error `-32020` (`HeaderMismatch`). A retry is the same request, so it also carries every request metadata header MCP requires of the request it repeats (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, and each `Mcp-Param-{Name}`). An intermediary between host and tool MUST pass `Auditable-Mcp-Session` through unchanged; one that removes it leaves every audited call it carries refused. A tool whose deployment serves a call's requests from more than one instance, and keeps the call's state in one of them, MUST deliver every retry of the call to that instance - by an intermediary that routes on `Auditable-Mcp-Session`, or by forwarding from the instance that receives it. Any request of an audited call that carries a `requestState` is a retry, whether it answers this extension's round or one of the tool's own [MCP-MRTR]; an instance that receives one for a round it neither holds nor can forward refuses it as it refuses a replay, performing nothing, and never serves it as the call's first request. A request without a `requestState` that carries the `session_id` of a call the tool already holds is not a retry and is refused likewise, since the host issues a fresh `session_id` for every call (§6.3). A tool that forwards SHOULD make every `requestState` it issues for an audited call - its own rounds' as well as this extension's - identify the instance that holds the round. Since `requestState` then selects which held state a retry resumes, and where it is forwarded, a tool MUST ensure that altering it can cause nothing worse than the request's failure - the state is found only by a value the client cannot guess, and a retry is forwarded only to an instance of the tool's own deployment - or else protect its integrity as MRTR requires. A tool that knows the authenticated principal of a request SHOULD bind each round to the principal of the request that opened the call, and refuse a retry that another principal presents [MCP-MRTR]. The header authenticates nothing: an intermediary that routes on it is trusting the body to agree, which is what the tool's check establishes.

**The call's end.** Between rounds no request of the call is in flight, so the host, which holds the next move, decides when the call ends. The audit session ends (§6.3) when the host has received a result that is not an `InputRequiredResult` and processed the events it carries, when it receives a JSON-RPC error for the call, when it cancels the call, or when it decides not to retry a round; a host that does not retry a round MUST end the session at that point. A host that ends a session without retrying a round in which it rejected an attempt leaves that attempt's `aborted` outcome undelivered, and a verifier then reports the attempt's `signer_seq` as unaccounted (§11.4); this is one reason the host SHOULD retry.

**Tasks.** This version does not bind the exchange to a task-augmented `tools/call`. A host MUST NOT request task augmentation for a call it audits, and a tool that receives a task-augmented `tools/call` MUST treat it as unnegotiated (§6.2).

### 6.5 Binding: MCP protocol versions with an initialization handshake

This binding applies where the call is made under an MCP protocol version that has the `initialize` handshake and server-initiated requests - protocol versions up to and including `2025-11-25`.

**Declarations.** Each party declares its capability object in the `initialize` exchange - the host in the `capabilities` of its `initialize` request, the tool in the `capabilities` of its result - under the `extensions` member [SEP-2133]. The comparison is made once for the MCP session, and its result is in effect for every call in it (§6.1).

**Session.** The host sends the audit session in the `tools/call` request's `params._meta["com.timberlandchapel/auditable-mcp"]`, exactly as under §6.4. An `audit/attempt` or `audit/outcome` arrives on the `tools/call` it is related to, where the transport relates requests; where it does not (stdio), it arrives on one of the calls in flight on the same MCP connection, and the host MUST treat an event whose `session_id` it did not issue for a call in flight on that connection as not the call's (§6.3).

**Attempt.** `audit/attempt`, a JSON-RPC request from the tool to the host, sent as a request related to the `tools/call` it serves (on transports that relate requests, on that call's stream). Its `params` member IS the audit event object (§4) directly - not a wrapper object. Its result is the Attempt Response (§7.1). The tool MUST await the result before it acts on the operation.

**Outcome.** `audit/outcome`, a JSON-RPC notification from the tool to the host, whose `params` member is the audit event object. JSON-RPC batching MUST NOT be used for either message: MCP removed it in protocol version `2025-06-18` [MCP-2025-06-18], and a batched attempt would defeat audit-before-act.

**Errors.** A JSON-RPC `error` in answer to `audit/attempt` is a protocol fault, not an Attempt Response (§6). JSON-RPC `error` responses are reserved for transport- and protocol-level faults (unparseable message, unknown method, malformed envelope).

**The call's end.** The audit session ends (§6.3) when the tool sends the `tools/call` response, or when the host cancels the call. Because `audit/outcome` is a notification, a tool MUST send every outcome of the session before it sends that response (§6).

## 7. Host behavior and tool obligations

The host's audit subsystem is a deterministic recording engine. It does not authorize domain actions; it strictly validates ledger integrity requirements (§5) before sealing records.

### 7.1 Attempt processing

Upon receiving an attempt, the host MUST perform the following validations before sealing:

1.  **Structural Validity:** The event MUST conform to the shared schema, `outcome` MUST be `attempted`, and every value MUST lie in the canonicalization domain (§8.1). An event failing any of these is rejected, not sealed.
2.  **Session:** The event's `session_id` MUST be the audit session of the call the attempt arrived on (§6.3); otherwise the attempt is rejected as `replay-detected`.
3.  **Cryptographic Integrity (Level 2):** If the negotiated level is Level 2, the host MUST verify the `signature` against the registered public key for the `key_id` (§7.4).
4.  **Uniqueness and idempotency (both levels):** If the partition already holds a sealed attempt with the same `id`, the host MUST NOT seal a second record for it. If the received event is byte-identical to the sealed one in canonical form (§8.1), the host MUST answer with the Attempt Response it gave when it sealed that record - the same host-assigned fields, and the same countersignature if it gave one - and this attempt is otherwise not processed further. If the two differ, the attempt is a replay and is rejected as `replay-detected`. An attempt whose `session_id` and `id` already have a sealed outcome - the operation has concluded, whether or not its attempt was ever accepted - is likewise rejected as `replay-detected`, so no attempt is sealed after its own terminal record. The byte-identical check comes first: a repeat of a sealed attempt is answered from the ledger whether or not its operation has concluded, since it seals nothing and §6 keeps the tool from acting twice. The terminal outcome reuses its attempt's `id` as the correlation key (§4) and is not subject to the first of these checks.
5.  **Sequence Verification (Level 2):** The `signer_seq` MUST NOT be a value the host has already decided for that `key_id` in that audit session (§7.4); one that is is rejected as `replay-detected`. A value that skips ahead is accepted and flagged.

If validation passes, the host seals the record into the ledger (§8) and replies with `status: "accept"` and the host-assigned `seq`, `host_ts`, `previous_hash`, and `record_hash` (see Verifiable Accept below). If validation fails it replies `status: "reject"` with the Tier-1 `reason` (§7.6). If it cannot durably record the event, it replies `status: "unavailable"`.

**Idempotent retry.** Rules 4 and 5 are what make an attempt safe to send twice. A tool that received `unavailable`, or no Attempt Response at all (§6), MAY send the byte-identical attempt again in the same audit session. If the first copy was sealed, the second receives the original `accept`; if it was not, the second is processed as the first would have been, whatever the host decided for other attempts of the session in between, because its `signer_seq` is one the host has not decided (§7.4). This is the retry discipline of an idempotent producer: a duplicate with the same content returns the original result rather than a new one or an error. A tool MUST NOT send, under an `id` it has already sent, an event that differs from the one it sent; the host cannot tell that from a replay, and rejects it as one.

**Atomic sealing.** A host MUST assign `seq` and `previous_hash`, seal the record, and commit it to the partition's chain atomically with respect to every other record being sealed into the same partition (§10.5). Two seals that interleave read the same chain tail, and the host issues two records claiming the same predecessor and the same `seq` - a broken chain it has already answered `accept` for twice, so the operations it cleared proceed on records the ledger cannot hold. The obligation falls on the host because no other party can detect the condition: each `accept` is individually well-formed and passes Polluted Stop (§7.2), and the break surfaces only later, to a verifier reading the chain (§11.4). Stated as the ledger shows it: no two records in one partition may carry the same `seq`, and none may carry the same `previous_hash` as another.

This constrains the property, not the mechanism. A host MAY serialize seals with a per-partition lock, elect a single writer per partition, or commit under an isolation level that aborts and retries a seal that interfered with another. A host that cannot complete a seal atomically has not recorded the event and MUST reply `unavailable` rather than seal it anyway; failing to record is a state this protocol already carries (§7.2), and a chain break is not. Nothing here constrains ordering *across* partitions, nor which of several concurrent attempts takes the earlier position - only that they take different ones, linked in the order they took them. Where an order is already pinned, it still holds: the events of one session are processed in the order the tool emitted them (§6).

Nothing here constrains the tool's concurrency. An attempt blocks the operation that sent it, not the tool; a tool MAY have several operations in flight, in one call or in many, and a host that seals atomically serves them all. Their records are ordered; their operations are not. Under Level 2 the tool carries an obligation of the same shape at its own end - §7.4 requires it to number and emit atomically within an audit session - so concurrent operations of one call leave in one order.

A log that answers a submission with a promise rather than a position can defer this. [RFC-9162] returns a Signed Certificate Timestamp and allocates the tree index later, within its Maximum Merge Delay, and [SCITT] states the append-only property of the verifiable data structure without constraining how concurrent registrations reach it. Auditable MCP cannot defer it: the Verifiable Accept hands the tool its position at the moment of the reply, because the tool reconstructs the preimage from `seq` and `previous_hash` to perform Polluted Stop (§7.2) *before* it acts. A protocol that returns the position owes the guarantee that the position is the record's own.

**Verifiable Accept:** On an `accept` response, the host MUST return the full set of host-assigned fields required for the tool to reconstruct the hash preimage (§8.2): `seq`, `host_ts`, `previous_hash`, and the resulting `record_hash`. Without these, the tool cannot perform the mandatory Polluted Stop verification (§7.2).

**Countersignature (countersign `host`).** A host that declares `countersign: "host"` (§5.2) MUST additionally return `host_signature`, a detached signature over the RFC 8785 canonical form (§8.1) of the object

```json
{
  "host_ts": "<ISO-8601 string assigned by host>",
  "log_id": "<the ledger's identifier>",
  "previous_hash": "<hex-encoded string>",
  "record_hash": "<hex-encoded string>",
  "seq": <integer>
}
```

together with the `host_key_id` identifying the signing key and the `log_id` it signed. `log_id` is a non-empty string the host chooses to name the partition's chain, stable for the chain's lifetime and distinct from the name of any other chain the host keeps; it plays the part of a transparency log's origin line [C2SP], so a countersignature names the ledger it is a statement about and cannot be presented as a statement about another. The algorithm is bound to `host_key_id` by a registry of the same normative shape as §5.1's, provisioned out-of-band; the same algorithm identifiers and the same base64url encoding apply. This signature preimage carries no signature field, so there is no self-reference, and it is not part of the §8.2 record-hash preimage: a record sealed with a countersignature and the same record sealed without one have the same `record_hash`.

A host that declares `countersign: "none"` MUST NOT return `host_signature`, `host_key_id`, or `log_id`. The response schema cannot enforce this, because the response does not carry the negotiated capability; it is a host obligation (§11.2). A host that countersigns MUST persist `host_signature`, `host_key_id`, and `log_id` alongside the sealed record, so a verifier reading the ledger later establishes the countersignature (§5.2) without the live exchange.

**Attempt Response.** The host's answer to an attempt is a JSON object forming a tagged union discriminated on `status`. Its normative schema is [`schema/audit-attempt-response.schema.json`](schema/audit-attempt-response.schema.json).

| Field            | Type    | Notes                                                                                                                                                                                                   |
| ---------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `status`         | string  | `"accept"`, `"reject"`, or `"unavailable"`. The discriminator.                                                                                                                                          |
| `seq`            | integer | REQUIRED when `status` is `"accept"`. Partition-monotonic ledger index assigned by the host (distinct from the tool's `signer_seq`, §4).                                                                |
| `record_hash`    | string  | REQUIRED when `status` is `"accept"`. Hex-encoded SHA-256 of the sealed record (§8.2).                                                                                                                  |
| `host_ts`        | string  | REQUIRED when `status` is `"accept"`. Authoritative host timestamp, ISO-8601 UTC with a `Z` suffix (no offset); it is part of the §8.2 preimage, so its exact string is hashed.                         |
| `previous_hash`  | string  | REQUIRED when `status` is `"accept"`. The preceding record's `record_hash` (64-zero genesis for the first record).                                                                                      |
| `reason`         | string  | REQUIRED when `status` is `"reject"` or `"unavailable"`. Machine-readable cause (§7.6).                                                                                                                 |
| `host_signature` | string  | REQUIRED when `status` is `"accept"` and the host declares `countersign: "host"` (§5.2); otherwise absent. Detached countersignature, base64url without padding.                                         |
| `host_key_id`    | string  | Present exactly when `host_signature` is. Identifies the host signing key and binds its algorithm via the registry.                                                                                     |
| `log_id`         | string  | Present exactly when `host_signature` is. Names the ledger the countersignature is a statement about.                                                                                                   |

`host_signature`, `host_key_id`, and `log_id` appear together or not at all. A conformant host MUST NOT return fields outside those permitted for the resolved `status`; the accept, reject, and unavailable variants are mutually exclusive.

### 7.2 Tool verification and the `aborted` state

The outcome event records the terminal state of the tool's execution lifecycle. The protocol defines four core states for `outcome`:

- `attempted` - the pre-action record carried by an attempt (§6).
- `success` - the internal action was performed and completed successfully.
- `failed` - the internal action was performed but did not complete successfully.
- `aborted` - the internal action was not performed (fail-closed; e.g., the attempt was not accepted, or Polluted Stop detected tampering).

An outcome is validated in the order an attempt is (§7.1) - structure (with `outcome` other than `attempted`), session, Level-2 signature, uniqueness (below), and sequence (§7.4) - and only then correlated. An outcome correlates to an attempt when both carry the same `session_id` and the same `id` and the attempt was sealed before it. One that passes is sealed as a record in the same partition chain (§8.3):

- An outcome that correlates to an accepted attempt is that operation's terminal record.
- An `aborted` outcome whose attempt the host did not accept - it rejected it, answered `unavailable`, or never received it - is sealed as the record of an operation the tool declined to perform. It is not a tampering anomaly (§10.4), and under Level 2 it is what accounts, in the sealed chain, for the `signer_seq` the unsealed attempt consumed (§11.4).
- A `success` or `failed` outcome that correlates to no accepted attempt is not sealed; the host MUST record it as `orphaned-outcome` in its anomaly set.

An operation has one terminal record. A host MUST NOT seal a second outcome for a `session_id` and `id` it has already sealed an outcome for: one byte-identical in canonical form to the sealed one is a repeat and is not processed further (§8.3), and one that differs is not sealed and is recorded as `replay-detected` in the host's anomaly set (§6).

**A countersigning host countersigns sealed outcome records too.** A host that declares `countersign: "host"` MUST compute a countersignature over every sealed outcome record's host-assigned fields, exactly as for an attempt (§7.1), and persist it with the record. An outcome has no response, so this countersignature is never returned to the tool; it is written into the ledger, where a verifier reads it (§11.4). Without it every terminal outcome in a countersigned chain would be uncountersigned, placing the conclusion of every operation outside what the host confirmed (§5.2).

An `aborted` outcome MUST carry a `reason`, and it MUST be the Tier-1 abort code for the condition that stopped the operation: one of `hash-mismatch`, `host-rejected`, `host-unavailable`, `host-uncountersigned`, or `host-signature-invalid` (§7.6). The event schema pins `reason` to this closed set. Because the outcome event is sealed into the ledger, its `reason` is part of the interoperable, hashed contract and admits no free-form value. Domain-specific failure detail (for a `failed` outcome, or additional context for an `aborted` one) belongs in `action_context`/`action_context_hash` (§4.3), not in `reason`.

To guarantee that the host recorded the exact event the tool emitted, the tool MAY (and under Level 2, or wherever it requires a countersignature, MUST) recompute the record hash (§8) using the host-assigned `seq`, `host_ts`, and `previous_hash`, then compare it against the `record_hash` returned in the `accept` response; this recompute-and-compare check is termed **Polluted Stop** verification. Because the host returns `record_hash` on every `accept` (§7.1) regardless of level, a Level-1 tool MAY opt into Polluted Stop; the check is OPTIONAL at Level 1 and REQUIRED at Level 2.

A tool that requires a countersignature MUST perform Polluted Stop at either level. The countersignature binds the host-assigned fields to `record_hash` and no further; it is Polluted Stop that binds `record_hash` to the event the tool emitted - its `id` and `session_id` among them. Without it, a genuine countersigned `accept` for some other record, replayed into this exchange, verifies and releases an operation that was never sealed.

The tool fails closed on any of the following, evaluated in this order:

- If the host replies with `reject`, the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "host-rejected"`.
- If the host replies with `unavailable`, or the attempt went unanswered (§6), the tool MUST NOT perform the internal action. It MAY send the identical attempt again (§7.1); once it stops trying, it MUST emit an outcome event with `outcome: "aborted"` and `reason: "host-unavailable"`.
- If the tool requires `countersign: "host"` (§5.2) and the `accept` carries no `host_signature`, the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "host-uncountersigned"`.
- If a `host_signature` is present but does not verify against the `host_key_id`'s registry entry, over the preimage built from the accept's own fields (including its `log_id`), the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "host-signature-invalid"`. A tool that does not require a countersignature MAY omit this verification; a tool that performs it MUST apply this bullet, whether or not it required a countersignature.
- If the hashes do not match (indicating ledger pollution or host compromise), the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and `reason: "hash-mismatch"`.

These conditions are listed in precedence order: the response's `status` first, then the countersignature that authenticates the host-assigned fields, then the hash computed over them. Where more than one holds, the tool MUST emit the `reason` of the first that applies, so that two implementations seal the same `reason` for the same response. The `reason` is sealed into the ledger and compared across implementations (§7.6), so leaving the choice open would make the record implementation-dependent.

### 7.3 Protocol limits and environmental enforcement

The protocol establishes the tool's obligation to halt execution - the `MUST NOT perform the internal action` of §7.2 - when an attempt is rejected, is unavailable, returns without the countersignature the tool requires, carries one the tool cannot verify, or fails hash verification. However, the Auditable MCP protocol itself operates via JSON-RPC messages and cannot physically restrain a rogue tool that violates this obligation.

Detecting and physically terminating a rogue tool (e.g., sending process kill signals, or dropping unauthorized network-layer egress traffic - distinct from the §4.2 `egress` attestation flag - via a network gateway) is outside the scope of this protocol and remains the responsibility of the host's runtime environment, orchestrator, or infrastructure.

### 7.4 Level-2 detection

Under Level 2, the host MUST verify each `signature` against a public key registered out-of-band for the `key_id`. The registry entry binds the signature algorithm (§5.1); an unregistered `key_id` is rejected as `unknown-key` (§7.6). The host MUST reject events with missing or invalid signatures.

**A sequence per key and session.** `signer_seq` counts the events a tool signs under one `key_id` within one audit session (§6.3). It starts at 0 with the first event the tool signs under that key in the session and increases by exactly one with each further event - attempts and their terminal outcomes alike, so an accepted attempt at N and its signed outcome at N+1 are contiguous. A verifier MUST count both when checking continuity. A new session starts again at 0. A tool signs every event of an audit session under one `key_id` (§10.9).

The replay rule is the anti-replay window of IPsec [RFC-4303] §3.4.3 and DTLS [RFC-9147] §4.5.1, which reject a number already received and accept one not yet seen even when it arrives out of order; here the window is the whole session, which is bounded and ends (§6.3), so the host keeps the set exactly and discards it when the session ends.

This scope is the one sequence-numbered protocols use when the numbers must detect loss and replay without the sender carrying a counter from one context to the next: a TCP or TLS connection [RFC-8446], an IPsec Security Association [RFC-4303], a Kafka producer's epoch on a partition [KIP-98], a syslog sender's reboot session [RFC-5848]. A key is long-lived and shared by every process that holds it; a session is short-lived and served by one. Numbering within the session is what lets one key serve any number of concurrent calls, processes, and hosts without their coordinating, and what lets a gap be read as a gap.

**The host's tracker.** For each `key_id` and audit session, the host keeps:

- the set of `signer_seq` values on which it has reached a decision - an event it sealed, or one it refused after its signature verified: an attempt it rejected, or an outcome it dropped (§6). An `unavailable` answer is not a decision and adds nothing, which is what lets the tool send the identical attempt again (§7.1); an idempotent duplicate answered from the ledger adds nothing either.
- the highest `signer_seq` it has received with a verifying signature, whatever it answered.

- **Replay.** The host MUST reject an event whose `signer_seq` it has already decided (`replay-detected`), except a byte-identical repeat of an event it sealed - the idempotent attempt that §7.1 answers from the ledger, or an outcome §7.2 does not process twice - which uniqueness disposes of before this check. A value it has not decided is not a replay, even when it is below one it has: that is an attempt sent again after `unavailable` while other operations of the session went ahead (§7.1).
- **Gap.** The host MUST flag a `signer-seq-gap` (§7.6) when an event's `signer_seq` exceeds the highest value received by more than one - or, for the first event it receives for a key in a session, when it is not 0. It MUST NOT reject an otherwise valid event for the gap. Within one session the tool emits in one order (below) and every event it emits reaches the host (§6), so a gap the host observes is an event the host never received.

**Atomic numbering.** A tool MUST assign `signer_seq` and emit the event atomically with respect to every other event it signs under the same `key_id` in the same audit session. `signer_seq` is the order the tool emitted in, not the order it happened to finish signing in: a tool that numbers two events 1 and 2 and emits 2 before 1 has told the host that its own event 1 is a replay, and the host - correctly, by the rule above - rejects it and records the anomaly against the tool. Where a tool signs remotely, the signing latency falls inside this section, because that is where the reordering happens.

This is the tool's half of §7.1's atomic sealing, and like it, it constrains the property rather than the mechanism. Its scope is one audit session: operations of different calls, and different processes serving different calls under one key, share nothing and need no coordination.

### 7.5 Reconciliation with governance-boundary observations

A host MAY independently observe a tool's operations and compare those observations against the tool's self-reported ledger records to detect event suppression (omissions). Because `egress` is defined against the governance boundary (§4.2), not physical network topology, a host that performs this reconciliation MUST derive its observations from a control that classifies each destination by governance scope - a Layer-7 control such as a CASB, DLP engine, or secure web gateway that distinguishes tenant-governed destinations from external ones. A raw L3/L4 network gateway does not provide a usable egress signal: it observes every call to a tenant-managed SaaS as network traffic and cannot tell it apart from an out-of-governance egress. Reconciliation looks for an observed egress to an out-of-governance destination that has no correlated self-reported `egress: true` event. The handling of the resulting reconciliation anomalies, and the concrete integration with a specific CASB/DLP control, are outside the scope of this protocol and are the responsibility of the host's runtime environment or orchestrator.

### 7.6 Reason and anomaly code vocabulary

A reject `reason` (§7.1), an outcome `reason` (§7.2), and a ledger anomaly kind (§7.4, §10) are all machine-readable codes. Because a tool branches on a reject/abort code and an independent verifier processes anomaly kinds in a ledger authored by a different implementation, an unconstrained "RECOMMENDED, extensible" vocabulary is too weak: two implementations would coin divergent strings and interoperability would fail on exactly the codes that drive control flow. This version therefore defines a two-tier vocabulary.

**Tier 1 (Normative, fixed).** The following codes are control-flow- or verification-critical. A conforming implementation MUST use these exact strings for the stated conditions, MUST NOT repurpose a Tier-1 string for a different meaning, and MUST map any Tier-2 condition onto the applicable Tier-1 code.

Host reject / unavailable `reason` codes (the host returns one to the tool; the tool branches on it):

| Code                | Meaning                                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `schema-invalid`    | The event failed structural or canonicalization-domain validation (§7.1, §8.1). The catch-all for malformed input.             |
| `replay-detected`   | A replay: an attempt `id` already sealed with a different event (§7.1), a `signer_seq` already decided for its key and session (§7.4), or a `session_id` that is not the call's (§6.3). |
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
| `host-uncountersigned`   | The tool required a countersignature and the `accept` carried none (§5.2, §7.2).                |
| `host-signature-invalid` | A countersignature was present but failed verification against the registered host key (§7.2).  |

Anomaly kinds (a verifier reads these from a possibly foreign ledger):

| Kind                     | Meaning                                                                                                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `schema-invalid`         | A sealed record fails structural or canonicalization-domain validation (a malformed record was sealed), or the host dropped an outcome that did (§6).                                                        |
| `record-hash-mismatch`   | A sealed record's recomputed hash does not match its stored `record_hash` (retroactive alteration, §10.7).                                                                                                   |
| `digest-mismatch`        | The recomputed tail digest does not match the anchored digest (§8.3, §10.7).                                                                                                                                 |
| `seq-gap`                | A gap in the host-assigned per-partition ledger `seq` (a lost sealed record, §10.7).                                                                                                                         |
| `signer-seq-gap`         | A Level-2 `signer_seq` missing within one key's sequence in one audit session (a possibly suppressed event, §7.4) - observed by the host as it decides events, or found by a verifier and not accounted for by a sealed refusal (§11.4); distinct from `seq-gap`, the host-assigned ledger index. |
| `signature-invalid`      | A sealed Level-2 record carries a signature that fails verification (§7.4), or the host dropped an outcome whose signature was missing, failed verification, or named an unknown key (§6).                  |
| `replay-detected`        | Two sealed records carry the same `signer_seq` for one key and audit session (§7.4, §11.4), or the host dropped an outcome whose `session_id` was not the call's, whose `signer_seq` it had already decided, or which differed from an outcome it had already sealed for the operation (§6, §7.2). |
| `orphaned-outcome`       | A `success` or `failed` outcome correlates to no accepted attempt of its audit session - never accepted, or after its attempt was rejected (§7.2).                                                          |
| `unresolved-attempt`     | An audit session ended with an accepted attempt that has no sealed terminal outcome (§6.3, §10.8). Recorded by the host, which observes the call's end.                                                      |
| `unreported-egress`      | Governance-boundary reconciliation saw an out-of-governance egress with no correlated self-reported event (§7.5, §10.2).                                                                                     |
| `host-signature-invalid` | A sealed record claims a countersignature it cannot back: a `host_signature` that fails verification against the registered host key, a `host_key_id` with no registry entry (§10.9), or some but not all of `host_signature`, `host_key_id`, and `log_id` present (§7.1). The absence of all three is not an anomaly; an uncountersigned record is a state (§5.2). |
| `principal-mismatch`     | A sealed record's bound identity - its `log_id`, or an enclosing record's binding - does not match the one its partition is expected to hold, or it carries no binding where the deployment requires one (§10.10). |

The Tier-1 set is a closure: every reject, unavailable, abort, and anomaly condition this specification defines maps to exactly one Tier-1 code, so an implementation always has a safe, interoperable code to emit. **Every code-valued field on the wire or in the ledger is pinned to Tier-1.** Specifically: the Attempt Response `reason` is pinned by its schema to the Tier-1 reject codes plus `internal-error` for `unavailable` (`schema/audit-attempt-response.schema.json`); the sealed outcome-event `reason` is pinned by its schema to the Tier-1 abort codes (§7.2, `schema/audit-event.schema.json`); and every anomaly `kind` a conformant verifier reports is a Tier-1 anomaly code. None carries an additional free-form field (the wire schemas are `additionalProperties: false`).

The Tier-1 codes are namespaced by the field they occupy - reject/unavailable `reason`, abort `reason`, and anomaly `kind` are three distinct code spaces - so a string such as `signature-invalid` legitimately appears both as a reject reason (a Level-2 host refusing an event) and as an anomaly kind (a verifier finding a sealed record whose signature fails).

**Tier 2 (local diagnostics only).** A finer-grained cause - for example a numeric-domain violation or a specific missing field (under `schema-invalid`), which of the three replay conditions fired (under `replay-detected`), whether an orphan was never-accepted or post-reject (under `orphaned-outcome`), or a specific storage fault (under `internal-error`) - is a **local, out-of-band diagnostic**: an implementation MAY record it in its host-side anomaly log, operator telemetry, or human-readable messages, but it is *not* carried on the wire or sealed into the ledger, which convey only the Tier-1 code. This keeps the interoperable contract (Tier-1) machine-checkable while leaving diagnostics unconstrained. If an implementation surfaces Tier-2 codes across a trust boundary (e.g., in an aggregated audit dashboard), each MUST be namespaced with a vendor prefix (e.g., `example.com/rows-exceeded`) to prevent cross-vendor collision, and MUST NOT collide with a Tier-1 string; a consumer that does not recognize a Tier-2 code MUST fall back to the Tier-1 code's semantics.

## 8. Canonicalization and hashing

The integrity of the ledger, the ability for tools to verify host responses (§7.2), and the cross-platform verifiability by independent auditors depend on a strict, deterministic serialization contract.

**Canonicalize the received structure with JCS; do not first apply any semantic normalization to field values.** Canonicalization (§8.1) is itself a re-serialization of the parsed JSON structure - that is required and deterministic. What an implementation MUST NOT do is route field values through a typed model that reconstructs and re-serializes them (parsing `id` into a native UUID, `ts` into a native datetime, or a number into a re-formatted numeric type) before canonicalizing, because such semantic normalization can silently change a value (case, zero-padding, timezone form, trailing zeros) and split the chain across implementations that would otherwise agree. Audit fields whose exact bytes are hashed SHOULD therefore be modeled as pattern-validated strings, not reconstructed typed values, so the validated value and the canonicalized value are the same string. Validating `id` and `ts` against string patterns rather than parsing them into native UUID or datetime types is how the reference implementations keep the two identical.

### 8.1 Canonical JSON serialization (RFC 8785)

Any JSON object subjected to hashing MUST be serialized according to the JSON Canonicalization Scheme (JCS) defined in **[RFC-8785]**.
This requirement provides byte-for-byte reproducibility across heterogeneous environments (e.g., differing floating-point representations), preventing false-positive ledger integrity failures.

Because JCS serializes numbers as IEEE-754 double-precision values, every numeric value in an event (including within `action_context`) MUST be finite, and every integer-valued number MUST satisfy |n| <= 2^53-1 - the interoperable range I-JSON sets for the same reason [RFC-7493]. Beyond that bound a runtime cannot distinguish an exact integer (which loses precision as a double, so one platform rounds it while another rejects it) from a float that happens to be integer-valued, so a conforming implementation MUST reject any such event rather than risk divergent canonicalization.

A conforming host MUST reject any event carrying a non-finite number or an integer-valued number with |n| > 2^53-1, before that value could be sealed. A producer MUST NOT emit such a value; a host reports the rejection under the Tier-1 code `schema-invalid` (§7.6).

Every string - member names and values alike, including within `action_context` - MUST be a sequence of Unicode scalar values: a lone surrogate, which JSON's `\u` escape can express, has no UTF-8 encoding, so JCS cannot serialize it and implementations that attempt to diverge [RFC-7493] §2.1. A host MUST reject such an event as `schema-invalid`, exactly as it rejects an out-of-domain number.

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

The `event` member is the complete audit event as sealed, byte-for-byte. **Under Level 2 this includes the `signature`, `key_id`, and `signer_seq` fields**: the `record_hash` is computed over the full signed event, so tampering with the signature after sealing breaks the chain. The `signature`-removal rule stated below applies ONLY to computing and verifying the signature itself (to avoid self-reference); it does *not* apply to the record-hash preimage, whose `event` retains `signature`. A host's `host_signature`, `host_key_id`, and `log_id` (§7.1) are the opposite case: they are not members of the preimage and not members of the `event`, so they never enter `record_hash`, which is what lets a countersigned and an uncountersigned sealing of the same record agree (§5.2).

Because the `signature` bytes are hashed verbatim, a host MUST NOT apply any cryptographic normalization - such as ECDSA low-S (malleability) coercion - to a `signature` before hashing it; the exact wire bytes MUST be used. A host that coerces `s` (or otherwise re-encodes the signature) before sealing would compute a `record_hash` divergent from the tool's Polluted Stop preimage and fork the Level-2 chain, even though the coerced and original signatures both verify. This complements §5.1's rule that a verifier accepts both low-S and high-S signatures without normalization: neither the verifying host nor the hashing host rewrites signature bytes.

The host MUST persist and re-serve the exact `host_ts` string it assigned (in the `accept` response and in the sealed record), byte-for-byte; it MUST NOT round-trip `host_ts` through a datetime type that could renormalize it (fractional digits, offset form), since `host_ts` is hashed into the preimage and any renormalization would break Polluted Stop and cross-verifier agreement. The schema pins `host_ts` to UTC `Z`.

The chain hashes (`record_hash`, `previous_hash`, and the tail digest) are bare hex (lowercase), fixed to SHA-256 by this version of the preimage construction. This differs from `action_context_hash` (§4.3), which carries an algorithm prefix (`sha256:<hex>`): the context hash is a tool-authored commitment that may need to name its algorithm as the field evolves, whereas the chain hash algorithm is version-pinned and needs no self-description. The chain hash algorithm MUST NOT vary within a `spec_version`; changing it is a new `spec_version`, never an in-band negotiation.

If Level 2 signatures are used, the signature MUST be computed and verified over the RFC 8785 canonical form of the event with the `signature` field itself removed, to prevent self-referential forgery.

This preimage is a cryptographic construct assembled locally by each party - by the host when sealing a record, and by the tool when performing Polluted Stop verification (§7.2). It is never transmitted on the wire. Unlike the wire contracts - the §4 audit event, the §6.1 Capability object, and the §7.1 Attempt Response, each bound to a JSON Schema under [`schema/`](schema/) - the preimage is defined solely by its structure in this section, with no accompanying schema. It is assembled from already-validated inputs (the `event` and the host-assigned fields) purely as input to the hash function; schema validation of the preimage is not required.

### 8.3 Ledger Chaining

The host seals a record for each accepted attempt (§7.1) and for each outcome §7.2 seals, and appends it to the partition chain in the order it seals them (advancing `seq`). An event byte-identical in canonical form to one already sealed in the partition is not sealed again: for an attempt the host answers from the ledger (§7.1), and for an outcome it does nothing further. Otherwise records are appended as they are sealed. An operation has at most one terminal record (§7.2); bounding the number of refusals a tool may have sealed in one session, and the number of rounds a host follows in one call (§6.4), to limit ledger growth is a host/SDK responsibility (cf. §7.3). Records form a tamper-evident chain by including the `previous_hash` in the preimage object. The first record in a partition uses a genesis hash consisting of 64 zeros. The `record_hash` of the tail record serves as the ledger digest, which SHOULD be anchored out-of-band to a secure medium; without a periodically anchored tail digest, truncation of a chain suffix (including a rewind to genesis) is undetectable, because a truncated prefix is internally consistent. §9 describes anchoring the tail into a SCITT Transparency Service.

### 8.4 Conformance Vectors

Golden conformance vectors are published alongside this specification under the `vectors/` directory, covering RFC 8785 canonicalization (`canonicalization.json`), per-event hashes (`events.json`), a complete sealed Level-1 chain (`chain.json`), a sealed Level-2 signed chain that hashes the `signature` into each `record_hash` (`chain-signed.json`, §8.2), a countersigned chain (`chain-countersigned.json`), the host's replay tracker (`signer-seq-replay.json`, §7.4), the verifier's accounting of `signer_seq` (`signer-seq-accounting.json`, §11.4), verifier inputs and findings - a required countersignature, an expected identity, version order, correlation order (`verifier-cases.json`, §11.4), and negative cases (`error-cases.json`): events that a conformant host MUST refuse, each paired with the expected Tier-1 code - the reject `reason` for an attempt, and the anomaly kind the host records for an outcome it drops (§6). A conforming implementation MUST reproduce the positive vectors byte-for-byte and MUST refuse each `error-cases.json` event with the pinned code.

`chain-countersigned.json` carries the same events and host-assigned fields as `chain.json`, plus the `host_signature`, `host_key_id`, `log_id`, and countersignature preimage of §7.1. An implementation MUST reproduce each record's `countersignature_preimage.canonical` byte-for-byte, and MUST produce `record_hash` values and a tail digest identical to `chain.json`'s - that identity is what holds the countersignature outside the §8.2 preimage (§5.2). Its `host_signature` values are real Ed25519 signatures that verify against the host key the vector publishes as a JWK, so the vector exercises countersignature determination (§11.4) as well as the property that the field does not enter the record hash. The `mutates` and `egress` values in the vectors are chosen for byte-coverage of the event shape, not as normative usage guidance; §4.2 is the sole source of their semantics.

## 9. Relationship to existing standards

**SEP-3004 (Tamper-Evident Audit Record Contract)**
SEP-3004 proposes a tamper-evident audit record contract for records a host's governance layers author about the call boundary [SEP-3004]. It adds no wire messages - its records are evaluated over an exported record set - and it makes emission non-blocking: a failure to record MUST NOT fail the governed operation. Auditable MCP differs on both points, by design: its records are authored by the tool about the call's interior, and they are recorded *before* the operation, which blocks on the answer. The two are complementary: an Auditable MCP record MAY be sealed inside a SEP-3004 boundary record as the underlying storage format, which is also one of the identity bindings §10.10 admits. (The proposal was closed on 2026-09-22 so that it can be carried through an MCP Working Group, not rejected; this document follows its text as last published.)

**Other MCP proposals that attest a call**
Proposals that attest a `tools/call` in MCP - Tool Outcome Attestation [MCP-TOA] is one - attach evidence to the call's result, in the result's `_meta` under the proposal's own identifier, and negotiate through the same per-request capabilities §6.4 uses; none holds the call open for a record before the operation. §6.4 uses that same placement for the events and responses of this exchange, and adds the one thing those proposals do not need: a round trip within the call, which MCP provides as MRTR [MCP-MRTR].

**SCITT (Supply Chain Integrity, Transparency and Trust)**
SCITT registers Signed Statements in a Transparency Service and returns a Receipt, a proof of inclusion in a verifiable data structure [SCITT]. The Verifiable Accept plays the part a Receipt plays in that architecture - the log's signed answer to a submission, stating where it placed it - with two differences a verifier must not overlook. What it proves is a position in a hash chain (`seq`, `previous_hash`), not inclusion in a structure a third party can audit; and it is signed only where the host countersigns (§5.2). A countersignature is therefore not a Receipt, and this specification does not call it one.

A deployment that wants the stronger property MAY anchor the ledger into a SCITT Transparency Service. The statement to register is the countersignature preimage (§7.1) of the partition's tail record - `host_ts`, `log_id`, `previous_hash`, `record_hash`, `seq` - which names the ledger and commits to everything before the tail; registered as the payload of a Signed Statement (content type `application/json`) issued under the host's countersigning key, it plays the part a checkpoint plays in a transparency log [C2SP]. The Receipt the Transparency Service returns is kept with the ledger and gives a verifier the out-of-band anchor §8.3 asks for, from a party other than the host. This specification defines the statement; the Signed Statement's envelope, the registration, and the Receipt are SCITT's [SCITT].

**Transparency-log witnesses**
In transparency-log vocabulary - [C2SP] `tlog-witness`, and Sigsum - a witness is a party independent of the log operator that cosigns what the operator published. The host's signature here is not that: the confirming party is the operator of the ledger itself, which is why this specification calls it a countersignature (§5.2). A deployment that wants independent cosigning adds it over the anchored tail (above).

**Transparency logs that answer with a promise**
A log may answer a submission with a promise rather than a position: [RFC-9162] returns a Signed Certificate Timestamp and allocates the entry's tree index later, within its Maximum Merge Delay, and [SCITT] states the append-only property of the verifiable data structure without constraining how concurrent registrations reach it. That deferral is what lets such a log sequence submissions in its own time. Auditable MCP is in the other class: the Verifiable Accept hands the tool `seq` and `previous_hash` at the moment of the reply, because the tool reconstructs the preimage to perform Polluted Stop (§7.2) before it acts. §7.1 therefore requires the host to seal atomically, which is the obligation that comes with returning the position rather than a promise.

**Sequence numbers**
The per-session scope of `signer_seq` (§7.4) is the one sequence-numbered protocols use for loss and replay detection: the sequence belongs to a context that begins and ends - a TLS connection [RFC-8446], an IPsec Security Association [RFC-4303], a Kafka producer's epoch on a partition [KIP-98], a syslog reboot session [RFC-5848] - and a new context starts a new sequence. None of them asks a sender to carry a counter across contexts. The replay rule is the anti-replay window of IPsec and DTLS [RFC-4303] [RFC-9147], which accepts a number not yet seen even out of order, rather than the strictly increasing check of a transport that never resends (TLS); a session in which the tool may send an attempt again needs the former. The idempotent retry of §7.1 is the Kafka idempotent producer's [KIP-98]: a duplicate with the same content returns the original result.

**JOSE**
The algorithm identifiers (§5.1) are the fully-specified JOSE names [RFC-9864], and signatures are encoded as JWS encodes them - base64url without padding, ECDSA as `r || s` [RFC-7515] [RFC-7518]. An implementation that already holds keys as JWKs [RFC-7517] uses them without translation.

**Cryptographic Ecosystems**
The requirement for deterministic serialization (RFC 8785) prior to hashing and detached signing (§8) is adopted from established supply-chain security and transparency frameworks (e.g., Sigstore, in-toto). This protocol uses these standard primitives rather than defining custom cryptography for the MCP boundary.

## 10. Security and Operational Considerations

### 10.1 Ledger Integrity as the Root of Trust

The host acts as the definitive authority for ledger integrity. Auditable MCP relies on the host's ability to maintain the append-only property and the hash-chain of records. Compromise of the host's ledger storage results in the total loss of auditability. Where the host countersigns, an attacker who reaches the storage but not the host's countersigning key cannot re-sign the records it rewrites, so a verifier that is told the chain must be countersigned detects the rewrite (§11.4) - the rewriter can strip a countersignature but not forge one, and a record without one is an anomaly only where one is required; the signing key is therefore a distinct asset from the ledger and SHOULD be held separately from it.

### 10.2 Limits of Self-Attestation (Omission and Misattestation)

Cryptographic signatures and sequence gaps detect _falsified_ or _lost_ records, but cannot detect an internal action a tool never reports at all (suppression by omission). This residual risk is mitigated only by out-of-band reconciliation (§7.5), which compares self-reported egress against independently observed out-of-governance egress.

A signature proves an event's authorship and integrity in transit, not the truthfulness of its content. A compromised or faulty tool can emit a validly-signed event that misdescribes the operation - a false `mutates`, `egress`, or `outcome`, or a fabricated `target_resource` (misattestation). Signature, sequence, and hash-chain verification do not detect this; reconciliation (§7.5) catches only discrepancies observable at the governance boundary (e.g., an out-of-governance egress the tool never reported). Misattestation of a within-governance, non-egress operation is a residual risk fed to allowlist governance, not a protocol guarantee.

**A record confirmed by the party that produced it adds nothing.** Where the tool and the host are one party - the degraded posture (§6.2), or any deployment in which a single operator controls the tool and the verifier's registry (§5.2) - the chain's internal consistency and its authorship both rest on that party, so no record in it is evidence against that party and the limits above apply to the chain as a whole rather than record by record. The countersignature axis exists so that a verifier can tell such a chain from one a distinct host confirmed, and §11.4 requires it to make that distinction from the record rather than from a claim.

### 10.3 Data-at-Rest Minimization

Because the host's ledger is append-only, any sensitive value written to `action_context` in cleartext is permanent and cannot be erased (e.g., conflicting with GDPR Right to Erasure). Implementations SHOULD prefer `action_context_hash` for sensitive internal context (§4.3), keeping only a verifiable commitment - not the data - in the immutable ledger.

### 10.4 Handling of Aborted Outcomes

An `aborted` outcome that references a rejected, unavailable, or never-received attempt is the tool correctly honoring its fail-closed obligation. A host MUST NOT treat it as a tampering anomaly. It seals it (§7.2), because it is a record of an operation the tool declined to perform - an audit signal in its own right - and because, under Level 2, it is what accounts in the sealed chain for the `signer_seq` its unsealed attempt consumed (§11.4).

### 10.5 Partition Isolation

A partition (§3) is a host-side isolation boundary. A host MUST maintain a separate hash chain, `seq` counter, and anomaly set per partition; records, sequences, and anomalies MUST NOT cross partitions, and a partition's chain is verifiable only against its own genesis. That separation is spatial; its temporal counterpart is the atomic sealing of §7.1, without which two concurrent seals may take the same position in one partition's chain.

`signer_seq` does not interact with partitions. It is scoped to an audit session (§7.4), and a session is recorded into exactly one partition (§6.3), so a key used by a tool across any number of partitions leaves a complete sequence in each session and no sequence spanning two.

### 10.6 Scope of the Polluted Stop

The Polluted Stop procedure (§7.2) lets a Level-2 tool detect that the host sealed a record whose body differs from the bytes the tool emitted, by recomputing the `record_hash` from the host's `accept` response. Its coverage is bounded:

- It detects only body substitution where the host honestly reports the hash it sealed. A host that lies consistently - returning a `record_hash` computed over the tool's original bytes while sealing or persisting something else - passes the check undetected.
- It does not cover post-`accept` tampering, nor a host that returns `accept` without durably persisting the record.
- It covers only attempt records: an outcome has no response (§6) and so no returned `record_hash`, and a tool cannot Polluted-Stop-verify its own outcomes. Outcome integrity rests instead on chain recomputation, the anchored digest, and - where the host countersigns - the countersignature the host writes into the ledger for each sealed outcome (§7.2).
- Under Level 1 the tool is not required to verify (§11.3) unless it requires a countersignature (§7.2); absent that check, an L1 host is trusted unconditionally.

Beyond this scope, detection rests on the host's own ledger integrity (§10.1), independent verification against an out-of-band anchor (§8.3), and governance-boundary reconciliation (§7.5). Post-seal tampering with a sealed Level-2 `signature` is caught by chain recomputation as a `record-hash-mismatch` (the signature is inside the record-hash preimage, §8.2), so an independent verifier detects it without re-running signature verification; the `signature-invalid` anomaly kind (§7.6) is reserved for a verifier that additionally re-verifies signatures against a synchronized key registry, which is optional for a pure ledger auditor.

### 10.7 Threats Detected

As a detective control, the protocol detects the following against the ledger:

- **Replay** - an attempt `id` already sealed with a different event is rejected, and a byte-identical one is answered from the ledger without a second record (§7.1); under Level 2 a `signer_seq` already decided in its session is rejected (§7.4), and a verifier reports two sealed records sharing one (§11.4).
- **Transplant into another call** - an event carries the `session_id` of the call it was emitted for inside its signed and hashed bytes, and a host rejects one that is not the call's (§6.3), so an event recorded for one call cannot be recorded again as another's, here or at another host.
- **In-flight forgery or modification** - a Level-2 detached signature is verified and an invalid one rejected (§7.4).
- **Event suppression** - a Level-2 `signer_seq` missing within a session is flagged as a `signer-seq-gap` (§7.4, §7.6), by the host as it decides events and by a verifier reading the sealed chain (§11.4).
- **Retroactive ledger alteration** - recomputation of the hash chain localizes a mutated record that does not re-link the chain (§8.3); a fully re-linked rewrite is detected only against an out-of-band anchor (as with truncation), or, where the host countersigns and the verifier requires it, by the countersignatures the rewriter cannot reproduce (§10.1).
- **Ledger truncation or rewind** - detected when the tail digest is anchored out-of-band (§8.3, §9); undetectable without an anchor.
- **Shadow operation (partial)** - a `success` or `failed` outcome that correlates to no accepted attempt of its own audit session is flagged (§7.2); an action a tool never reports at all is caught only by governance-boundary reconciliation for out-of-governance egress (§10.2).
- **Outcome suppression** - an accepted attempt with no terminal outcome when its call ends is recorded by the host as `unresolved-attempt` (§6.3, §10.8).
- **A fabricated or misattributed accept** - where the host countersigns, the `host_signature` binds the host-assigned fields and the ledger's `log_id` to a key the registry binds to that host, so an `accept` the named host did not issue fails verification and the tool aborts (§7.2). Polluted Stop alone does not cover this: it detects a response describing a *different* record, not one produced by a *different party* than the tool believed it was talking to.

Content misattestation (§10.2) is outside the reach of cryptographic detection.

### 10.8 Completeness of the Attempt/Outcome Correlation

An attempt is answered, so its loss is visible to the tool; an outcome is not answered, so its loss is not. What makes the loss of a trailing outcome detectable is the call. A tool delivers every outcome of an audit session no later than the call's result (§6), and the host - which issued the call - observes its end directly. An attempt the host accepted that has no sealed terminal outcome when the call ends is therefore one the tool never resolved, whether it crashed, was cancelled, or suppressed the outcome; the host records it as `unresolved-attempt` (§6.3).

The record is the host's, not the chain's. A verifier reading the ledger alone sees an accepted attempt with no outcome and cannot tell a call still in progress from one that ended without resolving it, because the call's end is not in the ledger. It MAY flag such an attempt after a deployment-defined settling period, but MUST NOT treat it as a sealed-integrity failure of the chain, since the chain over the sealed records remains internally consistent.

### 10.9 Key Lifecycle: Rotation and Revocation

Level 2 roots trust in the out-of-band key registry (§5.1). Key rotation and revocation are deployment concerns, but they interact with two protocol mechanisms and must be handled deliberately:

- **Rotation.** `signer_seq` is scoped to a key within an audit session (§7.4), and a tool signs every event of a session under one `key_id`, so rotation takes effect from the next call and needs no coordination with operations in flight: calls that began under the old key finish under it, and calls that begin under the new one start its sequence at 0. A key that changed mid-session would leave the refusal of an attempt numbered under the old key unable to account for it (§11.4). Reusing a `key_id` with a new public key is *not* rotation; it is indistinguishable from key compromise and MUST NOT be done - a `key_id` binds one key for its lifetime.
- **Revocation.** Records sealed with a key while it was valid remain valid evidence: the signature and the hash chain still prove authorship and integrity at seal time, and the append-only ledger is not rewritten on revocation. A revoked key therefore keeps its registry entry, marked revoked: a verifier checks a sealed record against it as before. Revocation is forward-looking - after a `key_id` is revoked in the registry, the host MUST reject subsequent events bearing it as `unknown-key` (§7.4). Whether events sealed near the compromise window are trustworthy is a governance judgment made against the anchored digests (§8.3) and the revocation timestamp, not a protocol determination; the protocol preserves the evidence, it does not adjudicate it.

**Both registries are in scope.** The rules above are written for the Level-2 registry that binds a tool's signing keys (§5.1). They apply unchanged, with the roles exchanged, to the countersignature registry that binds a host's (§7.1): a `host_key_id` binds one key for its lifetime, and a record countersigned under a key that was valid at seal time remains valid evidence, verified against the revoked entry. A `host_signature` whose `host_key_id` has no registry entry at all does not establish the countersignature, and is reported `host-signature-invalid` (§7.6) by a verifier; a tool aborts under §7.2 on an `accept` countersigned under a key with no entry or a revoked one, since a revoked key confirms nothing new. §7.6 requires such a condition to be mapped onto the applicable Tier-1 code rather than given a new one.

**The two registries share no key.** A key registered for a tool MUST NOT also be registered for a host. A tool holding a key the countersignature registry binds to a host manufactures the countersigned state, which §5.2 rests on its being unable to do.

Because the ledger is a detective control (§2), neither rotation nor revocation retroactively rewrites or re-flags sealed records; both are reconciled out-of-band against the registry's own history.

### 10.10 Identity binding in shared storage

The event (§4) carries no field naming the governed identity an operation is attributed to. A partition (§3, §10.5) is a host-side concept the tool is unaware of, and it is not part of the §8.2 preimage, so partition membership is a property of where a record is stored, not of the record's own bytes. A chain therefore proves internal consistency and authorship; by itself it does not prove whose chain it is.

That is sound where one deployment holds one principal's ledger. It is not sound where records for several principals share a store: a record sealed under one principal's partition stays internally consistent when moved into another's, because nothing in its hashed bytes contradicts the new location. A transplant of this kind is out of reach of the chain alone.

A deployment that stores records for more than one principal in a shared medium MUST bind identity by one of the following, and a verifier MUST check the one the deployment chose:

1. **The countersignature's `log_id`.** The host countersigns every record (§7.1), and the deployment gives each principal's partition its own `log_id`. The countersignature binds `log_id` to the record's position and `record_hash`, and `record_hash` binds the event, so a record moved into another principal's partition still names the partition it was sealed in, and a storage-level attacker without the host's countersigning key cannot re-sign it under another `log_id` (§10.1). The identity is the `log_id` together with the host key that signed it: a `log_id` is distinct only among one host's chains (§7.1), so another host could name a chain the same way, and only its key tells the two apart. This is how a Certificate Transparency log is identified by its key and its Signed Certificate Timestamp names the log it came from [RFC-9162], and how a checkpoint names its log by its origin line and verifies under the log's key [C2SP].
2. **An enclosing record.** Seal each Auditable MCP record inside a record of the storage layer that binds the principal in its own hashed and signed bytes - a SEP-3004 boundary record's `principal_id` is one such binding [SEP-3004] - and check that binding.

Either way, the expectation MUST be supplied out-of-band: the `log_id` and the `host_key_id`s the partition's host countersigns under, or the principal, the partition is expected to hold. It is an input to verification, never a value read from the artifact under verification: a transplanted record carries its own identity with it, so an expectation taken from that record would always match it. A record whose bound identity does not match the expectation, or which carries no binding where the deployment requires one - under the first construction, a record without all three of `host_signature`, `host_key_id`, and `log_id` - is flagged `principal-mismatch` (§7.6). The absent case fails closed: an unbound record cannot be shown to belong where it was found.

A single-principal deployment needs neither construction, and this specification does not add an identity field to §4 for it. Identity belongs to the layer that owns the storage boundary - here, the host that names its chains - and an optional field in the event would let an implementation satisfy the schema without binding anything.

### 10.11 Security of the 2026-07-28 binding

The binding in §6.4 routes each round of an audited call through the host, which makes the host's retry the thing that lets an operation proceed. Four consequences follow.

- **A retry that never comes releases nothing.** MRTR does not oblige a client to retry. A host that stops retrying - deliberately, or because it failed - leaves every operation the tool asked to record unperformed, which is the fail-closed direction.
- **A replayed retry is not a second accept.** `requestState` is attacker-controlled [MCP-MRTR], and a client can send a retry it has sent before. §6.4's at-most-once rule is what keeps one sealed attempt from standing for two executions; it is the property MRTR itself asks a server to enforce server-side for any state that must be consumed once.
- **A retry that reaches the wrong instance performs nothing.** Where the tool keeps a call's state in one instance (§6.4, round affinity), a retry routed elsewhere finds no round to resume and is refused like a replay; it fails the call and never runs an operation that was not accepted in it. The `Auditable-Mcp-Session` header lets a deployment avoid that failure; it is not a control, and a client that sends a wrong one only has its request refused.
- **`responses` are the host's word.** An Attempt Response in a retry authenticates nothing by itself; the transport's security is MCP's. Where the tool needs to know that the answer came from the host it expects, it requires a countersignature (§5.2), which binds the accept to a key the registry binds to that host, and performs Polluted Stop (§7.2), which binds the accept to its own attempt - together they reject both a fabricated answer and a genuine answer to some other attempt.

## 11. Conformance

An implementation (Host, Tool, or Verifier) is considered conformant to the Auditable MCP specification if it fulfills the following normative requirements. An implementation that acts in more than one role meets the requirements of each.

### 11.1 General Requirements

- **Conformance Vectors:** Implementations MUST reproduce every positive golden vector under `vectors/` byte-for-byte, and MUST refuse each negative (error-case) vector with its pinned Tier-1 code (§8.4). Given identical inputs, conformant implementations MUST produce an identical `record_hash` across any language boundary.
- **Canonicalization:** Implementations MUST perform JSON serialization strictly according to RFC 8785 (JCS) prior to any hashing or signing (§8.1).

### 11.2 Host Conformance

A host embedded in a tool for the degraded posture (§6.2) takes part in no MCP exchange, so the capability requirement below does not apply to it; every other requirement does.

A conformant Host MUST:

- **Capability Enforcement:** Declare its required audit capability under the `extensions` member of its client capabilities, keyed by the extension identifier, where its binding carries them (§6.1, §6.4, §6.5), and enforce that level at runtime (§7.1), rejecting events that do not meet the mandated level.
- **Audit Sessions:** Issue a fresh `session_id` for every call it audits, keep it for every request of the call, reject events that carry another, and close the session when the call ends (§6.3).
- **Round Affinity Header:** Where §6.4 is carried over Streamable HTTP, carry `Auditable-Mcp-Session` on every request of an audited call, and on each retry every request metadata header MCP requires of the request it repeats (§6.4).
- **Verifiable Accept:** Return `seq`, `host_ts`, and `previous_hash` alongside `record_hash` in the `accept` response (§7.1), and answer a byte-identical repeat of a sealed attempt with the response it gave the first time.
- **Countersigning:** If it declares `countersign: "host"` (§5.2), countersign the host-assigned fields and `log_id` of every sealed record - attempt and outcome alike - and persist `host_signature`, `host_key_id`, and `log_id` with it; return all three in the `accept` response for an attempt, which is the only event with a response (§7.1, §7.2).
- **Ledger Validation:** Perform the mandatory schema, numeric canonicalization-domain (§8.1), session, and attempt `id`-uniqueness (both levels), plus `signer_seq` and signature (Level 2), validations before sealing (§7.1); fail closed on integrity violations.
- **Atomic Sealing:** Assign `seq` and `previous_hash`, seal, and commit atomically with respect to any other record being sealed into the same partition, so that two concurrent attempts never take the same position (§7.1, §10.5).
- **Receive-boundary Numeric Enforcement:** Reject a number outside the canonicalization domain at ingestion, before a lossy native parse can corrupt it (§8.1).
- **Anomaly Flagging:** Record, without rejecting, a `signer-seq-gap` it observes (§7.4), an `orphaned-outcome` (§7.2), an outcome it dropped (§6), and an `unresolved-attempt` when a call ends (§6.3).
- **Code Vocabulary:** Use the Tier-1 reason codes for control-flow rejects and the Tier-1 anomaly kinds for cross-implementation ledger inspection, exactly as specified (§7.6).
- **Partition Isolation:** Maintain a separate hash chain, `seq`, and anomaly set per partition; never let records, sequences, or anomalies cross partitions (§10.5).

### 11.3 Tool Conformance

A conformant Tool MUST:

- **Audit-before-Act:** Send an attempt and receive an `accept` from the host before performing the corresponding internal domain action (§6), and perform it at most once, however many `accept`s reach it (§6).
- **Audit Sessions:** Carry the call's `session_id` in every event it emits for the call, and issue its own for each call in the degraded posture (§6.3).
- **Polluted Stop:** Under Level 2, and at either level where it requires a countersignature, recompute the `record_hash` upon receiving an `accept` response using the host-provided `seq`, `host_ts`, and `previous_hash`, and abort execution if the hash does not match (§7.2). Otherwise this verification is OPTIONAL.
- **Atomic Numbering (Level 2):** Sign every event of an audit session under one key, number its events from 0, and assign `signer_seq` and emit the event atomically with respect to every other event of that session (§7.4).
- **Signature Encoding (Level 2):** Sign with the algorithm bound to the `key_id` by the registry and encode the detached `signature` as base64url without padding (§5.1).
- **Abort Signaling:** Upon a `reject`, an `unavailable` or unanswered attempt it stops retrying, a missing or invalid countersignature it requires, or a Polluted-Stop hash mismatch, emit an `outcome: "aborted"` event with the Tier-1 `reason` of §7.2's precedence before halting the operation.
- **Countersignature Enforcement:** If it requires `countersign: "host"` (§5.2), verify the countersignature on every `accept` and abort with `host-uncountersigned` or `host-signature-invalid` rather than act on an uncountersigned record (§7.2).
- **Round Affinity:** Where §6.4 is carried over Streamable HTTP, reject a request whose `Auditable-Mcp-Session` header does not agree with its body; refuse, without acting, a retry of a round it does not hold and cannot forward and a first request for a call it already holds; where it keeps a call's state in one of several instances, deliver every retry to that instance; and keep an altered `requestState` from causing anything worse than the request's failure (§6.4).
- **Outcomes Before the Result:** Deliver every outcome of an audit session no later than the call's result (§6).
- **Degradation:** For an unnegotiated call (§6.2), send no attempt or outcome, serve `tools/call` exactly as a build without this extension would, and take one of the two admissible postures, degraded or mandatory. Never serve a call while neither recording the operations nor reporting the omission.

### 11.4 Verifier Conformance

A verifier reads a sealed ledger, possibly written by a different implementation, and reports anomalies (§7.6). A conformant Verifier MUST:

- **Chain Recomputation:** Recompute each record's hash from the §8.2 preimage and its predecessor's `record_hash`, and report `record-hash-mismatch`, `seq-gap`, and, against an anchored tail digest, `digest-mismatch` (§8.3).
- **Record Validation:** Report `schema-invalid` for a sealed record that fails structural or canonicalization-domain validation (§7.1, §8.1) - as a finding, not a failure to verify: a record that cannot be canonicalized is reported, and the chain is checked on either side of it. A record sealed under an earlier published `spec_version` is validated against that version's schema, published under [`schema/earlier/`](schema/earlier/), and its signature is decoded as that version encoded it; conforming to its own version, it is not `schema-invalid`. A chain's versions do not go backwards: a record of an earlier version sealed after a record of a later one in the same partition is reported `schema-invalid`, since no conforming host seals it (§4 pins `spec_version`) and only a rewrite could place it there. The per-session procedures of this section - correlation, the duplicate `signer_seq` check, and the accounting below - apply to records of this version; an earlier version's records are correlated and numbered as that version defined.
- **Level-2 Validation:** Where records carry Level-2 fields, report `signature-invalid` for a signature that fails verification, `replay-detected` for each `signer_seq` that two sealed records share within one key and audit session, and `signer-seq-gap` for each run of values the procedure below leaves unaccounted.
- **Correlation:** Report `orphaned-outcome` for a `success` or `failed` outcome that correlates to no sealed attempt of its audit session (§7.2).
- **Countersignature Determination:** Determine a record's countersignature (§5.2) by verifying `host_signature` against the `host_key_id`'s registry entry, over the §7.1 preimage built from the record's own host-assigned fields and `log_id`. A verifier MUST NOT infer the countersignature from any other field. A record carrying none of `host_signature`, `host_key_id`, and `log_id` is uncountersigned, which is a state and not an anomaly - unless the verifier was told, out-of-band, that the chain must be countersigned, in which case it is reported `host-signature-invalid`; a verifier MUST accept that requirement as an input, because a storage-level attacker can strip a countersignature it cannot forge. One that carries some but not all of the three, or a signature that fails verification, is reported `host-signature-invalid`.
- **Identity Matching:** Where the deployment binds identity (§10.10), compare each record's bound identity - its `log_id` and `host_key_id`, or the enclosing record's binding - against an expectation supplied out-of-band, and report `principal-mismatch` on a mismatch or on a missing binding, including for a record the verifier cannot otherwise validate. The two are compared as strings. A deployment that binds a structured identity in an enclosing record MUST reduce it to a single string before verification: comparing structures is implementation-defined, and two conforming verifiers would return opposite verdicts on one ledger.
- **Code Vocabulary:** Report anomalies using the Tier-1 anomaly kinds, exactly as specified (§7.6).

**Accounting for `signer_seq` in a sealed chain.** A verifier does not see the events a host rejected, so a rejected attempt leaves a value missing from the sealed sequence that the host itself did not flag. The sealed `aborted` outcome of that attempt (§7.2) is what accounts for it. For each `key_id` and `session_id` in a partition, a verifier MUST compute the unaccounted values as follows, so that two verifiers report the same values for one ledger:

1. Let *V* be the `signer_seq` values of the sealed records carrying that key and session, and *M* the integers from 0 to the largest value in *V* that are not in *V*.
2. Let *R* be those sealed records that are `aborted` outcomes with `reason` `host-rejected` or `host-unavailable` and to which no sealed attempt correlates - none with the same `session_id` and `id` (§7.2) - in ascending order of `signer_seq`.
3. For each record *r* in *R*, in that order, mark as accounted the smallest value in *M* that is less than *r*'s `signer_seq` and not yet accounted; if there is none, *r* accounts for nothing.
4. Each maximal run of consecutive values of *M* left unaccounted is one `signer-seq-gap`, naming its first and last value. A verifier computes the runs from the gaps between the values of *V* and MUST NOT enumerate *M*: one sealed value near 2^53 - 1 (§8.1) would otherwise exhaust it. The number of unaccounted values is exact; which values they are is not evidence of which event was suppressed, since a refusal accounts for the smallest value below it whichever attempt it concluded.

Level-2 verification and countersignature determination both require the out-of-band key registries (§5.1, §7.1). A verifier without them MUST report that those checks were not performed, rather than return a result in which their anomalies are simply absent: an unchecked signature and a valid one are not the same finding.

Two Tier-1 anomalies are not produced by reading a ledger: `unreported-egress` arises from governance-boundary reconciliation against an independent observation (§7.5), and `unresolved-attempt` from the host's observation of a call's end (§6.3). Both are outside this role.

## 12. Extensibility and Registries

This specification defines three extension points. All three are governed by `spec_version`, not by in-band negotiation: a participant declares its supported `spec_version` at capability negotiation (§6.1), and events carry `spec_version` (§4), so a change to any registry is a new `spec_version`.

### 12.1 Signature algorithm identifiers

The algorithm identifiers `Ed25519` and `ES256` (§5.1) are the complete set for this version. They are names from the IANA "JSON Web Signature and Encryption Algorithms" registry, and a future version adds only fully-specified names from that registry [RFC-9864], with the meaning and the raw signature encoding that registry gives them. An identifier is an opaque token matching the ABNF [RFC-5234]:

```abnf
alg-id = 1*( ALPHA / DIGIT / "_" )
```

The same identifiers and the same registry shape bind a host's countersigning key under `host_key_id` (§7.1). A future version MAY add identifiers; when this document graduates to a standards-track process, this registry SHOULD be maintained under a "Specification Required" policy ([RFC-8126]-style), each entry pinning the identifier string, the signature scheme, and the exact raw wire encoding. Identifiers MUST NOT be added or interpreted in-band; a `key_id` bound to an unrecognized algorithm is unverifiable and its events are rejected as `unknown-key` (§7.4).

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
- **[RFC-7515]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515, May 2015.
- **[RFC-7518]** Jones, M., "JSON Web Algorithms (JWA)", RFC 7518, May 2015.
- **[RFC-9864]** Jones, M. and O. Steele, "Fully-Specified Algorithms for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)", RFC 9864, October 2025.
- **[RFC-5234]** Crocker, D., Ed. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.
- **[RFC-1123]** Braden, R., Ed., "Requirements for Internet Hosts - Application and Support", STD 3, RFC 1123, October 1989.
- **[RFC-9562]** Davis, K., Peabody, B., and P. Leach, "Universally Unique IDentifiers (UUIDs)", RFC 9562, May 2024.
- **[FIPS-186-5]** National Institute of Standards and Technology, "Digital Signature Standard (DSS)", FIPS PUB 186-5, February 2023.
- **[SEP-2133]** Model Context Protocol, "Extensions framework for MCP", SEP-2133, merged 2026-01-26. The `extensions` capability member it introduces ships in MCP protocol version `2026-07-28`.
- **[MCP-2026-07-28]** Model Context Protocol, "Specification, protocol version 2026-07-28", <https://modelcontextprotocol.io/specification/2026-07-28>.
- **[MCP-MRTR]** Model Context Protocol, "Multi Round-Trip Requests", protocol version 2026-07-28, <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr>.
- **[MCP-HTTP]** Model Context Protocol, "Streamable HTTP", protocol version 2026-07-28, <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>.

### 13.2 Informative References

- **[RFC-7493]** Bray, T., Ed., "The I-JSON Message Format", RFC 7493, March 2015.
- **[RFC-7517]** Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.
- **[RFC-9338]** Schaad, J., "CBOR Object Signing and Encryption (COSE): Countersignatures", STD 96, RFC 9338, December 2022.
- **[RFC-8126]** Cotton, M., Leiba, B., and T. Narten, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 8126, June 2017.
- **[RFC-8446]** Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018.
- **[RFC-4303]** Kent, S., "IP Encapsulating Security Payload (ESP)", RFC 4303, December 2005.
- **[RFC-9147]** Rescorla, E., Tschofenig, H., and N. Modadugu, "The Datagram Transport Layer Security (DTLS) Protocol Version 1.3", RFC 9147, April 2022.
- **[RFC-5848]** Kelsey, J., Callas, J., and A. Clemm, "Signed Syslog Messages", RFC 5848, May 2010.
- **[KIP-98]** Apache Kafka, "KIP-98: Exactly Once Delivery and Transactional Messaging".
- **[MCP-2025-06-18]** Model Context Protocol, "Key Changes, protocol version 2025-06-18" (removal of JSON-RPC batching), <https://modelcontextprotocol.io/specification/2025-06-18/changelog>.
- **[SEP-414]** Model Context Protocol, "Document OpenTelemetry Trace Context Propagation Conventions", SEP-414, merged 2026-02-26.
- **[SEP-3004]** Model Context Protocol, "Tamper-Evident Audit Record Contract", SEP-3004, <https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004> (closed 2026-09-22 to proceed through a Working Group).
- **[MCP-TOA]** "Tool Outcome Attestation" (`dev.agentstatus/toa`), proposed MCP extension, <https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3350>.
- **[W3C-Trace-Context]** W3C, "Trace Context", W3C Recommendation.
- **[SCITT]** IETF SCITT Working Group, "An Architecture for Trustworthy and Transparent Digital Supply Chains", draft-ietf-scitt-architecture.
- **[RFC-9162]** Laurie, B., Messeri, E., and R. Stradling, "Certificate Transparency Version 2.0", RFC 9162, December 2021.
- **[C2SP]** Community Cryptography Specification Project, "tlog-witness" and "tlog-checkpoint", <https://c2sp.org/tlog-witness>, <https://c2sp.org/tlog-checkpoint>.
- **[NIST-SP-800-53]** National Institute of Standards and Technology, "Security and Privacy Controls for Information Systems and Organizations", SP 800-53 Rev. 5, control AU-5.
- **[OTel-GenAI]** OpenTelemetry, "Semantic Conventions for Generative AI Systems".
- **[EU-AI-Act]** Regulation (EU) 2024/1689 (Artificial Intelligence Act), Article 12: Record-keeping.
