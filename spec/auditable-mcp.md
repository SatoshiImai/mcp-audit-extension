# Auditable MCP

- **Status:** Draft proposal
- **Version:** `auditable-mcp/0.1`
- **Author:** Satoshi Imai
- **License:** MIT

## Abstract

Auditable MCP is a proposed extension to the Model Context Protocol (MCP). It defines a mechanism for an MCP tool server to self-attest its internal domain operations, such as database transactions and downstream API requests executed within a tool call. These operations are emitted as structured audit events, which the host subsequently records in a tamper-evident ledger.
While existing MCP auditing capabilities are limited to the orchestrator-visible call boundary, this extension addresses the unobservable interior by relying on the tool's self-attestation. This protocol is complementary to SEP-3004 (Tamper-Evident Audit Record Contract) [SEP-3004].

## 1. Motivation

When an MCP tool executes a `tools/call`, the host can observe the call boundary, including the tool name, arguments, and result. However, the host cannot observe the tool's internal execution. While operators can directly instrument the internals of first-party tools, third-party tools remain opaque. Regulatory record-keeping frameworks, such as Article 12 of the EU AI Act [EU-AI-Act], mandate traceability and the automatic recording of events (logs) for high-risk AI systems. Observations restricted to the call boundary are often insufficient to provide this level of detail.

Existing approaches generally terminate at the orchestrator-visible boundary:

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

**Out of Scope:**

- Defining real-time access control policies or authorization gateways for domain actions.
- Evaluating or guaranteeing the inherent trustworthiness of a tool. (Dangerous or unauthorized tools MUST be excluded out-of-band via the orchestrator's allowlist).

Architecturally, the host acts as a "monitoring camera" over tools that have already been vetted by the orchestrator. Via this extension protocol, the host is not expected to evaluate or authorize the semantic execution of a tool's internal actions. Therefore, within this document, when the host "rejects" or "blocks" a record, this exclusively refers to refusing the ingestion of an invalid audit record - ensuring a fail-closed posture for ledger integrity - and never implies the real-time interception or prevention of the domain action itself. (The term "blocking" elsewhere describes only the synchronous request/response nature of the audit exchange, per §6.1, never interception of the domain action.)

## 3. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC-2119] [RFC-8174] when, and only when, they appear in all capitals, as shown here.

- **Tool** - A specific capability exposed by an MCP Server, whose internal operations are subject to audit via this specification.
- **Host** - The MCP client or orchestrator that receives audit events and anchors them into the ledger.
- **Event** - One audit record describing one internal operation (§4).
- **Ledger** - The host's append-only, hash-chained, tamper-evident store of attested events.
- **Boundary** - The standard `tools/call` interface which the host can directly observe.
- **Self-attestation** - A tool's voluntary reporting of its internal domain actions to the host (cryptographically verifiable under Level 2).
- **Domain Action** - An execution step performed internally by a tool (e.g., executing a SQL query, invoking an external API) that is opaque to the host at the boundary.
- **Partition** - A logical isolation boundary defined by the host (e.g., per tenant or session) within which the ledger's hash chain, `seq`, sequence tracking, and anomaly set are scoped (§10.5). It is a host-side ledger concern; the tool is unaware of it.

## 4. The audit event

An event is a JSON object. Its normative schema is
[`schema/audit-event.schema.json`](schema/audit-event.schema.json).

| Field                 | Type              | Presence | Notes                                                                                                                                         |
| --------------------- | ----------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                  | UUID              | REQUIRED | Tool-generated. Correlation key for one operation: the `attempt` and its terminal `outcome` share it. De-duplication key for attempts (§7.1). |
| `spec_version`        | string            | REQUIRED | MUST be `auditable-mcp/0.1`.                                                                                                                  |
| `ts`                  | ISO-8601 datetime | REQUIRED | Tool-observed time (advisory; host time is authoritative).                                                                                    |
| `call_id`             | string            | REQUIRED | The parent `tools/call` request id.                                                                                                           |
| `traceparent`         | string            | OPTIONAL | W3C Trace Context.                                                                                                                            |
| `action_type`         | string            | REQUIRED | §4.1.                                                                                                                                         |
| `mutates`             | boolean           | REQUIRED | Whether the operation changes state. §4.2.                                                                                                    |
| `egress`              | boolean           | REQUIRED | Whether the operation leaves the trust boundary. §4.2.                                                                                        |
| `target_resource`     | object            | REQUIRED | The operation's domain target (sub-fields below).                                                                                             |
| `outcome`             | enum              | REQUIRED | `attempted` &#124; `success` &#124; `failed` &#124; `aborted` (§7.2).                                                                         |
| `reason`              | string            | OPTIONAL | Context for a `failed` or `aborted` outcome (§7.2).                                                                                           |
| `action_context`      | object            | OPTIONAL | Cleartext metadata about the internal operation, redacted at the tool's discretion (§4.3).                                                    |
| `action_context_hash` | string            | OPTIONAL | `sha256:<hex>` commitment to the exact internal context (§4.3).                                                                               |
| `sequence`            | integer           | OPTIONAL | Level 2. Per-`key_id` monotonic counter (distinct from the host-assigned ledger `seq`, §7.1).                                                 |
| `key_id`              | string            | OPTIONAL | Level 2. Identifies the signing key.                                                                                                          |
| `signature`           | string            | OPTIONAL | Level 2. Detached signature (§5, §8.2).                                                                                                       |

The `target_resource` object identifies the domain target of the operation:

| Field        | Type   | Presence | Notes                                                                                                                   |
| ------------ | ------ | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| `kind`       | string | REQUIRED | The class of resource - an open vocabulary, opaque to this specification (e.g., `table`, `file`, `endpoint`, `secret`). |
| `ref`        | string | REQUIRED | The specific resource reference (e.g., a table name, file path, or URL).                                                |
| `scope_hint` | string | OPTIONAL | Finer-grained domain scope within the resource (e.g., `row:consent_basis=marketing`).                                   |

The `sequence`, `key_id`, and `signature` fields are OPTIONAL in the schema, so a single schema covers both levels; see §5 for the resulting validity direction.

### 4.1. Action Type

The `action_type` field MUST be a non-empty string.

This specification treats `action_type` as an opaque identifier. It makes no attempt to define, constrain, or validate the vocabulary, syntax, or semantics of this field. The specific values used are entirely delegated to the tool's internal domain and the broader MCP ecosystem.

### 4.2. Operational Effects (`mutates` and `egress`)

While `action_type` is an opaque label, the physical and stateful impact of an operation is strictly defined by two explicit boolean flags: `mutates` and `egress`. These flags are the core components of the tool's self-attestation and MUST be explicitly declared for each internal event.

- **`mutates` (boolean):** Indicates whether the operation is intended to modify the state of the target resource. A value of `true` denotes a state-altering action (e.g., database INSERT, file write, API POST). A value of `false` denotes a strictly read-only operation.
- **`egress` (boolean):** Indicates whether the operation transmits data across a network or trust boundary to reach the target resource. A value of `true` denotes that data leaves the tool's local context (e.g., a remote database query, an external HTTP request). A value of `false` indicates an operation that is strictly local or contained entirely within the trust boundary.

These fields are orthogonal to standard MCP tool annotations (such as `readOnlyHint`). While standard annotations provide static, tool-level hints during initialization, `mutates` and `egress` provide a dynamic, per-operation attestation of what actually occurred at runtime. For example, a conceptually "read-only" tool may still emit an event where `mutates` is `false` but `egress` is `true`, accurately reflecting that data was transmitted outward to perform the read.

### 4.3. Audit context and data minimization

Ledger integrity and context confidentiality are distinct concerns. The host enforces ledger integrity via the hash chain (§8), independently of any context field. Confidentiality is the responsibility of the emitting tool. A tool attests its internal execution context, which is distinct from the `tools/call` parameters already known to the host. The host records the provided event as-is and does not inspect context for policy.

A tool describes an operation through either, both, or neither of two independent, optional fields:

- `action_context` (OPTIONAL): cleartext metadata about the internal operation, such as the database tables an internally generated query touched. The tool SHOULD redact or omit any field whose disclosure is not warranted before emission.
- `action_context_hash` (OPTIONAL): the `sha256:<hex>` digest of the canonical form (§8) of the exact internal context (the `sha256:` prefix names the hash algorithm; only SHA-256 is defined in this version). It seals a commitment to what the tool did without disclosing it. The commitment is opened later, becoming verifiable when the exact context is revealed (whether by the tool itself or reconstructed from independent records such as egress or downstream logs).

These fields do not need to correspond. A host MUST NOT require `action_context_hash` to match the hash of the possibly-redacted `action_context`. A tool SHOULD provide at least one of them if the internal context carries audit value.

Irrespective of a tool's disclosure policy, credentials, secret values, and raw authentication tokens MUST NOT appear in any field of an event. Personally identifiable information (PII) SHOULD be redacted or omitted in accordance with the operator's policy. The ledger is append-only; tools SHOULD use `action_context_hash` for sensitive context to prevent irreversible plaintext disclosure.

## 5. Conformance levels

Auditable MCP defines two conformance levels to provide a progression from basic self-reporting to cryptographically verifiable auditing. Level 2 adds cryptographic signatures to prevent forgery and a monotonic sequence to detect event loss. A sequence gap may indicate that an emitted event failed to reach the host (§7.4, §10.5).

Both levels share one event schema; the Level-2 fields (`signature`, `key_id`, `sequence`) are OPTIONAL. The validity relationship is directional: every Level-2 event is also a valid Level-1 event (a safe downgrade - an event carrying a signature is still accepted where none is required), whereas an unsigned Level-1 event does not satisfy a Level-2 host, which rejects it (§7.4). The distinction between levels lies entirely in the fields the tool chooses to populate and the validation obligations enforced by the host.

| Feature               | Level 1                                                                        | Level 2                                                                                               |
| :-------------------- | :----------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------- |
| **Tamper Resistance** | None                                                                           | Cryptographic signature and sequencing                                                                |
| **Tool Obligation**   | Emits the core event.                                                          | Adds `signature`, `key_id`, and monotonic `sequence`; MUST perform Polluted Stop verification (§7.2). |
| **Host Obligation**   | Records the event after schema and uniqueness validation (no signature check). | MUST verify signatures, reject invalid ones, and detect sequence gaps.                                |

Level 2 provides evidentiary strength to the audit record (non-repudiation and detection of lost events); it does not imply authorization of the domain action.

## 6. Protocol

Auditable MCP requires tool-to-host communication while a `tools/call` is being processed. It adopts the established MCP elicitation pattern for this exchange. However, the audit exchange itself is deterministic and does not employ human-in-the-loop semantics: the host's audit subsystem processes requests automatically, and execution is not suspended awaiting human input. (Human-in-the-loop consent MAY occur at capability negotiation per §6.1, but never within the per-event audit exchange.)

The protocol defines two messages:

- **`audit/attempt`:** A tool-to-host JSON-RPC request sent immediately before an internal operation, carrying an event with the `outcome` set to `attempted`. This is strictly an audit recording request, not an authorization request. The tool MUST await the response and MUST NOT perform the operation unless the response is `accept`. Bounding this wait (e.g., a transport-level timeout that fails closed) is a transport/SDK responsibility. The host rejects an attempt only when ledger integrity cannot be guaranteed (e.g., invalid signatures or sequence violations). If the host suffers a persistence failure, it replies with an `unavailable` status.
- **`audit/outcome`:** A tool-to-host JSON-RPC notification reporting how the operation resolved, carrying an event with the `outcome` set to `success`, `failed`, or `aborted`. Tools MAY bundle multiple such notifications into a single transmission using a standard JSON-RPC 2.0 Batch array; no Auditable-MCP-specific array payload is defined.

Because `audit/outcome` may be the final event of a tool call, its loss cannot reliably be detected via sequence gaps. Tracking incomplete operation lifecycles (e.g., applying an `expired` state due to execution timeouts) and managing tool process termination upon a rejected attempt are SDK implementation responsibilities.

Consequently, states such as `denied` (boundary-level allowlist rejection) and `expired` (abandoned or timed-out execution) are host-side lifecycle concepts. A tool-internal event never carries these states.

### 6.1 Capability negotiation

Auditable MCP integrates with the standard MCP `initialize` phase, where the host and the tool exchange capabilities bidirectionally. The host declares the audit capability it requires; the tool declares the audit capability it supports. Both use the [`schema/audit-capability.schema.json`](schema/audit-capability.schema.json) object.

The capability object declares the operational parameters of the audit subsystem. Both `level` and `attempt` are REQUIRED.

| Field     | Type   | Presence | Notes                                                                    |
| --------- | ------ | -------- | ------------------------------------------------------------------------ |
| `level`   | string | REQUIRED | MUST be `"L1"` or `"L2"`. The negotiated assurance level.                |
| `attempt` | string | REQUIRED | MUST be `"request"`. `audit/attempt` is a blocking, fail-closed request. |

When a tool's declared capability does not meet the host's requirement (e.g., the host requires Level 2 but the tool supports only Level 1), resolving the mismatch is an orchestrator or SDK implementation responsibility. The orchestrator MAY terminate the connection, or it MAY seek human-in-the-loop consent to admit the tool at a lower assurance level and record that decision in its allowlist.

A tool might falsely declare a higher capability than it possesses. The protocol does not verify a declaration's truthfulness during negotiation. Instead, the host enforces its required level at runtime (§7). If a tool fails to emit events compliant with the enforced level - for example, omitting a signature under Level 2 - the host's runtime validation rejects those events. Consequently, ledger integrity holds irrespective of the initial declaration.

## 7. Host behavior and Tool obligations

The host's audit subsystem is a deterministic recording engine. It does not authorize domain actions; it strictly validates ledger integrity requirements (§5) before sealing records.

### 7.1 Attempt processing

Upon receiving an `audit/attempt` event, the host MUST perform the following validations before sealing:

1.  **Structural Validity:** The event MUST conform to the shared schema, `outcome` MUST be `attempted`, and every numeric value MUST lie in the canonicalization domain (§8.1). An event failing any of these is rejected, not sealed.
2.  **Cryptographic Integrity (Level 2):** If the negotiated capability is Level 2, the host MUST verify the `signature` against the registered public key for the `key_id`.
3.  **Sequence Verification (Level 2):** The host MUST ensure the `sequence` is strictly greater than the last accepted sequence for that `key_id`. (A gap may indicate a suppressed event and is flagged as an anomaly, but the event is accepted if the signature is valid.)
4.  **Uniqueness (both levels):** The host MUST reject an `audit/attempt` whose `id` duplicates an already-accepted attempt (a replay), and MUST NOT seal a second attempt record for that `id`. The terminal `audit/outcome` deliberately reuses its attempt's `id` as the correlation key (§4) and is not subject to this attempt-uniqueness check.

If validation passes, the host seals the record into the ledger (§8) and replies with `status: "accept"` and the host-assigned `seq`, `host_ts`, `previous_hash`, and `record_hash` (see Verifiable Accept below).
If validation fails, or if the host suffers a persistence failure, it replies with `status: "reject"` or `status: "unavailable"`, respectively.

**Verifiable Accept:** On an `accept` response, the host MUST return the full set of host-assigned fields required for the tool to reconstruct the hash preimage (§8.2): `seq`, `host_ts`, `previous_hash`, and the resulting `record_hash`. Without these, the tool cannot perform the mandatory Polluted Stop verification (§7.2).

**Attempt Response.** The host's reply to the `audit/attempt` JSON-RPC request is a JSON object forming a tagged union discriminated on `status`. Its normative schema is [`schema/audit-attempt-response.schema.json`](schema/audit-attempt-response.schema.json).

| Field           | Type    | Notes                                                                                                                                  |
| --------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `status`        | string  | `"accept"`, `"reject"`, or `"unavailable"`. The discriminator.                                                                         |
| `seq`           | integer | REQUIRED when `status` is `"accept"`. Partition-monotonic ledger index assigned by the host (distinct from the tool's `sequence`, §4). |
| `record_hash`   | string  | REQUIRED when `status` is `"accept"`. Hex-encoded SHA-256 of the sealed record (§8.2).                                                 |
| `host_ts`       | string  | REQUIRED when `status` is `"accept"`. Authoritative host timestamp (ISO-8601).                                                         |
| `previous_hash` | string  | REQUIRED when `status` is `"accept"`. The preceding record's `record_hash` (64-zero genesis for the first record).                     |
| `reason`        | string  | REQUIRED when `status` is `"reject"` or `"unavailable"`. Machine-readable cause.                                                       |
| `retryable`     | boolean | REQUIRED when `status` is `"unavailable"`; MUST be `true`.                                                                             |

A conformant host MUST NOT return fields outside those permitted for the resolved `status`; the accept, reject, and unavailable variants are mutually exclusive.

### 7.2 Tool verification and the `aborted` state

The `audit/outcome` event records the terminal state of the tool's execution lifecycle. The protocol defines four core states for `outcome`:

- `attempted` - the pre-action record emitted by `audit/attempt` (§6).
- `success` - the internal action was performed and completed successfully.
- `failed` - the internal action was performed but did not complete successfully.
- `aborted` - the internal action was not performed (fail-closed; e.g., the attempt was not accepted, or Polluted Stop detected tampering).

An `audit/outcome` that correlates to an accepted attempt (by shared `id`) is sealed as a record in the same partition chain (§8.3), subject to the same Level-2 signature and sequence validation as an attempt (§7.4). An `aborted` outcome for a never-accepted or rejected attempt is not sealed into the chain and is not a tampering anomaly (§10.4); the host MUST flag a `success` or `failed` outcome that references no accepted attempt as an anomaly.

When the outcome is `failed` or `aborted`, the event MAY include an optional `reason` string. The `reason` is an opaque string; the values `hash-mismatch`, `host-rejected`, and `host-unavailable` are RECOMMENDED for the corresponding conditions, but tools and the broader ecosystem MAY extend this vocabulary.

To guarantee that the host recorded the exact event the tool emitted, the tool MAY (and under Level 2 MUST) recompute the record hash (§8) using the host-assigned `seq`, `host_ts`, and `previous_hash`, then compare it against the `record_hash` returned in the `accept` response; this recompute-and-compare check is termed **Polluted Stop** verification.

- If the hashes do not match (indicating ledger pollution or host compromise), the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and the RECOMMENDED `reason: "hash-mismatch"`.
- If the host replies with `reject` or `unavailable`, the tool MUST NOT perform the internal action. It MUST emit an outcome event with `outcome: "aborted"` and a `reason` (RECOMMENDED: `"host-rejected"` for a `reject`, `"host-unavailable"` for an `unavailable`).

### 7.3 Protocol limits and environmental enforcement

The protocol establishes the `MUST NOT` obligation for tools to halt execution when an attempt is rejected, unavailable, or fails hash verification. However, the Auditable MCP protocol itself operates via JSON-RPC messages and cannot physically restrain a rogue tool that violates this obligation.

Detecting and physically terminating a rogue tool (e.g., sending process kill signals, or dropping unauthorized egress traffic via a network gateway) is outside the scope of this protocol and remains the responsibility of the host's runtime environment, orchestrator, or infrastructure.

### 7.4 Level-2 detection

Under Level 2, the host MUST verify each `signature` against a public key registered out-of-band, and it MUST track the monotonic `sequence` per `key_id`.
The host MUST reject events with missing or invalid signatures, and MUST reject events with a sequence less than or equal to the last accepted sequence (replay). A forward sequence gap may indicate a suppressed event; the host MUST flag the anomaly but MUST NOT reject the current valid event.

### 7.5 Reconciliation with boundary observations

A host environment MAY independently observe a tool's operations (e.g., network egress captured by a gateway). Comparing these external boundary observations against the tool's self-reported ledger records enables the detection of event suppression (omissions). The handling of such reconciliation anomalies is outside the scope of this protocol and is the responsibility of the host's runtime environment or orchestrator.

## 8. Canonicalization and hashing

The integrity of the ledger, the ability for tools to verify host responses (§7.2), and the cross-platform verifiability by independent auditors depend on a strict, deterministic serialization contract.

### 8.1 Canonical JSON serialization (RFC 8785)

Any JSON object subjected to hashing MUST be serialized according to the JSON Canonicalization Scheme (JCS) defined in **[RFC-8785]**.
This strict requirement ensures byte-for-byte reproducibility across heterogeneous environments (e.g., differing floating-point representations), which is necessary to prevent false-positive ledger integrity failures.

Because JCS serializes numbers as IEEE-754 double-precision values, every numeric value in an event (including within `action_context`) MUST be finite, and every integer-valued number MUST satisfy |n| <= 2^53-1. Beyond that bound a runtime cannot distinguish an exact integer (which loses precision as a double, so one platform rounds it while another rejects it) from a float that happens to be integer-valued, so a conforming implementation MUST reject any such event rather than risk divergent canonicalization.

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

The chain hashes (`record_hash`, `previous_hash`) are bare hex, fixed to SHA-256 by this version of the preimage construction. This differs deliberately from `action_context_hash` (§4.3), which carries an algorithm prefix (`sha256:<hex>`): the context hash is a tool-authored commitment that may need to name its algorithm as the field evolves, whereas the chain hash algorithm is pinned by the spec version and needs no self-description.

If Level 2 signatures are used, the signature MUST be computed and verified over the RFC 8785 canonical form of the event with the `signature` field itself removed, to prevent self-referential forgery.

This preimage is a cryptographic construct assembled locally by each party - by the host when sealing a record, and by the tool when performing Polluted Stop verification (§7.2). It is never transmitted on the wire. Unlike the wire contracts - the §4 audit event, the §6.1 Capability object, and the §7.1 Attempt Response, each bound to a JSON Schema under [`schema/`](schema/) - the preimage is defined solely by its structure in this section and is deliberately not accompanied by a schema. It is assembled from already-validated inputs (the `event` and the host-assigned fields) purely as input to the hash function; runtime schema validation of the preimage would be a category error and is not required.

### 8.3 Ledger Chaining

The host seals a record for each accepted `audit/attempt`, and for each `audit/outcome` that correlates to an accepted attempt and passes the same Level-2 signature and sequence validation (§7.4), appended to the partition chain in arrival order (advancing `seq`). Attempt records are de-duplicated by `id` (§7.1); valid outcome records are appended as received and are not de-duplicated. Because outcomes are not de-duplicated, bounding the number of outcomes a tool may emit per correlation `id` (to limit ledger growth) is a host/SDK responsibility (cf. §7.3). Records form a tamper-evident chain by including the `previous_hash` in the preimage object. The first record in a partition uses a genesis hash consisting of 64 zeros. The `record_hash` of the tail record serves as the ledger digest, which SHOULD be anchored out-of-band to a secure medium; without a periodically anchored tail digest, truncation of a chain suffix (including a rewind to genesis) is undetectable, because a truncated prefix is internally consistent.

### 8.4 Conformance Vectors

Golden conformance vectors - covering RFC 8785 canonicalization, per-event hashes, and a complete sealed chain - are published alongside this specification under the `vectors/` directory. A conforming implementation MUST reproduce these vectors exactly.

## 9. Relationship to existing standards

**SEP-3004 (Tamper-Evident Audit Record Contract)**
SEP-3004 defines a tamper-evident audit record contract at the orchestrator-visible boundary. Auditable MCP is complementary: it produces the tool-internal domain records, which the host MAY subsequently seal using SEP-3004's contract as the underlying ledger storage format.

**Cryptographic Ecosystems**
The requirement for deterministic serialization (RFC 8785) prior to hashing and detached signing (§8) is adopted from established supply-chain security and transparency frameworks (e.g., Sigstore, in-toto). This protocol uses these standard primitives rather than defining custom cryptography for the MCP boundary.

## 10. Security and Operational Considerations

### 10.1 Ledger Integrity as the Root of Trust

The host acts as the definitive authority for ledger integrity. Auditable MCP relies on the host's ability to maintain the append-only property and the hash-chain of records. Compromise of the host's ledger storage results in the total loss of auditability.

### 10.2 Limits of Self-Attestation (Omission and Misattestation)

Cryptographic signatures and sequence gaps detect _falsified_ or _lost_ records, but cannot detect an internal action a tool never reports at all (suppression by omission). This residual risk is mitigated only by out-of-band reconciliation (§7.5), comparing self-reported egress against independently observed boundary egress.

A signature proves an event's authorship and integrity in transit, not the truthfulness of its content. A compromised or faulty tool can emit a validly-signed event that misdescribes the operation - a false `mutates`, `egress`, or `outcome`, or a fabricated `target_resource` (misattestation). Signature, sequence, and hash-chain verification do not detect this; reconciliation (§7.5) catches only discrepancies observable at the boundary (e.g., an egress the tool denied). Misattestation of a local, non-egress operation is a residual risk fed to allowlist governance, not a protocol guarantee.

### 10.3 Data-at-Rest Minimization

Because the host's ledger is append-only, any sensitive value written to `action_context` in cleartext is permanent and cannot be erased (e.g., conflicting with GDPR Right to Erasure). Implementations SHOULD prefer `action_context_hash` for sensitive internal context (§4.3), keeping only a verifiable commitment - not the data - in the immutable ledger.

### 10.4 Handling of Aborted Outcomes

An `aborted` outcome that references a rejected or never-accepted attempt is the tool correctly honoring its fail-closed obligation. A host MUST NOT treat such an `aborted` outcome as a tampering anomaly; it MAY note it out-of-band as an audit signal of a refused action, but MUST NOT seal it into the chain.

### 10.5 Partition Isolation and Sequence Scoping

A partition (§3) is a host-side isolation boundary. A host MUST maintain a separate hash chain, `seq` counter, sequence tracker, and anomaly set per partition; records, sequences, and anomalies MUST NOT cross partitions, and a partition's chain is verifiable only against its own genesis.

The host-assigned `seq` is per-partition, but a tool's Level-2 `sequence` is per `key_id` (§4, §7.4). If a tool reuses one signing key across partitions, that key's single monotonic `sequence` is interleaved across the partitions' independent ledgers, so a host or auditor examining one partition observes forward gaps for events the tool emitted to other partitions. Such a gap is benign and does not by itself indicate suppression; a host or auditor correlating events across partitions (by `key_id`) can distinguish it from a genuine gap.

### 10.6 Scope of the Polluted Stop

The Polluted Stop procedure (§7.2) lets a Level-2 tool detect that the host sealed a record whose body differs from the bytes the tool emitted, by recomputing the `record_hash` from the host's `accept` response. Its coverage is bounded:

- It detects only body substitution where the host honestly reports the hash it sealed. A host that lies consistently - returning a `record_hash` computed over the tool's original bytes while sealing or persisting something else - passes the check undetected.
- It does not cover post-`accept` tampering, nor a host that returns `accept` without durably persisting the record.
- Under Level 1 the tool is not required to verify (§11.3); absent that optional check, an L1 host is trusted unconditionally.

Beyond this scope, detection rests on the host's own ledger integrity (§10.1), independent verification against an out-of-band anchor (§8.3), and boundary reconciliation (§7.5).

### 10.7 Threats Detected

As a detective control, the protocol detects the following against the ledger:

- **Replay** - a duplicate attempt `id` is rejected (§7.1).
- **In-flight forgery or modification** - a Level-2 detached signature is verified and an invalid one rejected (§7.4).
- **Event suppression** - a Level-2 forward `sequence` gap is flagged (§7.4).
- **Retroactive ledger alteration** - recomputation of the hash chain localizes a mutated record that does not re-link the chain (§8.3); a fully re-linked rewrite is detected only against an out-of-band anchor (as with truncation).
- **Ledger truncation or rewind** - detected when the tail digest is anchored out-of-band (§8.3); undetectable without an anchor.
- **Shadow operation (partial)** - a `success` or `failed` outcome referencing no accepted attempt is flagged (§7.2); an action a tool never reports at all is caught only by boundary reconciliation for egress (§10.2).

Content misattestation (§10.2) is outside the reach of cryptographic detection.

## 11. Conformance

An implementation (Host or Tool) is considered conformant to the Auditable MCP specification if it fulfills the following normative requirements:

### 11.1 General Requirements

- **Conformance Vectors:** Implementations MUST reproduce every golden vector under `vectors/` byte-for-byte (§8.4). Given identical inputs, conformant implementations MUST produce an identical `record_hash` across any language boundary.
- **Canonicalization:** Implementations MUST perform JSON serialization strictly according to RFC 8785 (JCS) prior to any hashing or signing (§8.1).

### 11.2 Host Conformance

A conformant Host MUST:

- **Capability Enforcement:** Publish its required audit capability and enforce that level at runtime (§7.1), rejecting events that do not meet the mandated level.
- **Verifiable Accept:** Return `seq`, `host_ts`, and `previous_hash` alongside `record_hash` in the `accept` response (§7.1).
- **Ledger Validation:** Perform the mandatory schema, numeric canonicalization-domain (§8.1), and attempt `id`-uniqueness (both levels), plus sequence and signature (Level 2), validations before sealing (§7.1); fail closed on integrity violations.
- **Anomaly Flagging:** Flag (without rejecting) a forward sequence gap (§7.4) and any `success` or `failed` outcome that references no accepted attempt (§7.2).
- **Partition Isolation:** Maintain a separate hash chain, `seq`, sequence tracker, and anomaly set per partition; never let records, sequences, or anomalies cross partitions (§10.5).

### 11.3 Tool Conformance

A conformant Tool MUST:

- **Audit-before-Act:** Emit an `audit/attempt` and receive a successful `accept` response from the host before performing the corresponding internal domain action (§6).
- **Polluted Stop:** Under Level 2, recompute the `record_hash` upon receiving an `accept` response using the host-provided `seq`, `host_ts`, and `previous_hash`, and abort execution if the hash does not match (§7.2). Under Level 1, this verification is OPTIONAL.
- **Abort Signaling:** Upon a `reject`, `unavailable`, or Polluted-Stop hash mismatch, emit an `outcome: "aborted"` event with an appropriate `reason` before completely halting the operation.

## 12. References

### 12.1 Normative References

- **[RFC-2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC-8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC-8785]** Rundgren, A., "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.

### 12.2 Informative References

- **[SEP-3004]** Model Context Protocol, "Tamper-Evident Audit Record Contract", MCP Issue #3004.
- **[OTel-GenAI]** OpenTelemetry, "Semantic Conventions for Generative AI Systems".
- **[EU-AI-Act]** Regulation (EU) 2024/1689 (Artificial Intelligence Act), Article 12: Record-keeping.
