# Auditable MCP

- **Status:** Draft proposal (not adopted; not submitted to the MCP community)
- **Version:** `auditable-mcp/0.1`
- **Author:** Satoshi Imai
- **License:** MIT

## Abstract

Auditable MCP is a proposed extension to the Model Context Protocol (MCP). It defines a mechanism for an MCP tool server to self-attest its internal domain operations, such as database transactions and downstream API requests executed within a tool call. These operations are emitted as structured audit events, which the host subsequently records in a tamper-evident ledger.
While existing MCP auditing capabilities are limited to the orchestrator-visible call boundary, this extension addresses the unobservable interior by relying on the tool's self-attestation. This protocol complements, rather than competes with, the SEP-3004 (Tamper-Evident Audit Record Contract) specification.

## 1. Motivation

When an MCP tool executes a `tools/call`, the host can observe the call boundary, including the tool name, arguments, and result. However, the host cannot observe the tool's internal execution. While operators can directly instrument the internals of first-party tools, third-party tools remain opaque. Regulatory record-keeping frameworks, such as Article 12 of the EU AI Act, mandate traceability and the automatic recording of events (logs) for high-risk AI systems. Observations restricted to the call boundary are often insufficient to provide this level of detail.

Existing approaches generally terminate at the orchestrator-visible boundary:

* **SEP-3004** standardizes a tamper-evident, hash-chained audit record contract that is strictly scoped to the call boundary [SEP-3004].
* **OpenTelemetry** GenAI and MCP semantic conventions trace call attributes (arguments, results, latency) but rely on separate instrumentation for domain operations executed within a tool [OTel-GenAI].
* **Gateways**, by architectural design, log only the network traffic that crosses them.

Auditable MCP addresses a specific gap within this landscape by introducing a mechanism for tool-internal, domain-semantic self-attestation. It enables tools to formally report their internal operations to the host, which can then anchor these attestations into a tamper-evident ledger.

## 2. Scope and non-goals

The objective of this specification is to provide a mechanism for accountability (detective control) rather than authorization (preventive control).

**In Scope:**
* Defining a protocol for an MCP tool to voluntarily report its internal domain operations.
* Establishing the host's mechanism to anchor these reported events into a tamper-evident ledger.
* Enforcing ledger integrity by strictly refusing to record events that fail cryptographic or structural verification.

**Out of Scope:**
* Defining real-time access control policies or authorization gateways for domain actions.
* Evaluating or guaranteeing the inherent trustworthiness of a tool. (Dangerous or unauthorized tools MUST be excluded out-of-band via the orchestrator's allowlist).

Architecturally, the host acts as a "monitoring camera" over tools that have already been vetted by the orchestrator. Via this extension protocol, the host is not expected to evaluate or authorize the semantic execution of a tool's internal actions. Therefore, within this document, "rejecting" or "blocking" exclusively refers to refusing the ingestion of an invalid audit record—ensuring a fail-closed posture for ledger integrity—and never implies the real-time interception or prevention of the domain action itself.

## 3. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC-2119] [RFC-8174] when, and only when, they appear in all capitals, as shown here.

* **Tool** — A specific capability exposed by an MCP Server, whose internal operations are subject to audit via this specification.
* **Host** — The MCP client or orchestrator that receives audit events and anchors them into the ledger.
* **Event** — One audit record describing one internal operation (§4).
* **Ledger** — The host's append-only, hash-chained, tamper-evident store of attested events.
* **Boundary** — The standard `tools/call` interface which the host can directly observe.
* **Self-attestation** — A tool's voluntary, cryptographically verifiable reporting of its internal domain actions to the host.
* **Domain Action** — An execution step performed internally by a tool (e.g., executing a SQL query, invoking an external API) that is opaque to the host at the boundary.

## 4. The audit event

An event is a JSON object. Its normative schema is
[`schema/audit-event.schema.json`](schema/audit-event.schema.json).

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Tool-generated; idempotency key. |
| `spec_version` | string | MUST be `auditable-mcp/0.1`. |
| `ts` | ISO-8601 datetime | Tool-observed time (advisory; host time is authoritative). |
| `call_id` | string | The parent `tools/call` request id. |
| `traceparent` | string (optional) | W3C Trace Context. |
| `action_type` | string | §4.1. |
| `mutates` | boolean | Whether the operation changes state. §4.2. |
| `egress` | boolean | Whether the operation leaves the trust boundary. §4.2. |
| `target_resource` | object | `{ kind, ref, scope_hint? }`: the operation's domain target. |
| `outcome` | enum | `attempted` &#124; `success` &#124; `failed` &#124; `aborted` (§6). |
| `action_context` | object (optional) | Cleartext metadata about the internal operation, redacted at the tool's discretion (§4.3). |
| `action_context_hash` | string (optional) | `sha256:<hex>` commitment to the exact internal context (§4.3). |
| `sequence` | integer (optional) | Level 2. Per-tool monotonic counter. |
| `key_id` | string (optional) | Level 2. Identifies the signing key. |
| `signature` | string (optional) | Level 2. Detached signature (§5, §6). |

The `sequence`, `key_id`, and `signature` fields are OPTIONAL in the schema. This is a deliberate invariant (§5): a Level-1 event is a valid Level-2 event.

### 4.1. Action Type

The `action_type` field MUST be a non-empty string. 

This specification treats `action_type` as an opaque identifier. It makes no attempt to define, constrain, or validate the vocabulary, syntax, or semantics of this field. The specific values used are entirely delegated to the tool's internal domain and the broader MCP ecosystem.

### 4.2. Operational Effects (`mutates` and `egress`)

While `action_type` is an opaque label, the physical and stateful impact of an operation is strictly defined by two explicit boolean flags: `mutates` and `egress`. These flags are the core components of the tool's self-attestation and MUST be explicitly declared for each internal event.

* **`mutates` (boolean):** Indicates whether the operation is intended to modify the state of the target resource. A value of `true` denotes a state-altering action (e.g., database INSERT, file write, API POST). A value of `false` denotes a strictly read-only operation.
* **`egress` (boolean):** Indicates whether the operation transmits data across a network or trust boundary to reach the target resource. A value of `true` denotes that data leaves the tool's local context (e.g., a remote database query, an external HTTP request). A value of `false` indicates an operation that is strictly local or contained entirely within the trust boundary.

These fields are orthogonal to standard MCP tool annotations (such as `readOnlyHint`). While standard annotations provide static, tool-level hints during initialization, `mutates` and `egress` provide a dynamic, per-operation attestation of what actually occurred at runtime. For example, a conceptually "read-only" tool may still emit an event where `mutates` is `false` but `egress` is `true`, accurately reflecting that data was transmitted outward to perform the read.

### 4.3. Audit context and data minimization

Ledger integrity and context confidentiality are distinct concerns. The host enforces ledger integrity via the hash chain (§8), independently of any context field. Confidentiality is the responsibility of the emitting tool. A tool attests its internal execution context, which is distinct from the `tools/call` parameters already known to the host. The host records the provided event as-is and does not inspect context for policy.

A tool describes an operation through either, both, or neither of two independent, optional fields:

* `action_context` (optional): cleartext metadata about the internal operation, such as the database tables an internally generated query touched. The tool SHOULD redact or omit any field whose disclosure is not warranted before emission.
* `action_context_hash` (optional): the `sha256:<hex>` digest of the canonical form (§8) of the exact internal context. It seals a commitment to what the tool did without disclosing it. The commitment is opened later, becoming verifiable when the exact context is revealed (whether by the tool itself or reconstructed from independent records such as egress or downstream logs).

These fields do not need to correspond. A host MUST NOT require `action_context_hash` to match the hash of the possibly-redacted `action_context`. A tool SHOULD provide at least one of them if the internal context carries audit value.

Irrespective of a tool's disclosure policy, credentials, secret values, and raw authentication tokens MUST NOT appear in any field of an event. Personally identifiable information (PII) SHOULD be redacted or omitted in accordance with the operator's policy. The ledger is append-only; tools SHOULD utilize `action_context_hash` for sensitive context to prevent irreversible plaintext disclosure.

## 5. Conformance levels

Auditable MCP defines two conformance levels to provide a progression from basic self-reporting to cryptographically verifiable auditing. Level 2 adds cryptographic signatures to prevent forgery and a monotonic sequence to detect event loss. The sequence gap detection serves as a safety mechanism to identify when an emitted event fails to reach the host, ensuring awareness of an incomplete audit ledger.

To ensure seamless escalation and interoperability, both levels share the exact same event schema. By design, every Level-1 event is a valid Level-2 event (L1 ⊆ L2). The distinction between levels lies entirely in the fields the tool chooses to populate and the validation obligations enforced by the host.

| Feature | Level 1 | Level 2 |
| :--- | :--- | :--- |
| **Tamper Resistance** | None | Cryptographic signature and sequencing |
| **Tool Obligation** | Emits the core event. | Adds `signature`, `key_id`, and monotonic `sequence`; MUST perform Polluted Stop verification (§7.2). |
| **Host Obligation** | Records the event as-is. | MUST verify signatures, reject invalid ones, and detect sequence gaps. |

A tool escalates from Level 1 to Level 2 simply by attaching a signer and a sequence counter; its core emission logic remains unchanged. Level 2 provides evidentiary strength to the audit record (non-repudiation and detection of lost events); it does not imply authorization of the domain action.

## 6. Protocol

Auditable MCP requires tool-to-host communication while a `tools/call` is being processed. It adopts the established MCP elicitation pattern for this exchange. However, Auditable MCP is deterministic and does not employ human-in-the-loop semantics. The host's audit subsystem processes requests automatically; execution is not suspended awaiting human input.

The protocol defines two messages:

* **`audit/attempt`:** A tool-to-host JSON-RPC request sent immediately before an internal operation, carrying an event with the `outcome` set to `attempted`. This is strictly an audit recording request, not an authorization request. The tool MUST await the response and MUST NOT perform the operation unless the response is `accept`. The host rejects an attempt only when ledger integrity cannot be guaranteed (e.g., invalid signatures, sequence violations, or host-side persistence failures).
* **`audit/outcome`:** A tool-to-host JSON-RPC notification sent after the operation completes, carrying an event with the `outcome` set to `success` or `failed`.

Because `audit/outcome` may be the final event of a tool call, its loss cannot reliably be detected via sequence gaps. Tracking incomplete operation lifecycles (e.g., applying an `expired` state due to execution timeouts) and managing tool process termination upon a rejected attempt are SDK implementation responsibilities.

Consequently, states such as `denied` (boundary-level allowlist rejection) and `expired` (abandoned or timed-out execution) are host-side lifecycle concepts. A tool-internal event never carries these states.

### 6.1 Capability negotiation

Auditable MCP integrates with the standard MCP `initialize` phase, where the host and the tool exchange capabilities bidirectionally. The host declares the audit capability it requires; the tool declares the audit capability it supports. Both utilize the [`schema/audit-capability.schema.json`](schema/audit-capability.schema.json) object.

The capability object declares the operational parameters of the audit subsystem.

| Field | Type | Notes |
|-------|------|-------|
| `level` | string | MUST be `"L1"` or `"L2"`. The negotiated assurance level. |
| `attempt` | string | MUST be `"request"`. `audit/attempt` is a blocking, fail-closed request. |
| `attempt_ack_deadline_ms` | integer | Maximum time (ms) the tool waits for an attempt response. Default `500`. |
| `block_disposition` | array | How a blocked internal action surfaces in the `tools/call` result: `["abort"]` (safe floor) or `["partial"]` (opt-in). |
| `outcome_mode` | string | `"batched"` &#124; `"request"`: delivery mode for `audit/outcome`. Default `"batched"`. |
| `outcome_batch_window_ms` | integer | Batching window (ms) for outcomes when `outcome_mode` is `"batched"`. Default `200`. |

When a tool's declared capability does not meet the host's requirement (e.g., the host requires Level 2 but the tool supports only Level 1), resolving the mismatch is an orchestrator or SDK implementation responsibility. The orchestrator MAY terminate the connection, or it MAY seek human-in-the-loop consent to admit the tool at a lower assurance level and record that decision in its allowlist.

A tool might falsely declare a higher capability than it possesses. The protocol does not verify a declaration's truthfulness during negotiation. Instead, the host enforces its required level at runtime (§7). If a tool fails to emit events compliant with the enforced level—for example, omitting a signature under Level 2—the host's runtime validation rejects those events. Consequently, ledger integrity holds irrespective of the initial declaration.

## 7. Host behavior and Tool obligations

The host's audit subsystem is a deterministic recording engine. It does not authorize domain actions; it strictly validates ledger integrity requirements (§5) before sealing records. 

### 7.1 Attempt processing
Upon receiving an `audit/attempt` event, the host MUST perform the following validations before sealing:
1.  **Schema Compliance:** The event MUST conform to the negotiated schema and `outcome` MUST be `attempted`.
2.  **Cryptographic Integrity (Level 2):** If the negotiated capability is Level 2, the host MUST verify the `signature` against the registered public key for the `key_id`.
3.  **Sequence Verification (Level 2):** The host MUST ensure the `sequence` is strictly greater than the last accepted sequence for that `key_id`. (A gap indicates event suppression and is flagged as an anomaly, but the event is accepted if the signature is valid.)

If validation passes, the host seals the record into the ledger (§8) and replies with `status: "accept"`, providing the assigned `seq` and the `record_hash`.
If validation fails, or if the host suffers a persistence failure, it replies with `status: "reject"` or `status: "unavailable"`, respectively.

**Verifiable Accept:** On an `accept` response, the host MUST return the full set of host-assigned fields required for the tool to reconstruct the hash preimage (§8.2): `seq`, `host_ts`, `previous_hash`, and the resulting `record_hash`. Without these, the tool cannot perform the mandatory Polluted Stop verification (§7.2).

**Attempt Response.** The host's reply to the `audit/attempt` JSON-RPC request is a JSON object forming a tagged union discriminated on `status`. Its normative schema is [`schema/audit-attempt-response.schema.json`](schema/audit-attempt-response.schema.json).

| Field | Type | Notes |
|-------|------|-------|
| `status` | string | `"accept"`, `"reject"`, or `"unavailable"`. The discriminator. |
| `seq` | integer | REQUIRED when `status` is `"accept"`. Partition-monotonic sequence assigned by the host. |
| `record_hash` | string | REQUIRED when `status` is `"accept"`. Hex-encoded SHA-256 of the sealed record (§8.2). |
| `host_ts` | string | REQUIRED when `status` is `"accept"`. Authoritative host timestamp (ISO-8601). |
| `previous_hash` | string | REQUIRED when `status` is `"accept"`. The preceding record's `record_hash` (64-zero genesis for the first record). |
| `reason` | string | REQUIRED when `status` is `"reject"` or `"unavailable"`. Machine-readable cause. |
| `retryable` | boolean | REQUIRED when `status` is `"unavailable"`; MUST be `true`. |

A conformant host MUST NOT return fields outside those permitted for the resolved `status`; the accept, reject, and unavailable variants are mutually exclusive.

### 7.2 Tool verification and the `aborted` state
The `audit/outcome` event records the terminal state of the tool's execution lifecycle. The protocol defines four core states for `outcome`: `attempted`, `success`, `failed`, and `aborted`. 
When the outcome is `failed` or `aborted`, the event MAY include an optional `reason` string to record the context of the termination.

To guarantee that the host recorded the exact event the tool emitted, the tool MAY (and under Level 2 MUST) recompute the record hash (§8) using the host-assigned `seq`, `host_ts`, and `previous_hash`, then compare it against the `record_hash` returned in the `accept` response. 
*   If the hashes do not match (indicating ledger pollution or host compromise), the tool MUST NOT perform the internal action. It MAY emit an outcome event with `outcome: "aborted"` and a well-known reason (e.g., `reason: "hash-mismatch"`).
*   If the host replies with `reject` or `unavailable`, the tool MUST NOT perform the internal action. It MAY emit an outcome event with `outcome: "aborted"` and a contextual reason (e.g., `reason: "host-rejected"`).

### 7.3 Protocol limits and environmental enforcement
The protocol establishes the `MUST NOT` obligation for tools to halt execution when an attempt is rejected, unavailable, or fails hash verification. However, the Auditable MCP protocol itself operates via JSON-RPC messages and cannot physically restrain a rogue tool that violates this obligation.

Detecting and physically terminating a rogue tool (e.g., sending process kill signals, or dropping unauthorized egress traffic via a network gateway) is outside the scope of this protocol and remains the responsibility of the host's runtime environment, orchestrator, or infrastructure.

### 7.4 Level-2 detection

Under Level 2, the host MUST verify each `signature` against a public key registered out-of-band, and it MUST track the monotonic `sequence` per `key_id`. 
The host MUST reject events with missing or invalid signatures, and MUST reject events with a sequence less than or equal to the last accepted sequence (replay). A forward sequence gap indicates event suppression; the host MUST flag the anomaly but MUST NOT reject the current valid event.

### 7.5 Reconciliation with boundary observations

A host environment MAY independently observe a tool's operations (e.g., network egress captured by a gateway). Comparing these external boundary observations against the tool's self-reported ledger records enables the detection of event suppression (omissions). The handling of such reconciliation anomalies is outside the scope of this protocol and is the responsibility of the host's runtime environment or orchestrator.

## 8. Canonicalization and hashing

The integrity of the ledger, the ability for tools to verify host responses (§7.2), and the cross-platform verifiability by independent auditors depend on a strict, deterministic serialization contract.

### 8.1 Canonical JSON serialization (RFC 8785)

Any JSON object subjected to hashing MUST be serialized according to the JSON Canonicalization Scheme (JCS) defined in **[RFC-8785]**. 
This strict requirement ensures byte-for-byte reproducibility across heterogeneous environments (e.g., differing floating-point representations), which is necessary to prevent false-positive ledger integrity failures.

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

*(Note: If Level 2 signatures are used, the signature MUST be computed and verified over the RFC 8785 canonical form of the event with the `signature` field itself removed to prevent self-referential forgery.)*

This preimage is a cryptographic construct assembled locally by each party — by the host when sealing a record, and by the tool when performing Polluted Stop verification (§7.2). It is never transmitted on the wire. Unlike the wire contracts — the §6.1 Capability object and the §7.1 Attempt Response, each bound to a JSON Schema under [`schema/`](schema/) — the preimage is defined solely by its structure in this section and is deliberately not accompanied by a schema. It is assembled from already-validated inputs (the `event` and the host-assigned fields) purely as input to the hash function; runtime schema validation of the preimage would be a category error and is not required.

### 8.3 Ledger Chaining
Records form a tamper-evident chain by including the `previous_hash` in the preimage object. The first record in a partition uses a genesis hash consisting of 64 zeros. The `record_hash` of the tail record serves as the ledger digest, which MAY be anchored out-of-band to a secure medium. 

### 8.4 Conformance Vectors
Golden conformance vectors—covering RFC 8785 canonicalization, per-event hashes, and a complete sealed chain—are published alongside this specification under the `vectors/` directory. A conforming implementation MUST reproduce these vectors exactly.

## 9. Relationship to existing standards

**SEP-3004 (Tamper-Evident Audit Record Contract)**
SEP-3004 defines a tamper-evident audit record contract at the orchestrator-visible boundary. Auditable MCP is complementary: it produces the tool-internal domain records, which the host MAY subsequently seal using SEP-3004's contract as the underlying ledger storage format.

**Cryptographic Ecosystems**
The requirement for deterministic serialization (RFC 8785) prior to hashing and detached signing (§8) is adopted from established supply-chain security and transparency frameworks (e.g., Sigstore, in-toto). This protocol utilizes these standard primitives rather than defining custom cryptography for the MCP boundary.

## 10. Security and Operational Considerations

### 10.1 Ledger Integrity as the Root of Trust
The host acts as the definitive authority for ledger integrity. A-MCP relies on the host's ability to maintain the append-only property and the hash-chain of records. Compromise of the host's ledger storage results in the total loss of auditability.

### 10.2 Limits of Self-Attestation (Suppression by Omission)
Cryptographic signatures and sequence gaps detect *falsified* or *lost* records, but cannot detect an internal action a tool never reports at all (suppression by omission). This residual risk is mitigated only by out-of-band reconciliation (§7.5), comparing self-reported egress against independently observed boundary egress.

### 10.3 Data-at-Rest Minimization
Because the host's ledger is append-only, any sensitive value written to `action_context` in cleartext is permanent and cannot be erased (e.g., conflicting with GDPR Right to Erasure). Implementations SHOULD prefer `action_context_hash` for sensitive internal context (§4.3), keeping only a verifiable commitment—not the data—in the immutable ledger.

### 10.4 Handling of Aborted Outcomes
An `aborted` outcome that references a rejected or never-accepted attempt is the tool correctly honoring its fail-closed obligation. A host MUST NOT treat such an `aborted` outcome as a tampering anomaly; it MAY record it merely as an audit signal of a refused action.

## 11. Conformance

An implementation (Host or Tool) is considered conformant to the Auditable MCP specification if it fulfills the following normative requirements:

### 11.1 General Requirements
* **Conformance Vectors:** Implementations MUST reproduce every golden vector under `vectors/` byte-for-byte (§8.4). Given identical inputs, conformant implementations MUST produce an identical `record_hash` across any language boundary.
* **Canonicalization:** Implementations MUST perform JSON serialization strictly according to RFC 8785 (JCS) prior to any hashing or signing (§8.1).

### 11.2 Host Conformance
A conformant Host MUST:
* **Capability Enforcement:** Publish its required audit capability and enforce that level at runtime (§7.1), rejecting events that do not meet the mandated tier.
* **Verifiable Accept:** Return `seq`, `host_ts`, and `previous_hash` alongside `record_hash` in the `accept` response (§7.1).
* **Ledger Validation:** Perform mandatory schema, sequence, signature (Level 2), and chain validations before acceptance, failing-closed upon any discrepancy.

### 11.3 Tool Conformance
A conformant Tool MUST:
* **Audit-before-Act:** Emit an `audit/attempt` and receive a successful `accept` response from the host before performing the corresponding internal domain action (§7.2).
* **Polluted Stop:** Under Level 2, recompute the `record_hash` upon receiving an `accept` response using the host-provided `previous_hash` and `host_ts`, and abort execution if the hash does not match (§7.2). Under Level 1, this verification is OPTIONAL.
* **Abort Signaling:** Upon a `reject`, `unavailable`, or Polluted-Stop hash mismatch, emit an `outcome: "aborted"` event with an appropriate `reason` before completely halting the operation.

## 12. References

### 12.1 Normative References

* **[RFC-2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
* **[RFC-8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
* **[RFC-8785]** Rundgren, A., "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.

### 12.2 Informative References

* **[SEP-3004]** Model Context Protocol, "Tamper-Evident Audit Record Contract", MCP Issue #3004.
* **[OTel-GenAI]** OpenTelemetry, "Semantic Conventions for Generative AI Systems".
* **[EU-AI-Act]** Regulation (EU) 2024/1689 (Artificial Intelligence Act), Article 12: Record-keeping.
