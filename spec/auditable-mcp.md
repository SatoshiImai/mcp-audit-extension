# Auditable MCP

- **Status:** Draft proposal (not adopted; not submitted to the MCP community)
- **Version:** `auditable-mcp/0.1`
- **Author:** Satoshi Imai
- **License:** MIT

## Abstract

Auditable MCP is a proposed extension to the Model Context Protocol (MCP). It lets an MCP tool
server **self-attest its internal domain operations** — the database reads and writes and
downstream API calls it performs *inside* a tool call — as structured audit events that the
host records in a tamper-evident ledger. Existing MCP audit sees only the orchestrator-visible
call boundary; this extension covers what happens beyond it. It layers on top of SEP-3004
(Tamper-Evident Audit Record Contract) rather than competing with it.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in RFC 2119.

## 1. Motivation

When an MCP tool executes a `tools/call`, the host can observe the call boundary — the tool
name, argument hash, and result — but not what the tool did internally. For a first-party tool
the operator can instrument the internals directly; for a third-party tool the internals are a
black box. Regulatory record-keeping regimes (e.g. EU AI Act Article 12) require reconstructable
audit trails of automated decisions, which the boundary alone cannot provide.

Adjacent work stops at that boundary:

- **SEP-3004** standardizes a tamper-evident, hash-chained audit *record contract*, scoped to
  the orchestrator-visible seam.
- **OpenTelemetry GenAI/MCP** conventions trace the call (arguments, result, latency) but state
  that operations *within* a tool require separate instrumentation.
- **Gateways** log what crosses them, by design.

Auditable MCP fills the remaining slice: **tool-internal, domain-semantic self-attestation,
anchored into a tamper-evident ledger.**

## 2. Scope and non-goals

This is **accountability, not control.**

- **In scope:** a tool voluntarily reporting the internal operations it performs, so the host
  can record them in a tamper-evident ledger, and refusing to record events that do not verify.
- **Out of scope — the operator's allowlist:** deciding whether a tool may connect, or whether
  a given operation is permitted. A host MUST NOT be expected to prevent an untrusted tool's
  actions in real time via this extension. Dangerous tools are excluded at the allowlist.

The host is a monitoring camera over already-allowlisted tools. It never authorizes a tool's
domain action. The only thing it refuses is a record that does not verify (§7). "Blocking" in
this document always means refusing an invalid record, never blocking a domain action.

## 3. Terminology

- **Tool** — an MCP server whose internal operations are audited.
- **Host** — the MCP client / orchestrator that receives audit events and seals them.
- **Event** — one audit record describing one internal operation (§4).
- **Ledger** — the host's append-only, hash-chained, tamper-evident store of sealed events.
- **Boundary** — the `tools/call` seam the host can observe directly.

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
| `target_resource` | object | `{ kind, ref, scope_hint? }` — the operation's domain target. |
| `outcome` | enum | `attempted` \| `success` \| `failed` \| `aborted` (§6). |
| `params_hash` | string | `sha256:<hex>` of the (masked) parameters. §4.3. |
| `sequence` | integer (optional) | Level 2. Per-tool monotonic counter. |
| `key_id` | string (optional) | Level 2. Identifies the signing key. |
| `signature` | string (optional) | Level 2. Detached signature (§5, §6). |

The `sequence`, `key_id`, and `signature` fields are OPTIONAL in the schema. This is a
deliberate invariant (§5): a Level-1 event is a valid Level-2 event.

### 4.1 `action_type` vocabulary

`action_type` is a dotted, lowercase token: a **Core Enum** plus an extension namespace.

- **Core Enum (v0.1):** `db.read`, `db.write`, `fs.read`, `fs.write`, `api.request`,
  `os.exec`, `secret.read`.
- **Extension:** `ext.<vendor>.<operation>` (e.g. `ext.stripe.refund_charge`). Queue/pubsub
  and compute-provisioning operations belong here, not in the Core Enum.

Syntax MUST be validated (the JSON Schema encodes the regex). **Core membership is a soft
classification, not a validation rule**: a host MUST NOT reject a syntactically valid
`action_type` merely because it is not a known Core value. This keeps a v0.1 host
forward-compatible with a future v0.2 Core value.

### 4.2 The effect axis

`mutates` and `egress` are REQUIRED and are **orthogonal to `action_type`**, because
`api.request` and `ext.*` hide the security-relevant axis in an opaque verb. A read-only web
search, for example, is `mutates: false` yet `egress: true` — the query itself leaves the
boundary.

A host that cannot positively establish an operation as non-mutating and non-egressing MUST
treat it as `mutates: true, egress: true` (fail-safe). The tool's declared effect is advisory;
a Level-2 host MAY override it with its own classification, and a mismatch is itself a signal.

### 4.3 Confidentiality

`params_hash` MUST be a hash, never the raw parameters — the parameters (e.g. a search query)
may themselves be the sensitive data. Raw prompt text, tokens, and PII MUST NOT appear in an
event.

## 5. Conformance levels

There is one event schema and two conformance levels. **Invariant: every Level-1 event is a
valid Level-2 event (L1 ⊆ L2).** The level difference is host-side obligation layered on the
same schema, never a divergent payload.

| | Level 1 (trusted) | Level 2 (verifiable) |
|--|-------------------|----------------------|
| Event body | core event | the same core event |
| Trust basis | established out-of-band (onboarding) | the tool **signs** each event |
| Tool adds | nothing | `signature` + monotonic `sequence` |
| Host MUST | record as authoritative | verify signatures; reject invalid ones; detect sequence gaps |

A tool escalates L1 → L2 by attaching a signer; its emission logic is otherwise unchanged.
Level 2 provides **evidentiary strength (non-repudiation and completeness), not action
control.**

## 6. Protocol

Auditable MCP reuses the **wire shape** of MCP elicitation — a server→client request/response
issued while a `tools/call` is being processed — but NONE of its human-in-the-loop semantics.
The responder is the host's audit subsystem, not a human; no computation is suspended.

- **`audit/attempt`** — a server→client **request**, sent immediately before the internal
  operation, carrying an event with `outcome: attempted`. The tool MUST await the response and
  MUST NOT perform the operation unless the response is `accept` (§7). This is audit-before-act.
- **`audit/outcome`** — a server→client **notification**, sent after the operation, carrying an
  event with `outcome: success` or `failed`. It is not a completeness gate; a lost outcome is
  detected by the sequence gap it leaves.

`denied` and `expired` are outcomes produced by host-side boundary control (the allowlist) and
by abandoned confirmations, respectively. They are not responses to `audit/attempt`; a
tool-internal event never carries them.

### 6.1 Capability negotiation

The host declares its audit requirements at initialization; the tool complies or fails
observably. The declaration flows host→tool only, so a tool cannot weaken record integrity via
what it declares. See [`schema/audit-capability.schema.json`](schema/audit-capability.schema.json).

- `level` — `L1` or `L2`.
- `attempt` — always `request` (fail-closed).
- `attempt_ack_deadline_ms` — how long the tool waits for `accept` before treating the attempt
  as `unavailable`.
- `block_disposition` — how a blocked operation is surfaced in the `tools/call` result. `abort`
  is the always-present safe floor; `partial` is opt-in. There is no option that lets a tool
  proceed without a valid record.
- `outcome_mode` — `batched` (default) or `request`.

## 7. Host behavior

On `audit/attempt` the host MUST respond with exactly one of:

- **`accept`** — the event was durably recorded. The tool MAY proceed. The response carries the
  assigned `sequence` and `record_hash`.
- **`reject`** — the event is invalid: schema-invalid, or (Level 2) an unregistered key, an
  invalid signature, or a replayed sequence. The tool MUST NOT proceed. The event MUST NOT be
  sealed. `reject` refuses a lie into the ledger; it is not an action-policy decision.
- **`unavailable`** — the host could not durably record the event (a transient failure). The
  tool MUST NOT proceed. This is retryable.

Fail-closed here is about **record completeness** — no valid record, no action — not about
authorizing the action.

The host seals each accepted event by assigning a partition-monotonic `sequence`, the previous
record's hash as `prev_hash`, and a `record_hash` (§8). A replayed `id` MUST be rejected.

### 7.1 Level-2 detection

Under Level 2 the host MUST verify each signature against a public key registered out-of-band,
and MUST track each tool's `sequence`. A missing/invalid signature or a replayed sequence is
rejected. A **forward** sequence gap indicates a suppressed prior event; the host flags it but
does not reject the current event, since the missing event cannot be recovered.

### 7.2 Reconciliation

A host MAY cross-check self-reported egress events against egress it observes independently at
the boundary. An observed egress with no matching self-report is a suppression by omission —
the one form of lie that signatures and sequence gaps cannot catch, because the tool simply
never emits the event. This feeds allowlist governance, not real-time control.

## 8. Canonicalization and hashing

The ledger's integrity depends on a canonical serialization that every implementation
reproduces byte-for-byte:

- Object keys sorted recursively.
- No insignificant whitespace.
- Non-ASCII characters preserved (UTF-8).
- `null` preserved; absent (optional) fields omitted.

Hashes are SHA-256 over the UTF-8 canonical bytes. The record hash is:

```
record_hash = SHA256( canonical(event) | seq | host_ts | prev_hash )
```

Records chain by `prev_hash`; the tail `record_hash` is the ledger digest, which MAY be
anchored out-of-band. A verifier recomputes the chain from the event bytes: because chaining
uses the recomputed hash, any mutation of any field propagates to the digest.

Golden conformance vectors — canonicalization, per-event hashes, and a full sealed chain — are
published under [`vectors/`](vectors). A conforming implementation MUST reproduce them exactly.

## 9. Relationship to SEP-3004

SEP-3004 defines a tamper-evident audit record contract at the orchestrator-visible boundary.
Auditable MCP does not replace it. The events defined here are the **tool-internal records**
that a host anchors, using SEP-3004's contract as the ledger's record format where applicable.
Auditable MCP is the layer that *produces* internal domain records; SEP-3004 is a way to *seal*
them.

## 10. Security considerations

- **Trust model.** Level 1 trusts the tool's self-report (trust established at onboarding).
  Level 2 makes records non-repudiable and omissions detectable, but cannot force an untrusted
  tool to report honestly — that is the allowlist's job (§2). This extension raises the
  evidentiary strength of what allowlisted tools report; it does not vet the tools.
- **No secrets in events.** See §4.3.
- **Capability direction.** Capability flows host→tool only (§6.1); a tool cannot use it to
  lower the host's integrity requirements.

## 11. Conformance

An implementation conforms if it:

1. Validates events against `schema/audit-event.schema.json`.
2. Reproduces every vector under `vectors/` byte-for-byte.
3. Implements audit-before-act: no `accept`, no action (§7).
4. For Level 2: signs events over `canonical(event − signature)`, and (host side) rejects
   invalid signatures and replayed sequences and flags forward gaps.

## 12. References

- SEP-3004 — Tamper-Evident Audit Record Contract (`modelcontextprotocol/modelcontextprotocol#3004`)
- MCP #3023 — provenance on `CallToolResult`
- OWASP MCP08:2025 — Lack of Audit and Telemetry
- OpenTelemetry GenAI + MCP semantic conventions
- EU AI Act, Article 12 (record-keeping)
- RFC 2119 — key words for requirement levels
