# Auditable MCP — TypeScript reference implementation

> A conformance demonstration of the [Auditable MCP specification](../../spec/auditable-mcp.md).
> It validates against the shared [`spec/`](../../spec) contract. It is **not** a product or a
> library to build on.

Reference implementation for **Auditable MCP**: a tool server self-attests its
**internal** domain operations (DB reads/writes, downstream API calls) as first-class
structured audit events, which the host anchors into a **tamper-evident ledger**.

This PoC proves the Level 1 (trusted / self-attesting) path end to end. It is self-contained
and deterministic — **no AWS required**; the 3-tier ledger (durable accept → seal → anchor)
is simulated locally, because the standardization-relevant artifact is the hash chain, not
the infrastructure.

## What it proves

Run `npm run demo`:

1. **Clean run** — a first-party SQL analyst tool self-attests each internal op; the ledger
   `✅ VERIFIED (non-tampered + complete)` and matches the anchored digest. The ops span the
   effect axis, including the case naive "reads are safe" thinking misses: a `db.query` shows
   `mut=0 egr=1` — it mutates nothing, yet the **query egresses** to the database. The tables
   touched are disclosed in cleartext, while the exact SQL is sealed as an `action_context_hash`.
2. **Tamper** — flip one sealed field → recompute breaks the chain → `record-hash-mismatch` + `digest-mismatch`.
3. **Loss** — drop one sealed record → `seq-gap` + `digest-mismatch` (completeness).
4. **Reject** — a replayed (forged) attempt id is refused; the ledger stays clean (a lie is blocked from the camera, not the tool's action).
5. **Fail-closed** — Tier1 unavailable ⇒ the tool does **not** perform the internal action (no record, no action).

## Level 2 (verifiable / non-repudiation)

Run `npm run demo:l2`. L2 adds cryptographic evidentiary strength on the **same event
schema** (L1 ⊆ L2): the tool signs each event (Ed25519 over `canonical(event − signature)`)
and stamps a per-tool monotonic `sequence`. The host verifies against a public key
registered out-of-band (onboarding), and:

1. **Portable escalation** — the *same* tool code becomes L2 by attaching a signer; the
   audit-before-act logic is unchanged (`AmcpSession`'s only new argument).
2. **Forgery** — a record altered after signing → `reject: signature-invalid`; ledger stays clean.
3. **Unsigned under L2** → `reject: l2-unsigned` (needs escalation).
4. **Suppression via gap** — a skipped `sequence` exposes a hidden event → flagged.
5. **Suppression by omission** — `reconcile()` compares self-reports to boundary-observed
   egress; an egress the boundary saw but the tool never reported → `unreported-egress`.
   This is the one lie signatures alone cannot catch (the tool simply never emits).

L2's guarantee is **evidentiary strength (non-repudiation + completeness), not action
control**. The tool is already allowlisted by the host; L2 only makes its records
impossible to forge or repudiate, and its omissions detectable.

## Design boundary (why this is audit, not control)

The host is a **monitoring camera over already-allowed tools**, not a real-time gate.
Deciding whether to connect a tool is the operator's allowlist job. The host's only "block" is
refusing a **lie into the ledger** (`reject`) or failing closed when it cannot record
(`unavailable`). Neither authorizes the tool's domain action.

## Transport

The `AuditTransport` interface is shaped to the MCP elicitation wire (server→client
request/response during tool execution).

- **B1** — `InProcessTransport` (direct calls; also a fast test double).
- **B2** — `McpTransport` over the **real MCP SDK**: the tool runs as an MCP server that
  sends `audit/attempt` (server→client request) and `audit/outcome` (notification) to the
  host running as an MCP client, connected via `InMemoryTransport`. See `src/mcp/`.

The swap is a drop-in: the tool (`AmcpSession`, `SqlAnalystTool`), host (`AuditHost`),
ledger, and verifier are **byte-identical** across B1 and B2 — only the transport differs
(`src/mcp/mcp.test.ts` proves the same seal + verify over the wire, including fail-closed).
`audit/attempt` reuses the elicitation *wire form* (a server-initiated request during
`tools/call`), never its human-in-the-loop semantics.

## Layout

| Path | Role |
|------|------|
| `src/schema/` | Zod SoT: core event + capability (`npm run schema:json` emits JSON Schema) |
| `src/ledger/` | canonical JSON + Tier1/Tier2 sealer (sequence + hash chain) |
| `src/transport/` | wire-shaped `AuditTransport` + `InProcessTransport` (B1) + `McpTransport` (B2) |
| `src/host/` | audit subsystem: `accept` / `reject` / `unavailable` |
| `src/tool/` | audit-before-act library + dummy first-party SQL analyst tool (NL question → internal SQL) |
| `src/l2/` | signing (Ed25519), key registry, reconciliation (Level 2) |
| `src/mcp/` | MCP SDK wiring (tool server + host client over `InMemoryTransport`) |
| `src/verify/` | chain recompute, gap + tamper detection (`npm run verify`) |
| `src/demo/` | the 5-scenario walkthrough (`npm run demo`) |

## Conformance vectors

`npm run vectors` regenerates golden files under the repo-shared `../../spec/vectors/` that any
independent implementation (including the Python port) must reproduce byte-for-byte — the
Auditable MCP analogue of SEP-3004's conformance vectors. The JSON Schema (`../../spec/schema/`) and
these vectors are the language-neutral contract both reference implementations validate against:

- `canonicalization.json` — canonical serialization of primitives (key order, nesting, unicode, scalars).
- `events.json` — canonical bytes + sha256 for representative events (L1 minimal → L2 signed).
- `chain.json` — a full sealed chain (sequence + previous_hash + record_hash + anchored digest).

`vectors.test.ts` recomputes from the stored inputs and asserts equality, so the wire
contract cannot drift silently: change canonicalization/hashing → regenerate or the fence fails.

## Commands

```
npm install
npm test             # 50 tests (incl. conformance vectors, MCP wire, L2)
npm run demo         # L1 end-to-end walkthrough
npm run demo:l2      # L2: signing, forgery reject, gap + suppression detection
npm run verify       # verify the built-in scenario ledger (exit code reflects ok)
npm run schema:json  # emit JSON Schema from the Zod SoT → ../../spec/schema/*.json
npm run vectors      # regenerate conformance golden files → ../../spec/vectors/*.json
```
