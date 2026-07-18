# Auditable MCP

**This is a specification proposal, not a product or SDK.** It proposes an extension to the
Model Context Protocol (MCP). The [`reference/typescript/`](reference/typescript) and [`reference/python/`](reference/python)
directories are **reference implementations that demonstrate conformance** to the
specification — they exist to prove the spec is implementable and interoperable, not to be
depended on or shipped.

- **Read the specification:** [`spec/auditable-mcp.md`](spec/auditable-mcp.md)
- **Normative artifacts:** [`spec/schema/`](spec/schema) (JSON Schema), [`spec/vectors/`](spec/vectors) (conformance vectors)

## What it proposes

A standardized way for an MCP tool server to **self-attest its internal domain operations**
(DB reads and writes, downstream API calls) as structured audit events that the host anchors
into a tamper-evident ledger.

Existing MCP audit stops at the orchestrator-visible boundary: SEP-3004 defines a
tamper-evident record contract for that seam, OpenTelemetry's GenAI/MCP conventions trace the
call, and gateways log what crosses them — but none see what a tool actually did *inside*.
This proposal fills that slice, and only that slice. It layers on top of SEP-3004 rather than
competing with it.

It is **accountability, not control**. The host is a monitoring camera over tools the operator
already allowlisted; it never authorizes a tool's domain action. The one thing it refuses is a
record that does not verify.

## Repository layout

| Path | Role | Normative? |
|------|------|:---:|
| [`spec/auditable-mcp.md`](spec/auditable-mcp.md) | The specification (prose) | ✅ |
| [`spec/schema/`](spec/schema) | JSON Schema for the audit event and capability | ✅ |
| [`spec/vectors/`](spec/vectors) | Conformance vectors: canonical bytes, hashes, sealed chain | ✅ |
| [`reference/typescript/`](reference/typescript) | Reference implementation — a conformance demo | — |
| [`reference/python/`](reference/python) | Reference implementation, mirror — a conformance demo | — |

The two implementations validate against the **same** schema and vectors, so they are provably
interoperable rather than merely similar: they produce byte-identical ledger digests. Neither
is intended as a library to build on.

## Status

Draft proposal. Not yet submitted to the MCP community.

## Author

Satoshi Imai

Licensed under [MIT](LICENSE).
