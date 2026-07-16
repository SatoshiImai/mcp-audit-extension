# mcp-audit-extension

**[Proposal] Auditable MCP** — an extension to the Model Context Protocol (MCP) giving tool
servers a standardized way to self-attest their **internal** domain operations (DB reads and
writes, downstream API calls) as structured audit events that the host anchors into a
tamper-evident ledger.

Existing MCP audit stops at the orchestrator-visible boundary: SEP-3004 defines a
tamper-evident record contract for that seam, OpenTelemetry's GenAI/MCP conventions trace the
call, and gateways log what crosses them — but none see what a tool actually did *inside*.
This proposal fills that slice, and only that slice.

It is **accountability, not control**. The host is a monitoring camera over tools the operator
already allowlisted; it never authorizes a tool's domain action. The one thing it blocks is a
**lie into the ledger**.

## Layout

| Path | Role |
|------|------|
| `spec/schema/` | JSON Schema — the language-neutral contract (normative) |
| `spec/vectors/` | Conformance vectors — canonical bytes, hashes, sealed chain (normative) |
| `typescript/` | Reference implementation ([README](typescript/README.md)) |
| `python/` | Reference implementation, mirror ([README](python/README.md)) |

Both implementations validate against the **same** schema and vectors, so they are provably
interoperable rather than merely similar — they produce byte-identical ledger digests.

## Status

Early proposal. The specification text is not yet published here; the reference
implementations and the conformance contract are.

## Author

Satoshi Imai

Licensed under [MIT](LICENSE).
