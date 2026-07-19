# Auditable MCP

> **NOTICE:** This repository contains a draft specification proposal for the Model Context Protocol (MCP) ecosystem. It is **not** a production SDK or a library. The provided codebases are strictly reference implementations demonstrating protocol conformance.

Auditable MCP is a proposed extension protocol that enables an MCP tool server to self-attest its internal domain operations, optionally reinforced by cryptographic signatures and sequencing at Level 2. These operations are emitted as structured audit events, which the host subsequently anchors into a tamper-evident ledger.

- **Read the specification:** [`spec/auditable-mcp.md`](spec/auditable-mcp.md)
- **Normative artifacts:** [`spec/schema/`](spec/schema) (JSON Schema), [`spec/vectors/`](spec/vectors) (Conformance vectors)

## Architecture & Scope

Existing MCP observability mechanisms terminate at the orchestrator-visible boundary. Gateways log network traffic, OpenTelemetry semantic conventions trace call attributes, and **SEP-3004** standardizes a tamper-evident storage contract for the envelope. However, the exact execution _inside_ a third-party tool remains opaque.

This specification provides the missing interior observability layer. It produces the interior audit records; SEP-3004 provides the envelope and storage contract to seal them.

**Accountability, not authorization:**
The protocol provides detective control, not preventive control. The host acts as a monitoring camera over tools that have already been allowlisted by the operator, recording to an append-only ledger. It enforces ledger integrity (rejecting malformed, replayed, or - under Level 2 - forged records) but does not evaluate or intercept the semantic execution of the tool's domain actions.

## Repository Layout

| Path                                             | Role                                                                   | Normative |
| :----------------------------------------------- | :--------------------------------------------------------------------- | :-------: |
| [`spec/auditable-mcp.md`](spec/auditable-mcp.md) | The specification (prose).                                             |    Yes    |
| [`spec/schema/`](spec/schema)                    | JSON Schema defining the wire contracts (event, capability, response). |    Yes    |
| [`spec/vectors/`](spec/vectors)                  | Golden vectors for canonicalization, hashing, and the sealed chain.    |    Yes    |
| [`reference/typescript/`](reference/typescript)  | Non-normative reference implementation (conformance demo).             |     -     |
| [`reference/python/`](reference/python)          | Non-normative reference implementation (conformance demo).             |     -     |

### Cross-Language Interoperability

The TypeScript and Python reference implementations validate against the **same** language-neutral schemas and conformance vectors. By strictly adhering to the JSON Canonicalization Scheme (RFC 8785) mandated by the specification, both implementations reproduce the cryptographic hashes and ledger digests byte-for-byte, proving deterministic interoperability.

### Running the Conformance Demos

To verify the cross-language byte-for-byte conformance and see the integrity enforcement in action:

- **TypeScript:** `cd reference/typescript && npm install && npm test && npm run demo`
- **Python:** `cd reference/python && uv sync && uv run pytest && PYTHONPATH=src uv run python -m auditable_mcp.demo.demo`

## Status

Draft proposal - `auditable-mcp/0.1`.

## Author & License

Satoshi Imai  
Licensed under the [MIT License](LICENSE).
