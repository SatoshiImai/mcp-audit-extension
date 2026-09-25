# Auditable MCP

> **NOTICE:** This repository contains a draft specification proposal for the Model Context Protocol (MCP) ecosystem. It is **not** a production SDK or a library. The provided codebases are strictly reference implementations demonstrating protocol conformance.

Auditable MCP is a proposed extension protocol that enables an MCP tool server to self-attest its internal domain operations. These operations are emitted as structured audit events, which the host records into a tamper-evident ledger before the tool performs them.

It is an MCP extension in the sense of [SEP-2133](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2133), declared under the `extensions` capability member as `com.timberlandchapel/auditable-mcp`. Two independent axes describe an audit exchange: the **conformance level** (L1, or L2 adding signatures and sequencing) states how strongly a tool's attestation resists forgery, and the **countersignature** states whether the host that sealed a record signed for having done so.

**The record is kept apart from the wire.** The event, the ledger, and their verification do not depend on the MCP wire; each MCP protocol version has a binding of its own. Under MCP `2026-07-28` the exchange rides the `tools/call` itself through Multi Round-Trip Requests; under earlier versions it uses a server-to-client request. A change to MCP revises a binding and nothing else.

**A tool that speaks this extension still works with hosts that do not.** Where the host has not declared it, the tool sends no audit message and serves the call exactly as a build without the extension would, recording into an audit host it provides for itself. The specification names the admissible fallbacks and forbids the one that serves a call while recording nothing.

- **Read the specification:** [`spec/auditable-mcp.md`](spec/auditable-mcp.md)
- **Normative artifacts:** [`spec/schema/`](spec/schema) (JSON Schema), [`spec/vectors/`](spec/vectors) (Conformance vectors)

## Architecture & Scope

Existing MCP observability mechanisms terminate at the orchestrator-visible boundary. Gateways log network traffic, OpenTelemetry semantic conventions trace call attributes, and **SEP-3004** proposes a tamper-evident record contract for the boundary. However, the exact execution _inside_ a third-party tool remains opaque, and none of them records an operation before it happens.

This specification provides the missing interior observability layer. It produces the interior audit records, recorded before the operation; a boundary record such as SEP-3004's can carry them as its storage format.

**Accountability, not authorization:**
The protocol provides detective control, not preventive control. The host acts as a monitoring camera over tools that have already been allowlisted by the operator, recording to an append-only ledger. It enforces ledger integrity (rejecting malformed, replayed, or - under Level 2 - forged records) but does not evaluate or intercept the semantic execution of the tool's domain actions.

## Repository Layout

| Path                                             | Role                                                                   | Normative |
| :----------------------------------------------- | :--------------------------------------------------------------------- | :-------: |
| [`spec/auditable-mcp.md`](spec/auditable-mcp.md) | The specification (prose).                                             |    Yes    |
| [`spec/schema/`](spec/schema)                    | JSON Schema defining the wire contracts (event, capability, response, and the `_meta` objects of the 2026-07-28 binding). |    Yes    |
| [`spec/vectors/`](spec/vectors)                  | Golden vectors for canonicalization, hashing, signatures, the sealed chain, and `signer_seq` accounting. |    Yes    |
| [`reference/typescript/`](reference/typescript)  | Non-normative reference implementation (conformance demo).             |     -     |
| [`reference/python/`](reference/python)          | Non-normative reference implementation (conformance demo).             |     -     |

### Cross-Language Interoperability

The TypeScript and Python reference implementations validate against the **same** language-neutral schemas and conformance vectors. The JSON Canonicalization Scheme (RFC 8785) mandated by the specification is what makes this checkable: two conformant implementations reproduce the cryptographic hashes and ledger digests byte-for-byte, and the vectors are how either one is held to it.

### Running the Conformance Demos

To verify the cross-language byte-for-byte conformance and see the integrity enforcement in action:

- **TypeScript:** `cd reference/typescript && npm install && npm test && npm run demo`
- **Python:** `cd reference/python && uv sync && uv run pytest && PYTHONPATH=src uv run python -m auditable_mcp.demo.demo`

## Status

Draft proposal - `auditable-mcp/0.3`.

## Author & License

Satoshi Imai  
Licensed under the [MIT License](LICENSE).
