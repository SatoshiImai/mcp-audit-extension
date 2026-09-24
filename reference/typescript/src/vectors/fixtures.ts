import type { AuditEvent } from '../schema/event.js';

// Conformance fixtures - the fixed inputs a golden vector file is derived from. Any
// independent Auditable MCP implementation must reproduce the same canonical bytes and hashes from
// these inputs. Kept JSON-representable (no undefined, no floats) so they round-trip through
// the committed golden files and cross-language ports.

export interface CanonicalizationCase {
  name: string;
  value: unknown;
}

// Stress the canonicalization algorithm itself (key ordering, nesting, unicode, numbers).
export const CANONICALIZATION_CASES: CanonicalizationCase[] = [
  { name: 'key-order', value: { b: 1, a: 2, c: 3 } },
  { name: 'nested-object-and-array', value: { z: { y: 2, x: 1 }, a: [3, 2, 1], m: { n: [{ q: 1, p: 2 }] } } },
  // 2/3/4-byte UTF-8, incl. a surrogate-pair emoji: verifies canonical output emits raw UTF-8, not \u escapes.
  { name: 'unicode', value: { note: 'café — Ünïcödé — 🔒 lock' } },
  { name: 'scalars', value: { i: 0, big: 1234567890, neg: -5, t: true, f: false, z: null, s: 'x' } },
  // Boundary of the JSON-safe integer domain (§8.1); values beyond this are rejected, not canonicalized.
  { name: 'max-safe-int', value: { n: 9007199254740991 } },
  // Non-integer floats + exponents: pins ECMAScript Number-to-String agreement across ports.
  { name: 'floats', value: { a: 0.1, b: 1.5, c: -2.25, d: 1e-7 } },
  // Non-ASCII and astral keys: pins UTF-16 code-unit key ordering across ports.
  { name: 'non-ascii-keys', value: { é: 1, Ä: 2, a: 3, '🔒': 4 } },
  // Control characters: pins the mandatory JSON escapes and lowercase \u00xx form.
  { name: 'control-chars', value: { s: '\b\t\n\f\r' } },
  { name: 'empty', value: {} },
];

function pid(n: number): string {
  return `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
}

// A Level-2 signed attempt and its correlated signed outcome, for the signed-chain vector. The
// signatures are fixed opaque base64 strings (not live crypto): the vector pins that record_hash is
// computed over the FULL event including `signature` (§8.2), which is what forks Level-2 interop -
// so both ports must reproduce the same record_hash and digest over these signed bytes.
export const SIGNED_CHAIN_EVENTS: AuditEvent[] = [
  {
    id: pid(10),
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:10.000Z',
    call_id: 'call_l2',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'ledger_entries' },
    outcome: 'attempted',
    action_context_hash: `sha256:${'a'.repeat(64)}`,
    signer_seq: 42,
    key_id: 'tool-key-2026',
    signature: 'ZmFrZS1zaWduYXR1cmU=',
  },
  {
    id: pid(10),
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:11.000Z',
    call_id: 'call_l2',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'ledger_entries' },
    outcome: 'success',
    action_context_hash: `sha256:${'a'.repeat(64)}`,
    signer_seq: 43,
    key_id: 'tool-key-2026',
    signature: 'b3V0Y29tZS1zaWduYXR1cmU=',
  },
];

const ZERO_HASH = `sha256:${'0'.repeat(64)}`;

// Valid AuditEvents covering: minimal (both context fields absent), a db.query carrying both
// cleartext action_context and a sealed action_context_hash, and a Level-2 event committing
// action_context_hash with signature/signer_seq/unicode - the shared-schema shape and the two
// confidentiality choices (§4.3) in one file.
export const EVENT_CASES: Array<{ name: string; event: AuditEvent }> = [
  {
    name: 'db-read-minimal',
    event: {
      id: pid(1),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:01.000Z',
      call_id: 'call_abc',
      action_type: 'db.read',
      mutates: false,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'attempted',
    },
  },
  {
    name: 'db-query-with-trace-and-context',
    event: {
      id: pid(2),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:02.000Z',
      call_id: 'call_abc',
      traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      action_type: 'db.query',
      mutates: false,
      egress: true,
      target_resource: { kind: 'database', ref: 'analytics-postgres' },
      outcome: 'success',
      action_context: { dialect: 'postgres', tables_accessed: ['users', 'payments'] },
      action_context_hash: `sha256:${'a'.repeat(64)}`,
    },
  },
  {
    name: 'ext-l2-signed-unicode',
    event: {
      id: pid(3),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:03.000Z',
      call_id: 'call_xyz',
      action_type: 'ext.stripe.refund_charge',
      mutates: true,
      egress: true,
      target_resource: { kind: 'endpoint', ref: 'https://api.stripe.com/v1/refunds', scope_hint: 'clïent:c_1' },
      outcome: 'attempted',
      action_context_hash: `sha256:${'a'.repeat(64)}`,
      signer_seq: 42,
      key_id: 'tool-key-2026',
      signature: 'ZmFrZS1zaWduYXR1cmU=',
    },
  },
  {
    name: 'secret-read',
    event: {
      id: pid(4),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:04.000Z',
      call_id: 'call_abc',
      action_type: 'secret.read',
      mutates: false,
      egress: false,
      target_resource: { kind: 'secret', ref: 'db/password' },
      outcome: 'success',
      action_context_hash: ZERO_HASH,
    },
  },
  {
    // Pins the byte form of an aborted outcome carrying a Tier-1 abort code in `reason` (§7.2).
    name: 'aborted-outcome-host-rejected',
    event: {
      id: pid(5),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:05.000Z',
      call_id: 'call_abc',
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'aborted',
      reason: 'host-rejected',
    },
  },
  {
    // The witness axis adds two abort codes: a record no distinct party confirmed (§5.2, §7.2)...
    name: 'aborted-outcome-host-unwitnessed',
    event: {
      id: pid(6),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:06.000Z',
      call_id: 'call_abc',
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'aborted',
      reason: 'host-unwitnessed',
    },
  },
  {
    // ...and one whose witness signature was present and did not verify (§7.2, §11.4).
    name: 'aborted-outcome-host-signature-invalid',
    event: {
      id: pid(7),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:07.000Z',
      call_id: 'call_abc',
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'aborted',
      reason: 'host-signature-invalid',
    },
  },
];

// Negative conformance cases: an event a Level-1 host MUST refuse. An `attempt`-channel case is
// submitted to handleAttempt and MUST be rejected with the given Tier-1 reason; an `outcome`-channel
// case is submitted to handleOutcome and MUST be flagged with the given anomaly kind and not sealed.
// Pins cross-port agreement on the reject/anomaly vocabulary, including cases a pure JSON Schema
// cannot express (the numeric-domain boundary, §8.1) or that live only on the outcome channel.
export type ErrorCase =
  | { name: string; channel: 'attempt'; event: Record<string, unknown>; expect: { status: 'reject'; reason: string } }
  | { name: string; channel: 'outcome'; event: Record<string, unknown>; expect: { sealed: false; anomaly_kind: string } };

function attemptBase(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    id: pid(6),
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:06.000Z',
    call_id: 'call_abc',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
    action_context_hash: ZERO_HASH,
    ...overrides,
  };
}

export const ERROR_CASES: ErrorCase[] = [
  {
    name: 'numeric-domain-overflow',
    channel: 'attempt',
    event: attemptBase({ action_context: { rows: 9007199254740992 } }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    name: 'non-attempted-outcome-on-attempt',
    channel: 'attempt',
    event: attemptBase({ outcome: 'success' }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    name: 'malformed-action-context-hash',
    channel: 'attempt',
    event: attemptBase({ action_context_hash: 'not-a-sha256-hash' }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    // The aborted-reason presence MUST (§7.2): an aborted outcome with no Tier-1 abort code is
    // structurally invalid (schema if/then) and MUST NOT be sealed.
    name: 'aborted-missing-reason',
    channel: 'outcome',
    event: attemptBase({ outcome: 'aborted', action_context_hash: undefined }),
    expect: { sealed: false, anomaly_kind: 'schema-invalid' },
  },
];
