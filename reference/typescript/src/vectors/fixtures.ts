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

const ZERO_HASH = `sha256:${'0'.repeat(64)}`;

// Valid AuditEvents covering: minimal (both context fields absent), a db.query carrying both
// cleartext action_context and a sealed action_context_hash, and a Level-2 event committing
// action_context_hash with signature/sequence/unicode - the shared-schema shape and the two
// confidentiality choices (§4.3) in one file.
export const EVENT_CASES: Array<{ name: string; event: AuditEvent }> = [
  {
    name: 'db-read-minimal',
    event: {
      id: pid(1),
      spec_version: 'auditable-mcp/0.1',
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
      spec_version: 'auditable-mcp/0.1',
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
      spec_version: 'auditable-mcp/0.1',
      ts: '2026-07-15T00:00:03.000Z',
      call_id: 'call_xyz',
      action_type: 'ext.stripe.refund_charge',
      mutates: true,
      egress: true,
      target_resource: { kind: 'endpoint', ref: 'https://api.stripe.com/v1/refunds', scope_hint: 'clïent:c_1' },
      outcome: 'attempted',
      action_context_hash: `sha256:${'a'.repeat(64)}`,
      sequence: 42,
      key_id: 'tool-key-2026',
      signature: 'ZmFrZS1zaWduYXR1cmU=',
    },
  },
  {
    name: 'secret-read',
    event: {
      id: pid(4),
      spec_version: 'auditable-mcp/0.1',
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
];
