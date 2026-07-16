import type { AuditEvent } from '../schema/event.js';

// Conformance fixtures — the fixed inputs a golden vector file is derived from. Any
// independent A-MCP implementation must reproduce the same canonical bytes and hashes from
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
  { name: 'unicode', value: { note: 'café — 日本語 — 🔒 lock' } },
  { name: 'scalars', value: { i: 0, big: 1234567890, neg: -5, t: true, f: false, z: null, s: 'x' } },
  { name: 'empty', value: {} },
];

function pid(n: number): string {
  return `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
}

const ZERO_HASH = `sha256:${'0'.repeat(64)}`;

// Valid AuditEvents covering: minimal (all optionals absent), full core, and a Level-2
// event with signature/sequence/unicode — the L1 ⊆ L2 shape in one file.
export const EVENT_CASES: Array<{ name: string; event: AuditEvent }> = [
  {
    name: 'db-read-minimal',
    event: {
      id: pid(1),
      spec_version: 'a-mcp/0.1',
      ts: '2026-07-15T00:00:01.000Z',
      call_id: 'call_abc',
      action_type: 'db.read',
      mutates: false,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'attempted',
      params_hash: ZERO_HASH,
    },
  },
  {
    name: 'db-write-with-trace-and-scope',
    event: {
      id: pid(2),
      spec_version: 'a-mcp/0.1',
      ts: '2026-07-15T00:00:02.000Z',
      call_id: 'call_abc',
      traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers', scope_hint: 'row:consent_basis=marketing' },
      outcome: 'success',
      params_hash: ZERO_HASH,
    },
  },
  {
    name: 'ext-l2-signed-unicode',
    event: {
      id: pid(3),
      spec_version: 'a-mcp/0.1',
      ts: '2026-07-15T00:00:03.000Z',
      call_id: 'call_xyz',
      action_type: 'ext.stripe.refund_charge',
      mutates: true,
      egress: true,
      target_resource: { kind: 'endpoint', ref: 'https://api.stripe.com/v1/refunds', scope_hint: '顧客:c_1' },
      outcome: 'attempted',
      params_hash: `sha256:${'a'.repeat(64)}`,
      sequence: 42,
      key_id: 'tool-key-2026',
      signature: 'ZmFrZS1zaWduYXR1cmU=',
    },
  },
  {
    name: 'secret-read',
    event: {
      id: pid(4),
      spec_version: 'a-mcp/0.1',
      ts: '2026-07-15T00:00:04.000Z',
      call_id: 'call_abc',
      action_type: 'secret.read',
      mutates: false,
      egress: false,
      target_resource: { kind: 'secret', ref: 'db/password' },
      outcome: 'success',
      params_hash: ZERO_HASH,
    },
  },
];
