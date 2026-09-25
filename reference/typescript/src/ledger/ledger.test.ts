import { describe, it, expect } from 'vitest';
import { Ledger, GENESIS_HASH } from './ledger.js';
import { canonicalize } from './canonical.js';
import type { AuditEvent } from '../schema/event.js';

function ev(id: string, outcome: AuditEvent['outcome']): AuditEvent {
  return {
    id,
    spec_version: 'auditable-mcp/0.3',
    ts: new Date(1_000_000).toISOString(),
    session_id: '0198f3a2-5c1e-7000-8000-00000000abc0',
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome,
    action_context_hash: `sha256:${'0'.repeat(64)}`,
  };
}

describe('Ledger - sequence + hash chain', () => {
  it('assigns contiguous sequence from 0 and links previous_hash', () => {
    const l = new Ledger('t#d');
    const a = l.append(ev('00000000-0000-4000-8000-000000000001', 'attempted'), 'host-ts:1');
    const b = l.append(ev('00000000-0000-4000-8000-000000000001', 'success'), 'host-ts:2');
    expect(a.seq).toBe(0);
    expect(b.seq).toBe(1);
    expect(a.previous_hash).toBe(GENESIS_HASH);
    expect(b.previous_hash).toBe(a.record_hash);
    expect(l.digest()).toBe(b.record_hash);
  });

  it('produces a deterministic record_hash for identical inputs', () => {
    const l1 = new Ledger('t#d');
    const l2 = new Ledger('t#d');
    const r1 = l1.append(ev('00000000-0000-4000-8000-000000000001', 'attempted'), 'host-ts:1');
    const r2 = l2.append(ev('00000000-0000-4000-8000-000000000001', 'attempted'), 'host-ts:1');
    expect(r1.record_hash).toBe(r2.record_hash);
  });
});

describe('canonicalize - deterministic serialization', () => {
  it('is independent of key insertion order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });

  it('omits undefined-valued keys', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('accepts the max JSON-safe integer but rejects one beyond it (§8.1)', () => {
    expect(() => canonicalize({ n: 9007199254740991 })).not.toThrow();
    expect(() => canonicalize({ n: 9007199254740992 })).toThrow(RangeError);
    expect(() => canonicalize({ ctx: { rows: 12345678901234567890 } })).toThrow(RangeError);
  });
});
