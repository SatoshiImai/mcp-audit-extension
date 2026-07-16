import { describe, it, expect } from 'vitest';
import { Ledger, GENESIS_HASH } from './ledger.js';
import { canonicalize } from './canonical.js';
import type { AuditEvent } from '../schema/event.js';

function ev(id: string, outcome: AuditEvent['outcome']): AuditEvent {
  return {
    id,
    spec_version: 'a-mcp/0.1',
    ts: new Date(1_000_000).toISOString(),
    call_id: 'call_abc',
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome,
    params_hash: `sha256:${'0'.repeat(64)}`,
  };
}

describe('Ledger — sequence + hash chain', () => {
  it('assigns contiguous sequence from 0 and links prev_hash', () => {
    const l = new Ledger('t#d');
    const a = l.append(ev('00000000-0000-4000-8000-000000000001', 'attempted'), 'host-ts:1');
    const b = l.append(ev('00000000-0000-4000-8000-000000000001', 'success'), 'host-ts:2');
    expect(a.seq).toBe(0);
    expect(b.seq).toBe(1);
    expect(a.prev_hash).toBe(GENESIS_HASH);
    expect(b.prev_hash).toBe(a.record_hash);
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

describe('canonicalize — deterministic serialization', () => {
  it('is independent of key insertion order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });

  it('omits undefined-valued keys', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});
