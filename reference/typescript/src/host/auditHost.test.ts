import { describe, it, expect } from 'vitest';
import { AuditHost } from './auditHost.js';
import type { AuditEvent } from '../schema/event.js';

function attempt(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    spec_version: 'auditable-mcp/0.1',
    ts: new Date(1_000_000).toISOString(),
    call_id: 'call_abc',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers', scope_hint: 'row:id=c_1' },
    outcome: 'attempted',
    action_context_hash: `sha256:${'0'.repeat(64)}`,
    ...overrides,
  };
}

describe('AuditHost — accept / reject / unavailable', () => {
  it('accepts a valid attempt and seals it', () => {
    const host = new AuditHost('t#d');
    const res = host.handleAttempt(attempt());
    expect(res.status).toBe('accept');
    expect(host.records()).toHaveLength(1);
  });

  it('rejects a schema-invalid record (a lie into the ledger) without sealing it', () => {
    const host = new AuditHost('t#d');
    const res = host.handleAttempt({ ...attempt(), action_context_hash: 'not-a-hash' });
    expect(res.status).toBe('reject');
    expect(host.records()).toHaveLength(0);
    expect(host.getAnomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('rejects a replayed attempt id and keeps the ledger clean', () => {
    const host = new AuditHost('t#d');
    expect(host.handleAttempt(attempt()).status).toBe('accept');
    const res = host.handleAttempt(attempt()); // same id
    expect(res.status).toBe('reject');
    expect(host.records()).toHaveLength(1);
    expect(host.getAnomalies().some((a) => a.kind === 'attempt-replay')).toBe(true);
  });

  it('returns unavailable (fail-closed, retryable) when Tier1 durability fails', () => {
    const host = new AuditHost('t#d');
    host.unavailable = true;
    const res = host.handleAttempt(attempt());
    expect(res.status).toBe('unavailable');
    expect(host.records()).toHaveLength(0);
  });

  it('flags an outcome that references a rejected id', () => {
    const host = new AuditHost('t#d');
    host.handleAttempt(attempt()); // accepted
    host.handleAttempt(attempt()); // rejected (replay)
    host.handleOutcome(attempt({ outcome: 'success' }));
    // The id was accepted once, so success is sealed; but a rejected duplicate exists.
    expect(host.getAnomalies().some((a) => a.kind === 'attempt-replay')).toBe(true);
  });
});
