import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { AuditHost } from './auditHost.js';
import { SPEC_VECTORS_DIR } from '../paths.js';
import type { AuditEvent } from '../schema/event.js';

function attempt(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    spec_version: 'auditable-mcp/0.2',
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

describe('AuditHost - accept / reject / unavailable', () => {
  it('accepts a valid attempt and seals it', () => {
    const host = new AuditHost('t#d');
    const res = host.handleAttempt(attempt());
    expect(res.status).toBe('accept');
    expect(host.records()).toHaveLength(1);
  });

  it('rejects a schema-invalid record (a forged/invalid record) without sealing it', () => {
    const host = new AuditHost('t#d');
    const res = host.handleAttempt({ ...attempt(), action_context_hash: 'not-a-hash' });
    expect(res.status).toBe('reject');
    expect(host.records()).toHaveLength(0);
    expect(host.getAnomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('rejects (not throws) a non-canonicalizable number: out-of-range or non-finite (§8.1)', () => {
    const host = new AuditHost('t#d');
    expect(host.handleAttempt(attempt({ action_context: { rows: 9007199254740992 } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.handleAttempt(attempt({ action_context: { x: Infinity } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.handleAttempt(attempt({ action_context: { x: NaN } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.records()).toHaveLength(0);
  });

  it('rejects a replayed attempt id and keeps the ledger clean', () => {
    const host = new AuditHost('t#d');
    expect(host.handleAttempt(attempt()).status).toBe('accept');
    const res = host.handleAttempt(attempt()); // same id
    expect(res.status).toBe('reject');
    expect(host.records()).toHaveLength(1);
    expect(host.getAnomalies().some((a) => a.kind === 'replay-detected')).toBe(true);
  });

  it('returns unavailable (fail-closed, retryable) when persistence fails', () => {
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
    expect(host.getAnomalies().some((a) => a.kind === 'replay-detected')).toBe(true);
  });

  it('does not flag a fail-closed aborted outcome for a never-accepted attempt (§10.4)', () => {
    const host = new AuditHost('t#d');
    host.handleOutcome(attempt({ outcome: 'aborted', reason: 'host-rejected' }));
    expect(host.getAnomalies()).toHaveLength(0);
    expect(host.records()).toHaveLength(0);
    host.handleOutcome(attempt({ outcome: 'success' }));
    expect(host.getAnomalies().some((a) => a.kind === 'orphaned-outcome')).toBe(true);
  });

  it('flags a reason-less aborted outcome as schema-invalid (§7.2 presence rule)', () => {
    const host = new AuditHost('t#d');
    host.handleOutcome(attempt({ outcome: 'aborted' })); // no reason
    expect(host.getAnomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
    expect(host.records()).toHaveLength(0);
  });

  it('drops an attempted outcome on the audit/outcome channel and flags schema-invalid (§6)', () => {
    const host = new AuditHost('t#d');
    host.handleAttempt(attempt());
    host.handleOutcome(attempt({ outcome: 'attempted' }));
    expect(host.records()).toHaveLength(1);
    expect(host.getAnomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('seals every correlated outcome, not de-duplicated (§8.3)', () => {
    const host = new AuditHost('t#d');
    host.handleAttempt(attempt());
    host.handleOutcome(attempt({ outcome: 'success' }));
    host.handleOutcome(attempt({ outcome: 'success' }));
    expect(host.records()).toHaveLength(3);
    expect(host.getAnomalies()).toHaveLength(0);
  });
});

describe('conformance vectors - negative cases (error-cases.json)', () => {
  const cases = JSON.parse(readFileSync(resolve(SPEC_VECTORS_DIR, 'error-cases.json'), 'utf8')) as Array<{
    name: string;
    channel: 'attempt' | 'outcome';
    event: unknown;
    expect: { status?: string; reason?: string; sealed?: boolean; anomaly_kind?: string };
  }>;

  for (const c of cases) {
    it(`refuses "${c.name}" (${c.channel}) with the pinned Tier-1 code`, () => {
      const host = new AuditHost('t#d');
      if (c.channel === 'attempt') {
        expect(host.handleAttempt(c.event)).toMatchObject({ status: c.expect.status, reason: c.expect.reason });
      } else {
        host.handleOutcome(c.event);
        expect(host.records()).toHaveLength(0);
        expect(host.getAnomalies().some((a) => a.kind === c.expect.anomaly_kind)).toBe(true);
      }
    });
  }
});
