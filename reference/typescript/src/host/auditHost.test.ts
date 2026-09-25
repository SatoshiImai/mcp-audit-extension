import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { AuditHost } from './auditHost.js';
import { SPEC_VECTORS_DIR } from '../paths.js';
import type { AuditEvent } from '../schema/event.js';
import { canonicalize } from '../ledger/canonical.js';
import { computeRecordHash, GENESIS_HASH } from '../ledger/ledger.js';

const SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0';
const OTHER = '0198f3a2-5c1e-7000-8000-00000000abc1';

function attempt(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    spec_version: 'auditable-mcp/0.3',
    ts: new Date(1_000_000).toISOString(),
    session_id: SESSION,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers', scope_hint: 'row:id=c_1' },
    outcome: 'attempted',
    action_context_hash: `sha256:${'0'.repeat(64)}`,
    ...overrides,
  };
}

function openHost(): AuditHost {
  const host = new AuditHost('t#d');
  host.openSession(SESSION);
  return host;
}

describe('AuditHost - accept / reject / unavailable', () => {
  it('accepts a valid attempt and seals it', () => {
    const host = openHost();
    const res = host.handleAttempt(attempt());
    expect(res.status).toBe('accept');
    expect(host.records()).toHaveLength(1);
  });

  it('rejects a schema-invalid record (a forged/invalid record) without sealing it', () => {
    const host = openHost();
    const res = host.handleAttempt({ ...attempt(), action_context_hash: 'not-a-hash' });
    expect(res.status).toBe('reject');
    expect(host.records()).toHaveLength(0);
    expect(host.getAnomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('rejects (not throws) a non-canonicalizable number: out-of-range or non-finite (§8.1)', () => {
    const host = openHost();
    expect(host.handleAttempt(attempt({ action_context: { rows: 9007199254740992 } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.handleAttempt(attempt({ action_context: { x: Infinity } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.handleAttempt(attempt({ action_context: { x: NaN } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.records()).toHaveLength(0);
  });

  it('answers a byte-identical repeat of a sealed attempt with the original accept, sealing nothing (§7.1)', () => {
    const host = openHost();
    const first = host.handleAttempt(attempt());
    expect(first.status).toBe('accept');
    expect(host.handleAttempt(attempt())).toEqual(first);
    expect(host.records()).toHaveLength(1);
    expect(host.getAnomalies()).toHaveLength(0);
  });

  it('rejects an attempt id already sealed with a different event, and keeps the ledger clean', () => {
    const host = openHost();
    expect(host.handleAttempt(attempt()).status).toBe('accept');
    const res = host.handleAttempt(attempt({ target_resource: { kind: 'table', ref: 'salaries' } }));
    expect(res).toMatchObject({ status: 'reject', reason: 'replay-detected' });
    expect(host.records()).toHaveLength(1);
  });

  it('rejects an event whose session_id is not an open audit session (§6.3)', () => {
    const host = openHost();
    const res = host.handleAttempt(attempt({ session_id: '0198f3a2-5c1e-7000-8000-00000000ffff' }));
    expect(res).toMatchObject({ status: 'reject', reason: 'replay-detected' });
    expect(host.records()).toHaveLength(0);
  });

  it('accepts nothing for a session once its call has ended (§6.3)', () => {
    const host = openHost();
    host.closeSession(SESSION);
    expect(host.handleAttempt(attempt())).toMatchObject({ status: 'reject', reason: 'replay-detected' });
  });

  it('returns unavailable, which decides nothing, and accepts the identical attempt sent again (§7.1)', () => {
    const host = openHost();
    host.unavailable = true;
    expect(host.handleAttempt(attempt())).toEqual({ status: 'unavailable', reason: 'internal-error' });
    expect(host.records()).toHaveLength(0);
    host.unavailable = false;
    expect(host.handleAttempt(attempt()).status).toBe('accept');
    expect(host.records()).toHaveLength(1);
  });

  it('flags a success outcome for an attempt it rejected as orphaned, and seals nothing', () => {
    const host = openHost();
    host.handleAttempt({ ...attempt(), action_context_hash: 'not-a-hash' });
    host.handleOutcome(attempt({ outcome: 'success' }));
    expect(host.records()).toHaveLength(0);
    expect(host.getAnomalies().some((a) => a.kind === 'orphaned-outcome')).toBe(true);
  });

  it('seals the aborted outcome of an attempt it did not accept as a refusal, not an anomaly (§7.2, §10.4)', () => {
    const host = openHost();
    host.handleOutcome(attempt({ outcome: 'aborted', reason: 'host-rejected' }));
    expect(host.getAnomalies()).toHaveLength(0);
    expect(host.records()).toHaveLength(1);
    host.handleOutcome(attempt({ id: '00000000-0000-4000-8000-000000000002', outcome: 'success' }));
    expect(host.getAnomalies().some((a) => a.kind === 'orphaned-outcome')).toBe(true);
  });

  it('rejects an attempt whose operation already has a sealed outcome as replay-detected, sealing nothing (§7.1)', () => {
    const host = openHost();
    host.unavailable = true;
    expect(host.handleAttempt(attempt()).status).toBe('unavailable');
    host.unavailable = false;
    host.handleOutcome(attempt({ outcome: 'aborted', reason: 'host-unavailable' }));
    expect(host.records()).toHaveLength(1);
    expect(host.handleAttempt(attempt())).toEqual({ status: 'reject', reason: 'replay-detected' });
    expect(host.records()).toHaveLength(1);
    expect(host.getAnomalies().map((a) => a.kind)).toEqual(['replay-detected']);
  });

  it('records an unresolved attempt when the call ends without its outcome (§6.3)', () => {
    const host = openHost();
    host.handleAttempt(attempt());
    host.closeSession(SESSION);
    expect(host.getAnomalies().map((a) => a.kind)).toEqual(['unresolved-attempt']);
  });

  it('records nothing at the end of a call whose attempts were all resolved', () => {
    const host = openHost();
    host.handleAttempt(attempt());
    host.handleOutcome(attempt({ outcome: 'success' }));
    host.closeSession(SESSION);
    expect(host.getAnomalies()).toHaveLength(0);
  });

  it('flags a reason-less aborted outcome as schema-invalid (§7.2 presence rule)', () => {
    const host = openHost();
    host.handleOutcome(attempt({ outcome: 'aborted' })); // no reason
    expect(host.getAnomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
    expect(host.records()).toHaveLength(0);
  });

  it('drops an attempted outcome on the audit/outcome channel and flags schema-invalid (§6)', () => {
    const host = openHost();
    host.handleAttempt(attempt());
    host.handleOutcome(attempt({ outcome: 'attempted' }));
    expect(host.records()).toHaveLength(1);
    expect(host.getAnomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('seals one terminal outcome per operation: a byte-identical repeat is ignored, a differing one is a replay (§7.2)', () => {
    const host = openHost();
    host.handleAttempt(attempt());
    host.handleOutcome(attempt({ outcome: 'success' }));
    host.handleOutcome(attempt({ outcome: 'success' }));
    expect(host.records()).toHaveLength(2);
    expect(host.getAnomalies()).toHaveLength(0);
    host.handleOutcome(attempt({ outcome: 'failed' }));
    expect(host.records()).toHaveLength(2);
    expect(host.getAnomalies().map((a) => a.kind)).toEqual(['replay-detected']);
  });

  it('records an outcome for a session that is not the call’s as replay-detected, without throwing (§6)', () => {
    const host = openHost();
    expect(() => host.handleOutcome(attempt({ outcome: 'aborted', reason: 'host-rejected', session_id: OTHER }))).not.toThrow();
    expect(host.records()).toHaveLength(0);
    expect(host.getAnomalies().map((a) => a.kind)).toEqual(['replay-detected']);
  });

  it('checks structure before the session: a malformed event on a foreign session is schema-invalid (§7.1)', () => {
    const host = openHost();
    const res = host.handleAttempt({ ...attempt({ session_id: OTHER }), action_context_hash: 'not-a-hash' });
    expect(res).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
  });

  it('accepts only a session issued for a call in flight on the connection the event arrived on (§6.5)', () => {
    const host = openHost();
    host.openSession(OTHER);
    expect(host.handleAttempt(attempt(), new Set([OTHER]))).toMatchObject({ status: 'reject', reason: 'replay-detected' });
    expect(host.handleAttempt(attempt(), new Set([SESSION])).status).toBe('accept');
  });

  it('never issues a session id twice, even after the session ended (§6.3)', () => {
    const host = openHost();
    host.closeSession(SESSION);
    expect(() => host.openSession(SESSION)).toThrow('already issued');
  });

  it('rejects a string that is not a sequence of Unicode scalar values as schema-invalid (§8.1)', () => {
    const host = openHost();
    expect(host.handleAttempt(attempt({ action_context: { note: 'a\ud800b' } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.handleAttempt(attempt({ action_context: { ['k\udc00']: 1 } }))).toMatchObject({ status: 'reject', reason: 'schema-invalid' });
    expect(host.handleAttempt(attempt({ action_context: { note: '🔒' } })).status).toBe('accept');
  });

  it('hashes the received structure, not a parsed copy: a __proto__ member of action_context is sealed as received (§8)', () => {
    const host = openHost();
    const received = JSON.parse(
      JSON.stringify(attempt()).replace('"outcome":"attempted"', '"outcome":"attempted","action_context":{"__proto__":{"a":1},"b":2}'),
    ) as AuditEvent;
    const res = host.handleAttempt(received);
    expect(res.status).toBe('accept');
    const sealed = host.records()[0]!;
    expect(canonicalize(sealed.event)).toContain('"__proto__":{"a":1}');
    expect(res.status === 'accept' && res.record_hash).toBe(computeRecordHash(received, 0, sealed.host_ts, GENESIS_HASH));
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
      const host = openHost();
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
