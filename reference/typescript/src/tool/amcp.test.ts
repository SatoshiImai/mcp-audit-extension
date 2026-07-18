import { describe, it, expect, vi } from 'vitest';
import { AmcpSession, AmcpBlockedError, deterministicDeps } from './amcp.js';
import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';

function session(host: AuditHost): AmcpSession {
  return new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps());
}

describe('AmcpSession — audit-before-act discipline', () => {
  it('emits attempt, awaits accept, performs the action, then emits outcome', async () => {
    const host = new AuditHost('t#d');
    const s = session(host);
    const perform = vi.fn(async () => 'result');
    const out = await s.audited(
      { action_type: 'db.read', target_resource: { kind: 'table', ref: 'customers' }, params: { q: 1 }, effect: { mutates: false, egress: false } },
      perform,
    );
    expect(out).toBe('result');
    expect(perform).toHaveBeenCalledTimes(1);
    // Two sealed records: attempted, then success.
    const outcomes = host.records().map((r) => r.event.outcome);
    expect(outcomes).toEqual(['attempted', 'success']);
  });

  it('does NOT perform the action when Tier1 is unavailable (fail-closed)', async () => {
    const host = new AuditHost('t#d');
    host.unavailable = true;
    const s = session(host);
    const perform = vi.fn(async () => 'result');
    await expect(
      s.audited({ action_type: 'db.write', target_resource: { kind: 'table', ref: 'customers' }, params: {}, effect: { mutates: true, egress: false } }, perform),
    ).rejects.toBeInstanceOf(AmcpBlockedError);
    expect(perform).not.toHaveBeenCalled();
    expect(host.records()).toHaveLength(0);
  });

  it('seals a failed outcome when the action throws, and rethrows', async () => {
    const host = new AuditHost('t#d');
    const s = session(host);
    const boom = new Error('boom');
    await expect(
      s.audited({ action_type: 'db.write', target_resource: { kind: 'table', ref: 'customers' }, params: {}, effect: { mutates: true, egress: false } }, async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
    const outcomes = host.records().map((r) => r.event.outcome);
    expect(outcomes).toEqual(['attempted', 'failed']);
  });
});
