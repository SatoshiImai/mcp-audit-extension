import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { BoundaryObserver, reconcile } from './reconcile.js';

const STRIPE = 'https://api.stripe.com/v1/refunds';

async function egressAction(session: AmcpSession, ref: string): Promise<void> {
  await session.audited(
    { action_type: 'ext.stripe.refund_charge', target_resource: { kind: 'endpoint', ref }, params: { amount: 100 }, effect: { mutates: true, egress: true } },
    async () => undefined,
  );
}

describe('reconciliation — boundary egress vs self-report', () => {
  it('no anomaly when a self-reported egress matches a boundary observation', async () => {
    const host = new AuditHost('t#d');
    const session = new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps());
    const boundary = new BoundaryObserver();

    await egressAction(session, STRIPE); // tool self-reports the egress
    boundary.observeEgress('call_abc', STRIPE); // gateway observes it

    expect(reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc')).toHaveLength(0);
  });

  it('detects suppression: an observed egress the tool never reported', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    // The tool egressed (the boundary saw it) but emitted NO audit event.
    boundary.observeEgress('call_abc', STRIPE);

    const anomalies = reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc');
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({ kind: 'unreported-egress', destination: STRIPE });
  });

  it('flags a self-reported egress with no boundary observation', async () => {
    const host = new AuditHost('t#d');
    const session = new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps());
    const boundary = new BoundaryObserver();

    await egressAction(session, STRIPE); // reported but boundary saw nothing

    const anomalies = reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc');
    expect(anomalies.some((a) => a.kind === 'unobserved-egress')).toBe(true);
  });
});
