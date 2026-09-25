import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { GEOCODER, SqlAnalystTool } from '../tool/sqlAnalystTool.js';
import { BoundaryObserver, reconcile } from './reconcile.js';

// The tool's external geocoding call is the egress under audit: it mutates nothing, but it sends
// tenant data past the governance boundary to a third party. Reconciliation compares what the tool
// self-reported against what the boundary (a gateway) actually observed.
const EGRESS_DESTINATION = GEOCODER;
const QUESTION = 'What were the high-value customer trends in the Tokyo area last month?';

const SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0';

function newTool(host: AuditHost): SqlAnalystTool {
  return new SqlAnalystTool(new AmcpSession(new InProcessTransport(host), host.openSession(SESSION), deterministicDeps()));
}

describe('reconciliation - boundary egress vs self-report', () => {
  it('no anomaly when a self-reported egress matches a boundary observation', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    await newTool(host).analyze(QUESTION); // tool self-reports the egress
    boundary.observeEgress(SESSION, EGRESS_DESTINATION); // gateway observes it

    expect(reconcile(host.records(), boundary.forSession(SESSION), SESSION)).toHaveLength(0);
  });

  it('detects suppression: an egress the boundary saw but the tool never reported', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    // The gateway saw the egress, but the tool emitted no audit event, which signatures and
    // sequence gaps cannot catch.
    boundary.observeEgress(SESSION, EGRESS_DESTINATION);

    const anomalies = reconcile(host.records(), boundary.forSession(SESSION), SESSION);
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({ kind: 'unreported-egress', destination: EGRESS_DESTINATION });
  });

  it('returns anomalies in a stable sorted order regardless of observation order (per-port determinism)', () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    // Observe in a deliberately unsorted order. The Python port iterates a hash-randomized set, so
    // enough distinct destinations are used that an accidentally pre-sorted iteration (which would
    // let a missing sort pass) is negligible; the anomaly list must always come back sorted.
    for (const dest of ['zeta', 'mid', 'alpha', 'yankee', 'bravo', 'kilo']) {
      boundary.observeEgress(SESSION, dest);
    }

    const anomalies = reconcile(host.records(), boundary.forSession(SESSION), SESSION);
    expect(anomalies.map((a) => a.destination)).toEqual(['alpha', 'bravo', 'kilo', 'mid', 'yankee', 'zeta']);
  });

  it('does not flag a self-reported egress the boundary did not observe (a boundary blind spot is not tool misbehavior)', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    await newTool(host).analyze(QUESTION); // self-reported, but the boundary saw nothing

    expect(reconcile(host.records(), boundary.forSession(SESSION), SESSION)).toHaveLength(0);
  });
});
