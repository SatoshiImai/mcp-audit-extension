import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { SqlAnalystTool } from '../tool/sqlAnalystTool.js';
import { BoundaryObserver, reconcile } from './reconcile.js';

// The tool's SQL query is the egress under audit: it mutates nothing, but the query leaves the
// trust boundary to reach the database. Reconciliation compares what the tool self-reported
// against what the boundary (a gateway) actually observed.
const QUERY_DESTINATION = 'analytics-postgres';
const QUESTION = 'What were the high-value customer trends in the Tokyo area last month?';

function newTool(host: AuditHost): SqlAnalystTool {
  return new SqlAnalystTool(new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps()));
}

describe('reconciliation — boundary egress vs self-report', () => {
  it('no anomaly when a self-reported query egress matches a boundary observation', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    await newTool(host).analyze(QUESTION); // tool self-reports the egress
    boundary.observeEgress('call_abc', QUERY_DESTINATION); // gateway observes it

    expect(reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc')).toHaveLength(0);
  });

  it('detects suppression: a query the boundary saw but the tool never reported', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    // The gateway saw the query egress, but the tool emitted no audit event, which signatures
    // and sequence gaps cannot catch.
    boundary.observeEgress('call_abc', QUERY_DESTINATION);

    const anomalies = reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc');
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({ kind: 'unreported-egress', destination: QUERY_DESTINATION });
  });

  it('flags a self-reported egress with no boundary observation', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    await newTool(host).analyze(QUESTION); // reported but boundary saw nothing

    const anomalies = reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc');
    expect(anomalies.some((a) => a.kind === 'unobserved-egress')).toBe(true);
  });
});
