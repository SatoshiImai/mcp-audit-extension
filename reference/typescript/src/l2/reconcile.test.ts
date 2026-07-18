import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { ResearchTool } from '../tool/researchTool.js';
import { BoundaryObserver, reconcile } from './reconcile.js';

// The tool's web search is the egress under audit: it mutates nothing, but the query leaves
// the trust boundary. Reconciliation compares what the tool self-reported against what the
// boundary (a gateway) actually observed.
const SEARCH_ENDPOINT = 'https://api.search.example/v1/search';

function newTool(host: AuditHost): ResearchTool {
  return new ResearchTool(new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps()));
}

describe('reconciliation — boundary egress vs self-report', () => {
  it('no anomaly when a self-reported search egress matches a boundary observation', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    await newTool(host).search('acme corp merger due diligence'); // tool self-reports the egress
    boundary.observeEgress('call_abc', SEARCH_ENDPOINT); // gateway observes it

    expect(reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc')).toHaveLength(0);
  });

  it('detects suppression: a search the boundary saw but the tool never reported', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    // The gateway saw the search egress, but the tool emitted no audit event, which
    // signatures and sequence gaps cannot catch.
    boundary.observeEgress('call_abc', SEARCH_ENDPOINT);

    const anomalies = reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc');
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({ kind: 'unreported-egress', destination: SEARCH_ENDPOINT });
  });

  it('flags a self-reported egress with no boundary observation', async () => {
    const host = new AuditHost('t#d');
    const boundary = new BoundaryObserver();

    await newTool(host).search('acme corp merger due diligence'); // reported but boundary saw nothing

    const anomalies = reconcile(host.records(), boundary.forCall('call_abc'), 'call_abc');
    expect(anomalies.some((a) => a.kind === 'unobserved-egress')).toBe(true);
  });
});
