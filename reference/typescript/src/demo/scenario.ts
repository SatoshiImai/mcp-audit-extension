import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { SqlAnalystTool } from '../tool/sqlAnalystTool.js';

// The audit session of the clean scenario (§6.3). Fixed so the chain vector is reproducible.
export const SCENARIO_SESSION_ID = '0198f3a2-5c1e-7000-8000-00000000abc0';

// A reproducible L1 scenario shared by the demo, the tests, and the chain conformance vector.
// One host call drives a data-analysis tool that runs a raw SQL query the host never sees,
// enriches the result via an external service, then caches it: three internal operations that
// span the (mutates, egress) axis and both confidentiality choices of §4.3.
export async function runCleanScenario(partition = 'acme#2026-07-15'): Promise<AuditHost> {
  const host = new AuditHost(partition);
  const sessionId = host.openSession(SCENARIO_SESSION_ID);
  const transport = new InProcessTransport(host);
  const session = new AmcpSession(transport, sessionId, deterministicDeps());
  const tool = new SqlAnalystTool(session);

  await tool.analyze('What were the high-value customer trends in the Tokyo area last month?');
  host.closeSession(sessionId);

  return host;
}
