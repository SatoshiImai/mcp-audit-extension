import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { SqlAnalystTool } from '../tool/sqlAnalystTool.js';

// A reproducible L1 scenario shared by the demo, the tests, and the chain conformance vector.
// One host call drives a data-analysis tool that runs a raw SQL query the host never sees, then
// caches the result: two internal operations that span the (mutates, egress) axis and both
// confidentiality choices of §4.3.
export async function runCleanScenario(partition = 'acme#2026-07-15'): Promise<AuditHost> {
  const host = new AuditHost(partition);
  const transport = new InProcessTransport(host);
  const session = new AmcpSession(transport, 'call_abc', deterministicDeps());
  const tool = new SqlAnalystTool(session);

  await tool.analyze('What were the high-value customer trends in the Tokyo area last month?');

  return host;
}
