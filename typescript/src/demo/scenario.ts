import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { ResearchTool } from '../tool/researchTool.js';

// A reproducible L1 scenario shared by the demo, the tests, and the chain conformance vector.
// A first-party research tool performs three internal operations that deliberately span the
// (mutates, egress) axis: a web search (read-only, yet the query egresses), a note write, and
// a note read.
export async function runCleanScenario(partition = 'acme#2026-07-15'): Promise<AuditHost> {
  const host = new AuditHost(partition);
  const transport = new InProcessTransport(host);
  const session = new AmcpSession(transport, 'call_abc', deterministicDeps());
  const tool = new ResearchTool(session);

  await tool.search('acme corp merger due diligence'); // api.request — mutates=0, egress=1
  await tool.saveNote('acme', 'merger rumour confirmed by two sources'); // db.write
  await tool.listNotes(); // db.read

  return host;
}
