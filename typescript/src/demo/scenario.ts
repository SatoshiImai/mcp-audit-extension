import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { CustomerDbTool } from '../tool/customerDbTool.js';

// A reproducible L1 scenario shared by the demo and the tests. A first-party customer DB
// tool performs a few internal reads/writes; every operation is self-attested and sealed.
export async function runCleanScenario(partition = 'acme#2026-07-15'): Promise<AuditHost> {
  const host = new AuditHost(partition);
  const transport = new InProcessTransport(host);
  const session = new AmcpSession(transport, 'call_abc', deterministicDeps());
  const tool = new CustomerDbTool(session);

  await tool.getCustomer('c_1'); // db.read
  await tool.updateEmail('c_1', 'new@acme.example'); // db.write
  await tool.getCustomer('c_2'); // db.read

  return host;
}
