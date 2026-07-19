import { describe, it, expect } from 'vitest';
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { AuditHost } from '../host/auditHost.js';
import { verifyLedger } from '../verify/verify.js';
import { connectAuditPair } from './wiring.js';

// Same tool, host, ledger, and verifier as the in-process path, over the real MCP wire with only
// the transport swapped (InProcessTransport -> McpTransport). The tool self-attests its internal
// db ops via server->client audit/attempt requests during tools/call.
describe('Auditable MCP over MCP wire', () => {
  it('seals tool-internal ops via audit/attempt over the wire and verifies', async () => {
    const host = new AuditHost('mcp#demo');
    const { client, close } = await connectAuditPair(host);

    try {
      const r1 = await client.request(
        { method: 'tools/call', params: { name: 'analyze', arguments: { question: 'What were the high-value customer trends in the Tokyo area last month?' } } },
        CallToolResultSchema,
      );

      expect(r1.isError).toBeFalsy();

      // Ledger captured tool-internal operations, not just the tools/call boundary: one db.query
      // (the SELECT, which egressed to the DB) + one db.write, each attempted then success.
      const events = host.records().map((r) => `${r.event.action_type}:${r.event.outcome}`);
      expect(events).toEqual(['db.query:attempted', 'db.query:success', 'db.write:attempted', 'db.write:success']);

      // db.query mutates nothing yet egresses.
      const query = host.records()[0];
      expect(query?.event.mutates).toBe(false);
      expect(query?.event.egress).toBe(true);

      expect(verifyLedger(host.records()).ok).toBe(true);
    } finally {
      await close();
    }
  });

  it('fails closed over the wire: when the host is unavailable, the internal action is not performed', async () => {
    const host = new AuditHost('mcp#demo');
    host.unavailable = true;
    const { client, close } = await connectAuditPair(host);

    try {
      const res = await client.request(
        { method: 'tools/call', params: { name: 'analyze', arguments: { question: 'What were the high-value customer trends in the Tokyo area last month?' } } },
        CallToolResultSchema,
      );
      // The tool aborts the tools/call because no durable record could be obtained.
      expect(res.isError).toBe(true);
      expect(host.records()).toHaveLength(0);
    } finally {
      await close();
    }
  });
});
