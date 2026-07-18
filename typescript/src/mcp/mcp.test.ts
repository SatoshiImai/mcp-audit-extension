import { describe, it, expect } from 'vitest';
import { CallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { AuditHost } from '../host/auditHost.js';
import { verifyLedger } from '../verify/verify.js';
import { connectAuditPair } from './wiring.js';

// B2 proof: the SAME tool, host, ledger, and verifier from B1 work over the real MCP wire
// with only the transport swapped (InProcessTransport → McpTransport). The tool self-attests
// its internal db ops via server→client audit/attempt requests during tools/call.
describe('Auditable MCP over MCP wire (B2)', () => {
  it('seals tool-internal ops via audit/attempt over the wire and verifies', async () => {
    const host = new AuditHost('mcp#demo');
    const { client, close } = await connectAuditPair(host);

    try {
      const r1 = await client.request(
        { method: 'tools/call', params: { name: 'search', arguments: { query: 'acme corp merger due diligence' } } },
        CallToolResultSchema,
      );
      const r2 = await client.request(
        { method: 'tools/call', params: { name: 'save_note', arguments: { topic: 'acme', content: 'merger rumour' } } },
        CallToolResultSchema,
      );

      // Tool calls returned real results over the wire.
      expect(r1.isError).toBeFalsy();
      expect(r2.isError).toBeFalsy();

      // The host ledger captured the tool-INTERNAL operations (not just the CallTool boundary):
      // one api.request (the search, whose query egressed) + one db.write, each attempted then success.
      const events = host.records().map((r) => `${r.event.action_type}:${r.event.outcome}`);
      expect(events).toEqual(['api.request:attempted', 'api.request:success', 'db.write:attempted', 'db.write:success']);

      // The search is the point: it mutates nothing, yet it egresses.
      const search = host.records()[0];
      expect(search?.event.mutates).toBe(false);
      expect(search?.event.egress).toBe(true);

      // And the sealed chain verifies.
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
        { method: 'tools/call', params: { name: 'save_note', arguments: { topic: 'acme', content: 'must never be written' } } },
        CallToolResultSchema,
      );
      // The tool aborts the CallTool because no durable record could be obtained.
      expect(res.isError).toBe(true);
      expect(host.records()).toHaveLength(0);
    } finally {
      await close();
    }
  });
});
