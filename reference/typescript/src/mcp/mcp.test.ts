import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import { verifyLedger } from '../verify/verify.js';
import { connectAuditPair } from './wiring.js';
import { DEFAULT_L1_CAPABILITY } from '../schema/capability.js';
import { AUDIT_ATTEMPT_METHOD, AuditAttemptResultSchema } from '../transport/mcpWire.js';

function event(sessionId: string): Record<string, unknown> {
  return {
    id: '00000000-0000-4000-8000-0000000000aa',
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:01.000Z',
    session_id: sessionId,
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
  };
}

// Same tool, host, ledger, and verifier as the in-process path, over the real MCP wire with only
// the transport swapped (InProcessTransport -> McpTransport). The tool self-attests its internal
// db ops via server->client audit/attempt requests during tools/call.
describe('Auditable MCP over MCP wire', () => {
  it('seals tool-internal ops via audit/attempt over the wire and verifies', async () => {
    const host = new AuditHost('mcp#demo');
    const { callAudited, close } = await connectAuditPair(host);

    try {
      const r1 = await callAudited('analyze', { question: 'What were the high-value customer trends in the Tokyo area last month?' });

      expect(r1.isError).toBeFalsy();

      // Ledger captured tool-internal operations, not just the tools/call boundary: db.query,
      // ext.geocode, db.write, each attempted then success.
      const events = host.records().map((r) => `${r.event.action_type}:${r.event.outcome}`);
      expect(events).toEqual([
        'db.query:attempted',
        'db.query:success',
        'ext.geocode:attempted',
        'ext.geocode:success',
        'db.write:attempted',
        'db.write:success',
      ]);

      // db.query does not egress; ext.geocode does.
      const query = host.records()[0];
      expect(query?.event.mutates).toBe(false);
      expect(query?.event.egress).toBe(false);
      expect(host.records()[2]?.event.egress).toBe(true);

      expect(verifyLedger(host.records()).ok).toBe(true);
      // Every operation was resolved before the call returned (§6.3).
      expect(host.getAnomalies()).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('does not audit a call the host sent without an audit session (§6.2, §6.3)', async () => {
    const host = new AuditHost('mcp#demo');
    const { client, close } = await connectAuditPair(host);
    try {
      const res = await client.callTool({ name: 'analyze', arguments: { question: 'q' } });
      expect(res.isError).toBe(true);
      expect(host.records()).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('fails closed over the wire: when the host is unavailable, the internal action is not performed', async () => {
    const host = new AuditHost('mcp#demo');
    host.unavailable = true;
    const { callAudited, close } = await connectAuditPair(host);

    try {
      const res = await callAudited('analyze', { question: 'What were the high-value customer trends in the Tokyo area last month?' });
      // The tool aborts the tools/call because no durable record could be obtained.
      expect(res.isError).toBe(true);
      expect(host.records()).toHaveLength(0);
    } finally {
      await close();
    }
  });
  it('does not audit a call from a host that declared no capability, even when the call carries a session (§6.1, §6.2)', async () => {
    const host = new AuditHost('mcp#demo');
    const { callAudited, close } = await connectAuditPair(host, undefined, undefined, { hostDeclaration: null, forceSession: true });
    try {
      const res = await callAudited('analyze', { question: 'q' });
      expect(res.isError).toBe(true);
      expect(host.records()).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('does not audit a call whose comparison failed (§6.1)', async () => {
    const host = new AuditHost('mcp#demo');
    const older = { ...DEFAULT_L1_CAPABILITY, spec_version: 'auditable-mcp/0.2' };
    const { callAudited, close } = await connectAuditPair(host, undefined, undefined, { hostDeclaration: older, forceSession: true });
    try {
      expect((await callAudited('analyze', { question: 'q' })).isError).toBe(true);
      expect(host.records()).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('answers audit/attempt for a session not issued for a call in flight on the connection with a reject (§6.5)', async () => {
    const host = new AuditHost('mcp#demo');
    const open = host.openSession();
    const { server, close } = await connectAuditPair(host);
    try {
      const res = await server.request({ method: AUDIT_ATTEMPT_METHOD, params: event(open) }, AuditAttemptResultSchema);
      expect(res).toEqual({ status: 'reject', reason: 'replay-detected' });
      expect(host.records()).toHaveLength(0);
    } finally {
      await close();
    }
  });

  it('answers a malformed audit/attempt with a schema-invalid reject, not a protocol error (§6)', async () => {
    const host = new AuditHost('mcp#demo');
    const { server, close } = await connectAuditPair(host);
    try {
      const res = await server.request(
        { method: AUDIT_ATTEMPT_METHOD, params: { ...event(host.openSession()), id: 'NOT-A-UUID' } },
        AuditAttemptResultSchema,
      );
      expect(res).toEqual({ status: 'reject', reason: 'schema-invalid' });
    } finally {
      await close();
    }
  });
});
