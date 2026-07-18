import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CallToolRequestSchema,
  type CallToolResult,
  type Request,
  type Notification,
} from '@modelcontextprotocol/sdk/types.js';
import type { AuditHost } from '../host/auditHost.js';
import type { AuditCapability } from '../schema/capability.js';
import { DEFAULT_L1_CAPABILITY } from '../schema/capability.js';
import { AmcpSession, AmcpBlockedError, deterministicDeps, type AmcpDeps } from '../tool/amcp.js';
import { ResearchTool } from '../tool/researchTool.js';
import { McpTransport, type AuditToolServer } from '../transport/mcpTransport.js';
import {
  AuditAttemptRequestSchema,
  AuditOutcomeNotificationSchema,
  type AuditAttemptResult,
} from '../transport/mcpWire.js';

// The host client is typed so its request handler may return the custom audit result.
export type AuditHostClient = Client<Request, Notification, AuditAttemptResult>;

// The host runs as an MCP client: it handles the tool's audit/attempt requests and
// audit/outcome notifications by delegating to the AuditHost. This is the monitoring camera.
function createHostClient(auditHost: AuditHost): AuditHostClient {
  const client: AuditHostClient = new Client({ name: 'auditable-mcp-host', version: '0.1.0' }, { capabilities: {} });

  client.setRequestHandler(AuditAttemptRequestSchema, (req): AuditAttemptResult => auditHost.handleAttempt(req.params));
  client.setNotificationHandler(AuditOutcomeNotificationSchema, (notif) => {
    auditHost.handleOutcome(notif.params);
  });

  return client;
}

// The tool runs as an MCP server exposing the research tool. Inside tools/call it uses
// McpTransport, so the unchanged tool logic self-attests its internal ops over the wire.
function createToolServer(capability: AuditCapability, deps: AmcpDeps): AuditToolServer {
  const server: AuditToolServer = new Server(
    { name: 'research-tool', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(CallToolRequestSchema, async (req, extra): Promise<CallToolResult> => {
    const session = new AmcpSession(new McpTransport(server, capability), String(extra.requestId), deps);
    const tool = new ResearchTool(session);
    const args = (req.params.arguments ?? {}) as Record<string, string>;

    try {
      let result: unknown;
      switch (req.params.name) {
        case 'search':
          result = await tool.search(args.query ?? '');
          break;
        case 'save_note':
          result = await tool.saveNote(args.topic ?? '', args.content ?? '');
          break;
        case 'list_notes':
          result = await tool.listNotes();
          break;
        default:
          return { content: [{ type: 'text', text: `unknown tool: ${req.params.name}` }], isError: true };
      }
      return { content: [{ type: 'text', text: JSON.stringify(result ?? null) }] };
    } catch (err) {
      // Fail-closed abort: surface the blocked internal action in the CallTool result
      // instead of silently degrading.
      if (err instanceof AmcpBlockedError) {
        return {
          content: [{ type: 'text', text: `blocked: ${err.action_type} on ${err.target_ref} (${err.reason})` }],
          isError: true,
          structuredContent: { audit_blocked: [{ action_type: err.action_type, target_ref: err.target_ref, reason: err.reason }] },
        };
      }
      throw err;
    }
  });

  return server;
}

export interface AuditPair {
  client: Client;
  server: AuditToolServer;
  close: () => Promise<void>;
}

// Connect a host client and tool server over an in-memory MCP transport pair.
export async function connectAuditPair(
  auditHost: AuditHost,
  capability: AuditCapability = DEFAULT_L1_CAPABILITY,
  deps: AmcpDeps = deterministicDeps(),
): Promise<AuditPair> {
  const client = createHostClient(auditHost);
  const server = createToolServer(capability, deps);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

  return {
    client,
    server,
    close: async () => {
      await Promise.all([client.close(), server.close()]);
    },
  };
}
