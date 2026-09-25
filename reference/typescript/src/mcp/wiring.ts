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
import { auditCapabilitySchema, DEFAULT_L1_CAPABILITY, negotiateCapability } from '../schema/capability.js';
import { AmcpSession, AmcpAbortedError, deterministicDeps, type AmcpDeps } from '../tool/amcp.js';
import { SqlAnalystTool } from '../tool/sqlAnalystTool.js';
import { McpTransport, type AuditToolServer } from '../transport/mcpTransport.js';
import {
  AuditAttemptRequestSchema,
  AuditOutcomeNotificationSchema,
  AuditRequestMetaSchema,
  EXTENSION_ID,
  type AuditAttemptResult,
} from '../transport/mcpWire.js';

// The host client is typed so its request handler may return the custom audit result.
export type AuditHostClient = Client<Request, Notification, AuditAttemptResult>;

// The §6.5 binding (MCP protocol versions with an initialization handshake), which is what the MCP
// SDK this demonstration pins speaks. The host runs as an MCP client: it declares its capability
// object under `extensions` in `initialize`, and handles the tool's audit/attempt requests and
// audit/outcome notifications by delegating to the AuditHost. It records and verifies; it never
// authorizes the domain action.
//
// stdio relates no request to the call it serves, so an event "arrives on" the calls in flight on
// this connection: `inFlight` holds the sessions the host issued for them, and an event naming any
// other session - open or not - is not the call's (§6.3, §6.5).
function createHostClient(auditHost: AuditHost, declaration: AuditCapability | undefined, inFlight: ReadonlySet<string>): AuditHostClient {
  const capabilities = declaration === undefined ? {} : { extensions: { [EXTENSION_ID]: declaration } };
  const client: AuditHostClient = new Client({ name: 'auditable-mcp-host', version: '0.1.0' }, { capabilities });

  client.setRequestHandler(AuditAttemptRequestSchema, (req): AuditAttemptResult => auditHost.handleAttempt(req.params, inFlight));
  client.setNotificationHandler(AuditOutcomeNotificationSchema, (notif) => {
    auditHost.handleOutcome(notif.params, inFlight);
  });

  return client;
}

// The §6.1 comparison for a call, from the declarations exchanged in `initialize` (§6.5). A peer
// that declared no capability object under the extension id is undeclared; one whose object does
// not validate cannot fit.
function compare(peer: unknown, own: AuditCapability, ownIsHost: boolean): boolean {
  if (peer === undefined) return false;
  const parsed = auditCapabilitySchema.safeParse(peer);
  if (!parsed.success) return false;
  return (ownIsHost ? negotiateCapability(own, parsed.data) : negotiateCapability(parsed.data, own)).negotiated;
}

// The tool runs as an MCP server exposing the SQL analyst tool, declaring its capability object under
// `extensions`. Inside tools/call it uses McpTransport, so the unchanged tool logic self-attests its
// internal ops over the wire.
function createToolServer(capability: AuditCapability, deps: AmcpDeps): AuditToolServer {
  const server: AuditToolServer = new Server(
    { name: 'research-tool', version: '0.1.0' },
    { capabilities: { tools: {}, extensions: { [EXTENSION_ID]: capability } } },
  );

  server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
    // A call is audit-negotiated only when the host declared the extension, the comparison succeeded,
    // and the call carries an audit session the host issued (§6.2, §6.3). This demonstration takes
    // the mandatory posture for every other call (§6.2).
    const hostDeclaration = server.getClientCapabilities()?.extensions?.[EXTENSION_ID];
    const meta = AuditRequestMetaSchema.safeParse(req.params._meta?.[EXTENSION_ID]);
    if (!compare(hostDeclaration, capability, false) || !meta.success) {
      return { content: [{ type: 'text', text: 'this tool is served only to a host that audits it' }], isError: true };
    }
    const session = new AmcpSession(new McpTransport(server, capability), meta.data.session_id, deps);
    const tool = new SqlAnalystTool(session);
    const args = (req.params.arguments ?? {}) as Record<string, string>;

    try {
      let result: unknown;
      switch (req.params.name) {
        case 'analyze':
          result = await tool.analyze(args.question ?? '');
          break;
        default:
          return { content: [{ type: 'text', text: `unknown tool: ${req.params.name}` }], isError: true };
      }
      return { content: [{ type: 'text', text: JSON.stringify(result ?? null) }] };
    } catch (err) {
      // Fail-closed abort: surface the aborted internal action in the tools/call result
      // instead of silently degrading.
      if (err instanceof AmcpAbortedError) {
        return {
          content: [{ type: 'text', text: `aborted: ${err.action_type} on ${err.target_ref} (${err.reason})` }],
          isError: true,
          structuredContent: { audit_aborted: [{ action_type: err.action_type, target_ref: err.target_ref, reason: err.reason }] },
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
  // Call a tool, under a fresh audit session when the tool's declaration fits the host's (§6.1),
  // and close the session when the call ends (§6.3).
  callAudited: (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
  close: () => Promise<void>;
}

export interface AuditPairOptions {
  // What the host declares in `initialize`; `null` declares no capability object at all.
  hostDeclaration?: AuditCapability | null;
  // Send an audit session with every call, whatever the comparison found. Only a test of the tool's
  // side of §6.2 wants this.
  forceSession?: boolean;
}

// Connect a host client and tool server over an in-memory MCP transport pair.
export async function connectAuditPair(
  auditHost: AuditHost,
  capability: AuditCapability = DEFAULT_L1_CAPABILITY,
  deps: AmcpDeps = deterministicDeps(),
  options: AuditPairOptions = {},
): Promise<AuditPair> {
  const declaration = options.hostDeclaration === undefined ? auditHost.declaration() : (options.hostDeclaration ?? undefined);
  const inFlight = new Set<string>();
  const client = createHostClient(auditHost, declaration, inFlight);
  const server = createToolServer(capability, deps);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

  const toolDeclaration = client.getServerCapabilities()?.extensions?.[EXTENSION_ID];
  const audits = options.forceSession === true || compare(toolDeclaration, auditHost.declaration(), true);

  const callAudited = async (name: string, args: Record<string, unknown>): Promise<CallToolResult> => {
    if (!audits) return (await client.callTool({ name, arguments: args })) as CallToolResult;
    const sessionId = auditHost.openSession();
    inFlight.add(sessionId);
    try {
      return (await client.callTool({
        name,
        arguments: args,
        _meta: { [EXTENSION_ID]: { session_id: sessionId } },
      })) as CallToolResult;
    } finally {
      inFlight.delete(sessionId);
      auditHost.closeSession(sessionId);
    }
  };

  return {
    client,
    server,
    callAudited,
    close: async () => {
      await Promise.all([client.close(), server.close()]);
    },
  };
}
