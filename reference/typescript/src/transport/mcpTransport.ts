import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability, NegotiationResult } from '../schema/capability.js';
import { DEFAULT_L1_CAPABILITY, negotiateCapability } from '../schema/capability.js';
import type { AttemptResponse, AuditTransport } from './transport.js';
import {
  AUDIT_ATTEMPT_METHOD,
  AUDIT_OUTCOME_METHOD,
  AuditAttemptResultSchema,
  type AuditAttemptRequest,
  type AuditOutcomeNotification,
} from './mcpWire.js';

// Tool server typed to send the Auditable MCP methods to the client.
export type AuditToolServer = Server<AuditAttemptRequest, AuditOutcomeNotification>;

// MCP-wire transport: server->client request for attempt, notification for outcome. The only
// AuditTransport implementation that touches the MCP SDK; schema, ledger, host, verifier, and the
// tool's audit-before-act logic sit above this interface unchanged.
export class McpTransport implements AuditTransport {
  constructor(
    private readonly server: AuditToolServer,
    private readonly capability: AuditCapability = DEFAULT_L1_CAPABILITY,
  ) {}

  negotiate(offered: AuditCapability): NegotiationResult {
    return negotiateCapability(this.capability, offered);
  }

  async sendAttempt(event: AuditEvent): Promise<AttemptResponse> {
    const result = await this.server.request(
      { method: AUDIT_ATTEMPT_METHOD, params: event },
      AuditAttemptResultSchema,
    );
    return result;
  }

  async sendOutcome(event: AuditEvent): Promise<void> {
    await this.server.notification({ method: AUDIT_OUTCOME_METHOD, params: event });
  }
}
