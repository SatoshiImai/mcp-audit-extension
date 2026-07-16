import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability } from '../schema/capability.js';
import { DEFAULT_L1_CAPABILITY } from '../schema/capability.js';
import type { AttemptResponse, AuditTransport } from './transport.js';
import {
  AUDIT_ATTEMPT_METHOD,
  AUDIT_OUTCOME_METHOD,
  AuditAttemptResultSchema,
  type AuditAttemptRequest,
  type AuditOutcomeNotification,
} from './mcpWire.js';

// The tool server, typed so it can send the A-MCP methods to the client.
export type AuditToolServer = Server<AuditAttemptRequest, AuditOutcomeNotification>;

// McpTransport is the B2 drop-in: it speaks the real MCP wire (server→client request for
// attempt, notification for outcome). Everything above the AuditTransport interface — schema,
// ledger, host, verifier, and the tool's audit-before-act logic — is reused unchanged. This
// is the only asset that differs from B1's InProcessTransport.
export class McpTransport implements AuditTransport {
  constructor(
    private readonly server: AuditToolServer,
    private readonly capability: AuditCapability = DEFAULT_L1_CAPABILITY,
  ) {}

  negotiate(): AuditCapability {
    return this.capability;
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
