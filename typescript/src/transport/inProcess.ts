import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability } from '../schema/capability.js';
import type { AuditHost } from '../host/auditHost.js';
import type { AttemptResponse, AuditTransport } from './transport.js';

// In-process transport: the tool calls the host directly. This is the only asset superseded
// when B2 swaps in an MCP-SDK-backed transport — and it survives as a fast test double.
// It models the wire contract faithfully (request/response for attempt, void for outcome,
// capability negotiation), so nothing above this line changes on the swap.
export class InProcessTransport implements AuditTransport {
  constructor(private readonly host: AuditHost) {}

  negotiate(): AuditCapability {
    return this.host.negotiate();
  }

  async sendAttempt(event: AuditEvent): Promise<AttemptResponse> {
    return this.host.handleAttempt(event);
  }

  async sendOutcome(event: AuditEvent): Promise<void> {
    this.host.handleOutcome(event);
  }
}
