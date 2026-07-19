import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability, NegotiationResult } from '../schema/capability.js';
import type { AuditHost } from '../host/auditHost.js';
import type { AttemptResponse, AuditTransport } from './transport.js';

// In-process transport: the tool calls the host directly. Swapped for an MCP-SDK-backed
// transport in a real deployment; survives as a fast test double.
export class InProcessTransport implements AuditTransport {
  constructor(private readonly host: AuditHost) {}

  negotiate(offered: AuditCapability): NegotiationResult {
    return this.host.negotiate(offered);
  }

  async sendAttempt(event: AuditEvent): Promise<AttemptResponse> {
    return this.host.handleAttempt(event);
  }

  async sendOutcome(event: AuditEvent): Promise<void> {
    this.host.handleOutcome(event);
  }
}
