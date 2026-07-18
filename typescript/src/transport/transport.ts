import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability } from '../schema/capability.js';

// AuditTransport is shaped to the MCP elicitation wire: a server->client request/response
// for attempt, a lighter outcome delivery, plus capability negotiation. Keeping it faithful
// lets an MCP-SDK-backed transport drop in without changing anything above this interface.

// Response to audit/attempt. accept = record durably persisted (proceed). reject = invalid
// or forged record (do not proceed). unavailable = transient persistence failure (do not
// proceed). None authorize the domain action; fail-closed is about record completeness.
export type AttemptResponse =
  | { status: 'accept'; seq: number; record_hash: string }
  | { status: 'reject'; reason: string }
  | { status: 'unavailable'; reason: string; retryable: true };

export class AuditCancelledError extends Error {
  constructor(reason: string) {
    super(`audit cancelled: ${reason}`);
    this.name = 'AuditCancelledError';
  }
}

export interface AuditTransport {
  // Host declares what it requires; the tool complies or fails observably.
  negotiate(): AuditCapability;

  // Blocking request/response. Throws AuditCancelledError when the context is torn down.
  sendAttempt(event: AuditEvent): Promise<AttemptResponse>;

  // Outcome (success/failed). Not a completeness gate; loss is caught by sequence gaps.
  sendOutcome(event: AuditEvent): Promise<void>;
}
