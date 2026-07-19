import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability, NegotiationResult } from '../schema/capability.js';

// Transport shaped to the MCP elicitation wire: server->client request/response for attempt,
// notification for outcome, plus capability negotiation. An MCP-SDK-backed transport drops in
// without changes above this interface.

// audit/attempt response. accept = record durably persisted; proceed. reject = invalid/forged
// record; do not proceed. unavailable = transient persistence failure; do not proceed. None
// authorize the domain action: fail-closed governs record completeness, not authorization.
export type AttemptResponse =
  | { status: 'accept'; seq: number; record_hash: string; host_ts: string; previous_hash: string }
  | { status: 'reject'; reason: string }
  | { status: 'unavailable'; reason: string; retryable: true };

export interface AuditTransport {
  // Bidirectional capability exchange (§6.1). Mismatch handling is an orchestrator concern.
  negotiate(offered: AuditCapability): NegotiationResult;

  // Blocking request/response; bounding the wait (a fail-closed timeout) is a transport/SDK
  // responsibility (§6).
  sendAttempt(event: AuditEvent): Promise<AttemptResponse>;

  // Outcome delivery. Not a completeness gate; loss is caught by sequence gaps (§7.1).
  sendOutcome(event: AuditEvent): Promise<void>;
}
