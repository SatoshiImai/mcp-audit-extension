import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability } from '../schema/capability.js';

// AuditTransport is deliberately shaped to the MCP elicitation wire contract (design §6):
// a server→client REQUEST with a response (attempt), plus a lighter outcome delivery, plus
// capability negotiation and cancellation. Keeping this faithful is what makes the
// in-process implementation zero-waste: swapping InProcessTransport for an MCP-SDK-backed
// transport is a mechanical change, and everything above this interface is reused.

// Response to audit/attempt. accept = record durably persisted (proceed). reject = the
// RECORD is invalid/forged (a lie into the ledger) — do not proceed, integrity fault.
// unavailable = infra could not persist — do not proceed (fail-closed). None of these
// authorize the domain action; that is the operator's allowlist. Fail-closed here is about record
// completeness, not action control (§6.1).
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

  // Blocking request/response. Resolves with accept/reject/unavailable, or throws
  // AuditCancelledError when the surrounding context is torn down (MCP notifications/cancelled).
  sendAttempt(event: AuditEvent): Promise<AttemptResponse>;

  // Outcome (success/failed). Delivery mode is host-declared; the PoC records it the same
  // way. Not a completeness gate — loss is caught by sequence gaps (§6.1).
  sendOutcome(event: AuditEvent): Promise<void>;
}
