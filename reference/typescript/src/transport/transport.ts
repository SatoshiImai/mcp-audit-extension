import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability, NegotiationResult } from '../schema/capability.js';

// The exchange of §6, independent of the MCP wire: an attempt answered by an Attempt Response, and
// an outcome answered by nothing. A binding (§6.4, §6.5) carries both; nothing above this interface
// depends on which.

// Tier-1 reject reason codes (§7.6); the wire reason is pinned to this closed set.
export type RejectReason = 'schema-invalid' | 'replay-detected' | 'signature-invalid' | 'l2-unsigned' | 'unknown-key';

// accept = the record is sealed; proceed. reject = the record will not be sealed; do not proceed.
// unavailable = nothing was decided; do not proceed, and the identical attempt may be sent again
// (§7.1). None authorizes the domain action: fail-closed governs the record, not the action.
export type AttemptResponse =
  | {
      status: 'accept';
      seq: number;
      record_hash: string;
      host_ts: string;
      previous_hash: string;
      // The countersignature triple appears together or not at all (§7.1). A host declaring `none`
      // returns none of it; one declaring `host` returns all of it on every accept (§5.2).
      host_signature?: string;
      host_key_id?: string;
      log_id?: string;
    }
  | { status: 'reject'; reason: RejectReason }
  | { status: 'unavailable'; reason: 'internal-error' };

export interface AuditTransport {
  // The §6.1 comparison, for the call this transport serves.
  negotiate(offered: AuditCapability): NegotiationResult;

  // Resolves with the host's answer; bounding the wait is the binding's concern (§6).
  sendAttempt(event: AuditEvent): Promise<AttemptResponse>;

  sendOutcome(event: AuditEvent): Promise<void>;
}
