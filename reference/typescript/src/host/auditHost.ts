import { auditEventSchema, type AuditEvent } from '../schema/event.js';
import type { AuditCapability, NegotiationResult } from '../schema/capability.js';
import { DEFAULT_L1_CAPABILITY, negotiateCapability } from '../schema/capability.js';
import { Ledger, type SealedRecord } from '../ledger/ledger.js';
import { hasUnsafeNumber } from '../ledger/canonical.js';
import type { AttemptResponse, RejectReason } from '../transport/transport.js';
import { verifyEventSignature } from '../l2/signing.js';
import type { KeyRegistry } from '../l2/keys.js';

// Host-side audit subsystem. Decides accept/reject/unavailable and seals accepted records into
// the tamper-evident ledger. Does not authorize domain actions (operator allowlist owns that);
// rejects only malformed, forged, or replayed records so they never enter the chain.

// Tier-1 codes the host emits (§7.6): reject/unavailable reasons logged when refusing a record,
// and anomaly kinds flagged on accepted records. Finer cause (e.g. numeric-domain, id vs signer_seq
// replay, orphan sub-kind) is carried as Tier-2 free text in `detail`.
export interface IntegrityAnomaly {
  id: string;
  kind:
    | 'schema-invalid'
    | 'replay-detected'
    | 'l2-unsigned'
    | 'unknown-key'
    | 'signature-invalid'
    | 'signer-seq-gap'
    | 'orphaned-outcome';
  detail: string;
}

export class AuditHost {
  readonly ledger: Ledger;
  private readonly capability: AuditCapability;
  private readonly keyRegistry: KeyRegistry | undefined;
  private readonly acceptedAttempts = new Set<string>();
  private readonly rejectedIds = new Set<string>();
  private readonly lastSeqByKey = new Map<string, number>();
  private readonly anomalies: IntegrityAnomaly[] = [];
  private hostClock = 0;

  // Test switch: simulate durability failure; must fail closed.
  unavailable = false;

  constructor(partition: string, capability: AuditCapability = DEFAULT_L1_CAPABILITY, keyRegistry?: KeyRegistry) {
    this.ledger = new Ledger(partition);
    this.capability = capability;
    this.keyRegistry = keyRegistry;
  }

  negotiate(offered: AuditCapability): NegotiationResult {
    return negotiateCapability(this.capability, offered);
  }

  getAnomalies(): readonly IntegrityAnomaly[] {
    return this.anomalies;
  }

  // Deterministic monotonic host time in ISO-8601 (§8.2); no wall clock, for reproducible vectors.
  private nextHostTs(): string {
    this.hostClock += 1;
    return new Date(Date.UTC(2026, 6, 15, 0, 0, this.hostClock)).toISOString();
  }

  // L2 (§7.4): verify signature over a registered key and per-key_id signer_seq. Unsigned, forged,
  // or replayed records are rejected. A forward signer_seq gap is flagged (signer-seq-gap), not
  // rejected: the suppressed event is unrecoverable. No-op under L1. The first signer_seq for a
  // key_id (no prior tracked value) is the baseline, so it is accepted and never flagged as a gap.
  private checkL2(event: AuditEvent): { reject: false } | { reject: true; reason: RejectReason } {
    if (this.capability.level !== 'L2') return { reject: false };

    if (!event.signature || !event.key_id || event.signer_seq === undefined) {
      this.anomalies.push({ id: event.id, kind: 'l2-unsigned', detail: 'L2 requires signature, key_id, signer_seq' });
      return { reject: true, reason: 'l2-unsigned' };
    }
    const key = this.keyRegistry?.get(event.key_id);
    if (!key) {
      this.anomalies.push({ id: event.id, kind: 'unknown-key', detail: `no registered key for ${event.key_id}` });
      return { reject: true, reason: 'unknown-key' };
    }
    if (!verifyEventSignature(event, key)) {
      this.anomalies.push({ id: event.id, kind: 'signature-invalid', detail: 'signature does not verify (forged/altered)' });
      return { reject: true, reason: 'signature-invalid' };
    }
    const last = this.lastSeqByKey.get(event.key_id);
    if (last === undefined) {
      // First observation for this key_id is the baseline (§7.4): accepted as-is, never a gap,
      // because there is no prior value to compare against (a persisted or cross-partition counter
      // may legitimately start above 0).
      return { reject: false };
    }
    if (event.signer_seq <= last) {
      this.anomalies.push({ id: event.id, kind: 'replay-detected', detail: `signer_seq ${event.signer_seq} <= last ${last}` });
      return { reject: true, reason: 'replay-detected' };
    }
    if (event.signer_seq > last + 1) {
      this.anomalies.push({ id: event.id, kind: 'signer-seq-gap', detail: `expected ${last + 1}, got ${event.signer_seq} (suppressed event)` });
    }
    return { reject: false };
  }

  // Advance the per-key signer_seq tracker; called only after a record is sealed (§7.4). The tracker
  // follows the last accepted (sealed) signer_seq, not the last seen, so an unavailable/retryable
  // attempt does not poison the counter for a retry.
  private advanceSeq(event: AuditEvent): void {
    if (event.key_id !== undefined && event.signer_seq !== undefined) {
      this.lastSeqByKey.set(event.key_id, event.signer_seq);
    }
  }

  handleAttempt(raw: unknown): AttemptResponse {
    const parsed = auditEventSchema.safeParse(raw);
    if (!parsed.success) {
      const id = extractId(raw);
      this.anomalies.push({ id, kind: 'schema-invalid', detail: parsed.error.message });
      return { status: 'reject', reason: 'schema-invalid' };
    }
    const event = parsed.data;
    if (event.outcome !== 'attempted') {
      // Tier-1 schema-invalid; the Tier-2 specifics go in detail (§7.6).
      this.anomalies.push({ id: event.id, kind: 'schema-invalid', detail: 'attempt-must-be-attempted: attempt must carry outcome=attempted' });
      return { status: 'reject', reason: 'schema-invalid' };
    }
    // Not canonicalizable (§8.1): reject gracefully instead of throwing at seal time.
    if (hasUnsafeNumber(event)) {
      this.anomalies.push({ id: event.id, kind: 'schema-invalid', detail: 'numeric-domain: numeric value not canonicalizable (§8.1)' });
      return { status: 'reject', reason: 'schema-invalid' };
    }
    // L2: reject forged/unsigned/replayed records before sealing.
    const l2 = this.checkL2(event);
    if (l2.reject) {
      this.rejectedIds.add(event.id);
      return { status: 'reject', reason: l2.reason };
    }
    // Persistence failure: fail closed (retryable), returned as internal-error (§7.6).
    if (this.unavailable) {
      return { status: 'unavailable', reason: 'internal-error', retryable: true };
    }
    // Replayed attempt id: reject as duplicate.
    if (this.acceptedAttempts.has(event.id)) {
      this.rejectedIds.add(event.id);
      this.anomalies.push({ id: event.id, kind: 'replay-detected', detail: 'id-replay: duplicate attempt id' });
      return { status: 'reject', reason: 'replay-detected' };
    }
    const sealed = this.ledger.append(event, this.nextHostTs());
    this.acceptedAttempts.add(event.id);
    this.advanceSeq(event);
    // Verifiable Accept (§7.1): return host-assigned fields the tool needs to reconstruct the
    // §8.2 preimage for Polluted Stop verification.
    return {
      status: 'accept',
      seq: sealed.seq,
      record_hash: sealed.record_hash,
      host_ts: sealed.host_ts,
      previous_hash: sealed.previous_hash,
    };
  }

  // Outcome is appended, not gated. A success/failed outcome for a never-accepted or rejected id is
  // flagged; a fail-closed `aborted` outcome is not (§10.4).
  handleOutcome(raw: unknown): void {
    const parsed = auditEventSchema.safeParse(raw);
    if (!parsed.success) {
      this.anomalies.push({ id: extractId(raw), kind: 'schema-invalid', detail: parsed.error.message });
      return;
    }
    const event = parsed.data;
    // Not canonicalizable (§8.1): drop instead of throwing at seal time.
    if (hasUnsafeNumber(event)) {
      this.anomalies.push({ id: event.id, kind: 'schema-invalid', detail: 'numeric-domain: numeric value not canonicalizable (§8.1)' });
      return;
    }
    // §6: an `attempted` outcome on the audit/outcome channel is invalid; drop and flag it rather than
    // sealing a second attempt record for the id (§7.1 uniqueness).
    if (event.outcome === 'attempted') {
      this.anomalies.push({ id: event.id, kind: 'schema-invalid', detail: 'attempted outcome on the audit/outcome channel (§6)' });
      return;
    }
    // An aborted outcome MUST carry a Tier-1 abort code (§7.2). Zod pins the value but not its
    // presence; the emitted JSON Schema adds the conditional, and the host enforces it here too.
    if (event.outcome === 'aborted' && event.reason === undefined) {
      this.anomalies.push({ id: event.id, kind: 'schema-invalid', detail: 'aborted-without-reason: an aborted outcome MUST carry a Tier-1 abort code (§7.2)' });
      return;
    }
    // §10.4: a fail-closed `aborted` outcome for a never-accepted or rejected attempt is the honest
    // refused-action signal, not a tampering anomaly. Exempt it before checkL2, so a fresh signer
    // sequence that outran the unsealed attempt is not flagged as a suppression gap.
    if (event.outcome === 'aborted' && !this.acceptedAttempts.has(event.id)) return;
    // L2: drop an outcome with invalid signature/sequence (a notification has no reply).
    if (this.checkL2(event).reject) return;
    if (this.acceptedAttempts.has(event.id)) {
      // Each correlated outcome is sealed, not de-duplicated (§8.3). This reference imposes no cap
      // on outcomes per id; §8.3 makes that bound a host/SDK responsibility, so picking a number
      // here would be an arbitrary policy the spec deliberately leaves open.
      this.ledger.append(event, this.nextHostTs());
      this.advanceSeq(event);
      return;
    }
    if (this.rejectedIds.has(event.id)) {
      this.anomalies.push({ id: event.id, kind: 'orphaned-outcome', detail: `after-reject: outcome=${event.outcome} for rejected id` });
    } else {
      this.anomalies.push({ id: event.id, kind: 'orphaned-outcome', detail: `never-accepted: outcome=${event.outcome} without accepted attempt` });
    }
  }

  records(): readonly SealedRecord[] {
    return this.ledger.all();
  }
}

function extractId(raw: unknown): string {
  if (raw && typeof raw === 'object' && 'id' in raw && typeof (raw as { id: unknown }).id === 'string') {
    return (raw as { id: string }).id;
  }
  return '<unknown>';
}
