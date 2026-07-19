import { auditEventSchema, type AuditEvent } from '../schema/event.js';
import type { AuditCapability, NegotiationResult } from '../schema/capability.js';
import { DEFAULT_L1_CAPABILITY, negotiateCapability } from '../schema/capability.js';
import { Ledger, type SealedRecord } from '../ledger/ledger.js';
import type { AttemptResponse } from '../transport/transport.js';
import { verifyEventSignature } from '../l2/signing.js';
import type { KeyRegistry } from '../l2/keys.js';

// Host-side audit subsystem. Decides accept/reject/unavailable and seals accepted records into
// the tamper-evident ledger. Does not authorize domain actions (operator allowlist owns that);
// rejects only malformed, forged, or replayed records so they never enter the chain.

export interface IntegrityAnomaly {
  id: string;
  kind:
    | 'schema-invalid'
    | 'attempt-replay'
    | 'outcome-without-attempt'
    | 'outcome-after-reject'
    | 'l2-unsigned'
    | 'unknown-key'
    | 'signature-invalid'
    | 'sequence-replay'
    | 'sequence-gap';
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
    return `2026-07-15T00:00:${String(this.hostClock).padStart(2, '0')}.000Z`;
  }

  // L2 (§7.4): verify signature over a registered key and per-tool sequence. Unsigned, forged,
  // or replayed records are rejected. A forward sequence gap is flagged, not rejected: the
  // suppressed event is unrecoverable. No-op under L1.
  private checkL2(event: AuditEvent): { reject: false } | { reject: true; reason: string } {
    if (this.capability.level !== 'L2') return { reject: false };

    if (!event.signature || !event.key_id || event.sequence === undefined) {
      this.anomalies.push({ id: event.id, kind: 'l2-unsigned', detail: 'L2 requires signature, key_id, sequence' });
      return { reject: true, reason: 'l2-unsigned' };
    }
    const publicKey = this.keyRegistry?.get(event.key_id);
    if (!publicKey) {
      this.anomalies.push({ id: event.id, kind: 'unknown-key', detail: `no registered key for ${event.key_id}` });
      return { reject: true, reason: 'unknown-key' };
    }
    if (!verifyEventSignature(event, publicKey)) {
      this.anomalies.push({ id: event.id, kind: 'signature-invalid', detail: 'signature does not verify (forged/altered)' });
      return { reject: true, reason: 'signature-invalid' };
    }
    const last = this.lastSeqByKey.get(event.key_id) ?? -1;
    if (event.sequence <= last) {
      this.anomalies.push({ id: event.id, kind: 'sequence-replay', detail: `sequence ${event.sequence} <= last ${last}` });
      return { reject: true, reason: 'sequence-replay' };
    }
    if (event.sequence > last + 1) {
      this.anomalies.push({ id: event.id, kind: 'sequence-gap', detail: `expected ${last + 1}, got ${event.sequence} (suppressed event)` });
    }
    this.lastSeqByKey.set(event.key_id, event.sequence);
    return { reject: false };
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
      this.anomalies.push({ id: event.id, kind: 'schema-invalid', detail: 'attempt must carry outcome=attempted' });
      return { status: 'reject', reason: 'attempt-must-be-attempted' };
    }
    // L2: reject forged/unsigned/replayed records before sealing.
    const l2 = this.checkL2(event);
    if (l2.reject) {
      this.rejectedIds.add(event.id);
      return { status: 'reject', reason: l2.reason };
    }
    // Durability failure: fail closed (retryable).
    if (this.unavailable) {
      return { status: 'unavailable', reason: 'tier1-durability-failure', retryable: true };
    }
    // Replayed attempt id: reject as duplicate.
    if (this.acceptedAttempts.has(event.id)) {
      this.rejectedIds.add(event.id);
      this.anomalies.push({ id: event.id, kind: 'attempt-replay', detail: 'duplicate attempt id' });
      return { status: 'reject', reason: 'attempt-replay' };
    }
    const sealed = this.ledger.append(event, this.nextHostTs());
    this.acceptedAttempts.add(event.id);
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

  // Outcome is appended, not gated. An outcome for an id never accepted, or rejected, is flagged.
  handleOutcome(raw: unknown): void {
    const parsed = auditEventSchema.safeParse(raw);
    if (!parsed.success) {
      this.anomalies.push({ id: extractId(raw), kind: 'schema-invalid', detail: parsed.error.message });
      return;
    }
    const event = parsed.data;
    // L2: drop an outcome with invalid signature/sequence (a notification has no reply).
    if (this.checkL2(event).reject) return;
    if (this.rejectedIds.has(event.id)) {
      this.anomalies.push({ id: event.id, kind: 'outcome-after-reject', detail: `outcome=${event.outcome} for rejected id` });
      return;
    }
    if (!this.acceptedAttempts.has(event.id)) {
      this.anomalies.push({ id: event.id, kind: 'outcome-without-attempt', detail: `outcome=${event.outcome} without accepted attempt` });
      return;
    }
    this.ledger.append(event, this.nextHostTs());
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
