import { auditEventSchema, type AuditEvent } from '../schema/event.js';
import type { AuditCapability } from '../schema/capability.js';
import { DEFAULT_L1_CAPABILITY } from '../schema/capability.js';
import { Ledger, type SealedRecord } from '../ledger/ledger.js';
import type { AttemptResponse } from '../transport/transport.js';
import { verifyEventSignature } from '../l2/signing.js';
import type { KeyRegistry } from '../l2/keys.js';

// Host-side audit subsystem. Receives self-attested events, decides accept/reject/unavailable,
// and seals accepted records into the tamper-evident ledger. It is a monitoring camera, not a
// control point: it never authorizes the tool's domain action (that is the operator's allowlist). The
// only thing it blocks is a lie into the ledger — a malformed, forged, or replayed record
// gets `reject` and never pollutes the chain (design §0, §6.1).

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

  // Demo switch: simulate Tier1 durability failure (infra), which must fail-closed.
  unavailable = false;

  constructor(partition: string, capability: AuditCapability = DEFAULT_L1_CAPABILITY, keyRegistry?: KeyRegistry) {
    this.ledger = new Ledger(partition);
    this.capability = capability;
    this.keyRegistry = keyRegistry;
  }

  negotiate(): AuditCapability {
    return this.capability;
  }

  getAnomalies(): readonly IntegrityAnomaly[] {
    return this.anomalies;
  }

  // Deterministic monotonic host time (no wall clock, for reproducible test vectors).
  private nextHostTs(): string {
    this.hostClock += 1;
    return `host-ts:${this.hostClock}`;
  }

  // L2 record-integrity check. Verifies non-repudiation (signature over a registered key)
  // and per-tool sequence continuity. A forged/altered/unsigned record or a replayed
  // sequence is a lie into the ledger → `reject`. A forward gap means a prior event was
  // suppressed → flagged (the suppression is already committed; rejecting the current event
  // would not recover the missing one). No-op under L1. This detects tampering; it never
  // controls the tool's domain action.
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
    // L2: reject forged/unsigned/replayed records before they touch the ledger.
    const l2 = this.checkL2(event);
    if (l2.reject) {
      this.rejectedIds.add(event.id);
      return { status: 'reject', reason: l2.reason };
    }
    // Infra durability failure → fail-closed. Not the tool's fault; retryable.
    if (this.unavailable) {
      return { status: 'unavailable', reason: 'tier1-durability-failure', retryable: true };
    }
    // Replayed attempt id = a forged/duplicate record → reject the lie, keep the ledger clean.
    if (this.acceptedAttempts.has(event.id)) {
      this.rejectedIds.add(event.id);
      this.anomalies.push({ id: event.id, kind: 'attempt-replay', detail: 'duplicate attempt id' });
      return { status: 'reject', reason: 'attempt-replay' };
    }
    const sealed = this.ledger.append(event, this.nextHostTs());
    this.acceptedAttempts.add(event.id);
    return { status: 'accept', seq: sealed.seq, record_hash: sealed.record_hash };
  }

  // Outcome is not a completeness gate; it is appended. Anomalies (outcome for an id that
  // was never accepted, or was rejected) are flagged — the natural tamper-evidence byproduct.
  handleOutcome(raw: unknown): void {
    const parsed = auditEventSchema.safeParse(raw);
    if (!parsed.success) {
      this.anomalies.push({ id: extractId(raw), kind: 'schema-invalid', detail: parsed.error.message });
      return;
    }
    const event = parsed.data;
    // L2: an outcome with an invalid signature/sequence is a lie too; flag and drop it
    // (an outcome is a notification, so there is no response to reject with).
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
