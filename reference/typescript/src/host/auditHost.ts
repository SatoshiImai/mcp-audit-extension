import { randomUUID } from 'node:crypto';
import type { AuditEvent } from '../schema/event.js';
import type { AuditCapability, NegotiationResult } from '../schema/capability.js';
import { DEFAULT_L1_CAPABILITY, negotiateCapability } from '../schema/capability.js';
import { checkEventStructure } from '../schema/validate.js';
import { Ledger, type Countersigner, type SealedRecord } from '../ledger/ledger.js';
import { canonicalize } from '../ledger/canonical.js';
import type { AttemptResponse, RejectReason } from '../transport/transport.js';
import { verifyEventSignature } from '../l2/signing.js';
import type { KeyRegistry } from '../l2/keys.js';

// Host-side audit subsystem. Decides accept/reject/unavailable and seals records into the
// tamper-evident ledger. Does not authorize domain actions (operator allowlist owns that); rejects
// only malformed, forged, or replayed records so they never enter the chain.

// The Tier-1 anomaly kinds the host records (§7.6). Finer cause is Tier-2 free text in `detail`.
export type AnomalyKind =
  | 'schema-invalid'
  | 'replay-detected'
  | 'signature-invalid'
  | 'signer-seq-gap'
  | 'orphaned-outcome'
  | 'unresolved-attempt';

export interface IntegrityAnomaly {
  id: string;
  kind: AnomalyKind;
  detail: string;
}

// The replay window of one key in one audit session (§7.4): the signer_seq values the host has
// decided - sealed, or rejected after the signature verified - and the highest received with a
// verifying signature. `unavailable` and an idempotent duplicate add nothing to `decided`.
interface KeyTracker {
  decided: Set<number>;
  received: number | undefined;
}

// One audit session: one tools/call (§6.3).
interface Session {
  trackers: Map<string, KeyTracker>;
  accepted: Set<string>;
  rejected: Set<string>;
  // The canonical form of the terminal outcome sealed for each id: one per operation (§7.2).
  outcomes: Map<string, string>;
}

type SignatureCheck = { ok: true; tracker?: KeyTracker; signerSeq?: number } | { ok: false; reason: RejectReason };

type Admitted = { ok: true; event: AuditEvent; session: Session } | { ok: false; reason: RejectReason };

// The Tier-1 anomaly kind of a Level-2 reject reason (§7.6): a missing signature and an unknown key
// are signature failures in the anomaly code space.
const SIGNATURE_ANOMALY: AnomalyKind = 'signature-invalid';

export class AuditHost {
  readonly ledger: Ledger;
  private readonly capability: AuditCapability;
  private readonly keyRegistry: KeyRegistry | undefined;
  private readonly sessions = new Map<string, Session>();
  private readonly issued = new Set<string>();
  // The partition's sealed attempts by id, with the canonical bytes and the response they got, so
  // a byte-identical repeat is answered from the ledger (§7.1).
  private readonly sealedAttempts = new Map<string, { canonical: string; response: AttemptResponse }>();
  private readonly anomalies: IntegrityAnomaly[] = [];
  private readonly countersigner?: Countersigner;
  private hostClock = 0;

  // Test switch: simulate durability failure; must fail closed.
  unavailable = false;

  // A host that declares it countersigns and then does not would leave every record uncountersigned
  // while its peers expect otherwise; a host that declares `none` MUST NOT return the triple (§7.1),
  // and holding a signer is the only way to violate that. Both are refused here, not at seal time.
  constructor(
    partition: string,
    capability: AuditCapability = DEFAULT_L1_CAPABILITY,
    keyRegistry?: KeyRegistry,
    countersigner?: Countersigner,
  ) {
    if (capability.countersign === 'host' && countersigner === undefined) {
      throw new Error('a host declaring countersign "host" requires a Countersigner (§5.2)');
    }
    if (capability.countersign === 'none' && countersigner !== undefined) {
      throw new Error('a host declaring countersign "none" must not hold a Countersigner (§7.1)');
    }
    this.ledger = new Ledger(partition);
    this.capability = capability;
    this.keyRegistry = keyRegistry;
    this.countersigner = countersigner;
  }

  negotiate(offered: AuditCapability): NegotiationResult {
    return negotiateCapability(this.capability, offered);
  }

  // The capability object this host declares (§6.1).
  declaration(): AuditCapability {
    return this.capability;
  }

  getAnomalies(): readonly IntegrityAnomaly[] {
    return this.anomalies;
  }

  // Issue a fresh audit session for a call the host audits (§6.3): never one issued before, even
  // for a session that has since ended.
  openSession(sessionId: string = randomUUID()): string {
    if (this.issued.has(sessionId)) throw new Error(`session ${sessionId} was already issued (§6.3)`);
    this.issued.add(sessionId);
    this.sessions.set(sessionId, { trackers: new Map(), accepted: new Set(), rejected: new Set(), outcomes: new Map() });
    return sessionId;
  }

  // The call ended (§6.3): every outcome of the session has been delivered, so an accepted attempt
  // without a sealed terminal outcome was never resolved. The session accepts nothing further, and
  // its replay window is discarded (§7.4).
  closeSession(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session === undefined) return;
    for (const id of session.accepted) {
      if (!session.outcomes.has(id)) {
        this.flag(id, 'unresolved-attempt', `call ended with attempt ${id} unresolved`);
      }
    }
    this.sessions.delete(sessionId);
  }

  private flag(id: string, kind: AnomalyKind, detail: string): void {
    this.anomalies.push({ id, kind, detail });
  }

  // Deterministic monotonic host time in ISO-8601 (§8.2); no wall clock, for reproducible vectors.
  private nextHostTs(): string {
    this.hostClock += 1;
    return new Date(Date.UTC(2026, 6, 15, 0, 0, this.hostClock)).toISOString();
  }

  // Structure (§7.1 step 1, incl. which outcome each channel carries) and then the session (step 2).
  // `arrivedOn` is the set of sessions the host issued for the calls in flight on the connection the
  // event arrived on (§6.5); without it, any open session is the call's (a transport bound to one call).
  private admit(raw: unknown, attempt: boolean, arrivedOn?: ReadonlySet<string>): Admitted {
    const check = checkEventStructure(raw);
    if (!check.ok) {
      this.flag(extractId(raw), 'schema-invalid', check.detail);
      return { ok: false, reason: 'schema-invalid' };
    }
    const { event } = check;
    if ((event.outcome === 'attempted') !== attempt) {
      const detail = attempt ? 'attempt-must-be-attempted: attempt must carry outcome=attempted' : 'attempted outcome on the outcome channel (§6)';
      this.flag(event.id, 'schema-invalid', detail);
      return { ok: false, reason: 'schema-invalid' };
    }
    const session = this.sessions.get(event.session_id);
    if (session === undefined || (arrivedOn !== undefined && !arrivedOn.has(event.session_id))) {
      this.flag(event.id, 'replay-detected', `session: ${event.session_id} is not the session of a call in flight (§6.3)`);
      return { ok: false, reason: 'replay-detected' };
    }
    return { ok: true, event, session };
  }

  // Level 2 (§7.1 step 3, §7.4). Once the signature verifies the event counts as received: a value
  // more than one past the highest received - or a first value other than 0 - is flagged, not rejected.
  private verifySignature(event: AuditEvent, session: Session): SignatureCheck {
    if (this.capability.level !== 'L2') return { ok: true };
    if (event.signature === undefined || event.key_id === undefined || event.signer_seq === undefined) {
      this.flag(event.id, SIGNATURE_ANOMALY, 'l2-unsigned: Level 2 requires signature, key_id, signer_seq');
      return { ok: false, reason: 'l2-unsigned' };
    }
    const key = this.keyRegistry?.current(event.key_id);
    if (key === undefined) {
      this.flag(event.id, SIGNATURE_ANOMALY, `unknown-key: no current registry entry for ${event.key_id}`);
      return { ok: false, reason: 'unknown-key' };
    }
    if (!verifyEventSignature(event, key)) {
      this.flag(event.id, SIGNATURE_ANOMALY, 'signature does not verify (forged/altered)');
      return { ok: false, reason: 'signature-invalid' };
    }
    let tracker = session.trackers.get(event.key_id);
    if (tracker === undefined) {
      tracker = { decided: new Set(), received: undefined };
      session.trackers.set(event.key_id, tracker);
    }
    const seq = event.signer_seq;
    if (tracker.received === undefined ? seq !== 0 : seq > tracker.received + 1) {
      const expected = tracker.received === undefined ? 0 : tracker.received + 1;
      this.flag(event.id, 'signer-seq-gap', `expected ${expected}, got ${seq}`);
    }
    if (tracker.received === undefined || seq > tracker.received) tracker.received = seq;
    return { ok: true, tracker, signerSeq: seq };
  }

  private static decide(check: SignatureCheck): void {
    if (check.ok && check.tracker !== undefined && check.signerSeq !== undefined) check.tracker.decided.add(check.signerSeq);
  }

  private static alreadyDecided(check: SignatureCheck): boolean {
    return check.ok && check.tracker !== undefined && check.signerSeq !== undefined && check.tracker.decided.has(check.signerSeq);
  }

  handleAttempt(raw: unknown, arrivedOn?: ReadonlySet<string>): AttemptResponse {
    const admitted = this.admit(raw, true, arrivedOn);
    if (!admitted.ok) return { status: 'reject', reason: admitted.reason };
    const { event, session } = admitted;
    const signed = this.verifySignature(event, session);
    if (!signed.ok) {
      session.rejected.add(event.id);
      return { status: 'reject', reason: signed.reason };
    }
    // §7.1 step 4: a sealed id answers a byte-identical repeat from the ledger and rejects anything else.
    const canonical = canonicalize(event);
    const sealed = this.sealedAttempts.get(event.id);
    if (sealed !== undefined) {
      if (sealed.canonical === canonical) return sealed.response;
      AuditHost.decide(signed);
      session.rejected.add(event.id);
      this.flag(event.id, 'replay-detected', 'id-replay: attempt id sealed with a different event');
      return { status: 'reject', reason: 'replay-detected' };
    }
    // §7.1 step 4: an operation with a sealed outcome has concluded, and no attempt is sealed after
    // its own terminal record.
    if (session.outcomes.has(event.id)) {
      AuditHost.decide(signed);
      session.rejected.add(event.id);
      this.flag(event.id, 'replay-detected', 'concluded: the operation already has a sealed outcome');
      return { status: 'reject', reason: 'replay-detected' };
    }
    // §7.1 step 5: a signer_seq already decided in this session is a replay.
    if (AuditHost.alreadyDecided(signed)) {
      session.rejected.add(event.id);
      this.flag(event.id, 'replay-detected', `sequence: signer_seq ${event.signer_seq} already decided`);
      return { status: 'reject', reason: 'replay-detected' };
    }
    // Persistence failure: nothing is decided, so the identical attempt may come again (§7.1).
    if (this.unavailable) return { status: 'unavailable', reason: 'internal-error' };

    const record = this.ledger.append(event, this.nextHostTs(), this.countersigner);
    AuditHost.decide(signed);
    session.accepted.add(event.id);
    // Verifiable Accept (§7.1): the host-assigned fields the tool needs to reconstruct the §8.2
    // preimage for Polluted Stop, and the countersignature triple where the host countersigns.
    const response: AttemptResponse = {
      status: 'accept',
      seq: record.seq,
      record_hash: record.record_hash,
      host_ts: record.host_ts,
      previous_hash: record.previous_hash,
      ...(record.host_signature !== undefined && record.host_key_id !== undefined && record.log_id !== undefined
        ? { host_signature: record.host_signature, host_key_id: record.host_key_id, log_id: record.log_id }
        : {}),
    };
    this.sealedAttempts.set(event.id, { canonical, response });
    return response;
  }

  // An outcome has no response (§6): one that fails validation is dropped and recorded under its
  // Tier-1 anomaly kind, never answered and never thrown. It is validated in the order an attempt is
  // - structure, session, signature, uniqueness, sequence - and only then correlated (§7.2).
  handleOutcome(raw: unknown, arrivedOn?: ReadonlySet<string>): void {
    const admitted = this.admit(raw, false, arrivedOn);
    if (!admitted.ok) return;
    const { event, session } = admitted;
    // The signature is verified, and the event counted as received, even when the host then turns
    // out to be unavailable: receiving and deciding are separate (§7.4).
    const signed = this.verifySignature(event, session);
    if (!signed.ok) return;
    // One terminal record per (session_id, id) (§7.2): a byte-identical repeat is not processed further.
    const canonical = canonicalize(event);
    const sealed = session.outcomes.get(event.id);
    if (sealed !== undefined) {
      if (sealed === canonical) return;
      AuditHost.decide(signed);
      this.flag(event.id, 'replay-detected', 'correlation: differs from the outcome already sealed for this operation');
      return;
    }
    if (AuditHost.alreadyDecided(signed)) {
      this.flag(event.id, 'replay-detected', `sequence: signer_seq ${event.signer_seq} already decided`);
      return;
    }
    const correlated = session.accepted.has(event.id);
    // §7.2: a success or failed outcome with no accepted attempt in its session is not sealed.
    if (!correlated && event.outcome !== 'aborted') {
      AuditHost.decide(signed);
      const sub = session.rejected.has(event.id) ? 'after-reject' : 'never-accepted';
      this.flag(event.id, 'orphaned-outcome', `${sub}: outcome=${event.outcome}`);
      return;
    }
    // The switch that simulates a durability failure covers every seal, not only attempts.
    if (this.unavailable) return;
    // A correlated outcome is its operation's terminal record; an aborted outcome of an attempt the
    // host did not accept is the record of an operation the tool declined to perform (§7.2, §10.4).
    this.ledger.append(event, this.nextHostTs(), this.countersigner);
    AuditHost.decide(signed);
    session.outcomes.set(event.id, canonical);
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
