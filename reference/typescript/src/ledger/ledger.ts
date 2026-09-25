import type { AuditEvent } from '../schema/event.js';
import { canonicalize, sha256Hex } from './canonical.js';

// A sealed record is a tool-emitted event plus host-assigned fields (seq, previous_hash,
// record_hash). Local deterministic simulation of a tamper-evident append-only ledger.

export const GENESIS_HASH = '0'.repeat(64);

export interface SealedRecord {
  event: AuditEvent;
  seq: number; // partition-monotonic ledger index assigned by the sealer (a gap means a record was lost)
  host_ts: string; // authoritative host time
  previous_hash: string; // previous record_hash in the chain
  record_hash: string; // sha256( JCS({event, host_ts, previous_hash, seq}) )
  // The countersignature triple appears together or not at all (§7.1). A record carrying it was
  // confirmed by the host that `host_key_id` names, in the ledger `log_id` names; one without it is
  // uncountersigned, a state and not an anomaly (§5.2).
  host_signature?: string;
  host_key_id?: string;
  log_id?: string;
}

// Countersigns every record this host seals (§5.2, §7.1).
export interface Countersigner {
  readonly keyId: string; // the `host_key_id` a verifier's registry resolves to this host's key
  sign(payload: string): string; // base64url over the UTF-8 bytes of the canonical payload
}

// The bytes a countersigning host signs: the canonical form of its own assigned fields and the name
// of the ledger (§7.1). The preimage carries no signature field, so there is no self-reference, and
// it is not part of the §8.2 record-hash preimage - a record sealed with a countersignature and the
// same record sealed without one have the same record_hash.
export function countersignaturePayload(
  seq: number,
  hostTs: string,
  logId: string,
  previousHash: string,
  recordHash: string,
): string {
  return canonicalize({ host_ts: hostTs, log_id: logId, previous_hash: previousHash, record_hash: recordHash, seq });
}

// The bytes the chain commits to: a single JCS-canonicalized object (§8.2), never a
// delimiter-joined string. Kept explicit so the verifier recomputes identically.
export function computeRecordHash(
  event: AuditEvent,
  seq: number,
  hostTs: string,
  previousHash: string,
): string {
  const preimage = { event, host_ts: hostTs, previous_hash: previousHash, seq };
  return sha256Hex(canonicalize(preimage));
}

// Append-only, per-partition ledger. Append assigns the next seq and links the chain.
export class Ledger {
  private records: SealedRecord[] = [];

  // `logId` names this partition's chain in every countersignature (§7.1); it defaults to the
  // partition's own name, which is stable and distinct from every other chain the host keeps.
  constructor(
    public readonly partition: string,
    public readonly logId: string = partition,
  ) {}

  // §7.1 requires the assignment, the seal and the commit to be atomic with respect to any other
  // record being sealed into the same partition. Nothing here awaits, so the section is the call
  // itself; a host that signs or persists asynchronously holds a lock across the same span.
  append(event: AuditEvent, hostTs: string, countersigner?: Countersigner): SealedRecord {
    const seq = this.records.length;
    const prev = this.records[seq - 1];
    const previousHash = prev ? prev.record_hash : GENESIS_HASH;
    const record_hash = computeRecordHash(event, seq, hostTs, previousHash);
    const sealed: SealedRecord = { event, seq, host_ts: hostTs, previous_hash: previousHash, record_hash };
    if (countersigner !== undefined) {
      sealed.host_signature = countersigner.sign(
        countersignaturePayload(seq, hostTs, this.logId, previousHash, record_hash),
      );
      sealed.host_key_id = countersigner.keyId;
      sealed.log_id = this.logId;
    }
    this.records.push(sealed);
    return sealed;
  }

  all(): readonly SealedRecord[] {
    return this.records;
  }

  // Tail digest, anchored out-of-band. Rewriting history invalidates it.
  digest(): string {
    const tail = this.records[this.records.length - 1];
    return tail ? tail.record_hash : GENESIS_HASH;
  }

  // Test/demo affordance: expose the mutable array to inject a tamper.
  unsafeMutableRecords(): SealedRecord[] {
    return this.records;
  }
}
