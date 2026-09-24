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
  // The witness pair appears together or not at all (§7.1). A record carrying it was confirmed by
  // the host that `host_key_id` names; one without it is unwitnessed, a state and not an anomaly.
  host_signature?: string;
  host_key_id?: string;
}

// Signs the host-assigned fields of every record this host seals (§5.2, §7.1).
export interface WitnessSigner {
  readonly keyId: string; // the `host_key_id` a verifier's registry resolves to this host's key
  sign(payload: string): string; // standard-base64 over the UTF-8 bytes of the canonical payload
}

// The bytes a witnessing host signs: the canonical form of its own assigned fields (§7.1). The
// preimage carries no signature field, so there is no self-reference, and it is not part of the
// §8.2 record-hash preimage - a record sealed with a witness signature and the same record sealed
// without one have the same record_hash.
export function witnessPayload(
  seq: number,
  hostTs: string,
  previousHash: string,
  recordHash: string,
): string {
  return canonicalize({ host_ts: hostTs, previous_hash: previousHash, record_hash: recordHash, seq });
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

  constructor(public readonly partition: string) {}

  // §7.1 requires the assignment, the seal and the commit to be atomic with respect to any other
  // record being sealed into the same partition. Nothing here awaits, so the section is the call
  // itself; a host that signs or persists asynchronously holds a lock across the same span.
  append(event: AuditEvent, hostTs: string, witness?: WitnessSigner): SealedRecord {
    const seq = this.records.length;
    const prev = this.records[seq - 1];
    const previousHash = prev ? prev.record_hash : GENESIS_HASH;
    const record_hash = computeRecordHash(event, seq, hostTs, previousHash);
    const sealed: SealedRecord = { event, seq, host_ts: hostTs, previous_hash: previousHash, record_hash };
    if (witness !== undefined) {
      sealed.host_signature = witness.sign(witnessPayload(seq, hostTs, previousHash, record_hash));
      sealed.host_key_id = witness.keyId;
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
