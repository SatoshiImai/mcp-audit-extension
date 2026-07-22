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

  append(event: AuditEvent, hostTs: string): SealedRecord {
    const seq = this.records.length;
    const prev = this.records[seq - 1];
    const previousHash = prev ? prev.record_hash : GENESIS_HASH;
    const record_hash = computeRecordHash(event, seq, hostTs, previousHash);
    const sealed: SealedRecord = { event, seq, host_ts: hostTs, previous_hash: previousHash, record_hash };
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
