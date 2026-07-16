import type { AuditEvent } from '../schema/event.js';
import { canonicalize, sha256Hex } from './canonical.js';

// Sealed record = tool-emitted event + host-assigned ledger fields. In a real deployment
// these tiers map to DynamoDB (Tier1 durable accept) + Sealing Lambda → S3 Object Lock
// (Tier2 WORM + hash-chain), design audit-integrity §2. The PoC simulates both locally and
// deterministically — the standardization-relevant artifact is the hash chain, not AWS.

export const GENESIS_HASH = '0'.repeat(64);

export interface SealedRecord {
  event: AuditEvent;
  seq: number; // partition-monotonic sequence assigned by the sealer (a gap means a record was lost)
  host_ts: string; // authoritative host time
  prev_hash: string; // previous record_hash in the chain
  record_hash: string; // sha256( canonical(event) ‖ seq ‖ host_ts ‖ prev_hash )
}

// The bytes the chain commits to. Kept explicit so the verifier recomputes identically.
export function computeRecordHash(
  event: AuditEvent,
  seq: number,
  hostTs: string,
  prevHash: string,
): string {
  const preimage = `${canonicalize(event)}|${seq}|${hostTs}|${prevHash}`;
  return sha256Hex(preimage);
}

// Append-only, per-partition ledger. A partition is a tenant#day-like scope; the PoC keeps
// one in memory. Append assigns the next seq and links the hash chain.
export class Ledger {
  private records: SealedRecord[] = [];

  constructor(public readonly partition: string) {}

  append(event: AuditEvent, hostTs: string): SealedRecord {
    const seq = this.records.length;
    const prev = this.records[seq - 1];
    const prevHash = prev ? prev.record_hash : GENESIS_HASH;
    const record_hash = computeRecordHash(event, seq, hostTs, prevHash);
    const sealed: SealedRecord = { event, seq, host_ts: hostTs, prev_hash: prevHash, record_hash };
    this.records.push(sealed);
    return sealed;
  }

  all(): readonly SealedRecord[] {
    return this.records;
  }

  // Digest anchored out-of-band (Tier3). Rewriting history without invalidating this is
  // infeasible because the tail commits to the whole chain.
  digest(): string {
    const tail = this.records[this.records.length - 1];
    return tail ? tail.record_hash : GENESIS_HASH;
  }

  // Test/demo affordance: expose the mutable array so a tamper can be injected and caught.
  unsafeMutableRecords(): SealedRecord[] {
    return this.records;
  }
}
