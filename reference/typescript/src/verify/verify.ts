import { auditEventSchema } from '../schema/event.js';
import { GENESIS_HASH, computeRecordHash, type SealedRecord } from '../ledger/ledger.js';

// Verifier: proves non-tampering and completeness over a sealed ledger. Recomputes the hash
// chain, detects sequence gaps, checks the anchored digest, and correlates attempts with outcomes.

export interface VerifyIssue {
  seq: number | null;
  kind:
    | 'schema-invalid'
    | 'seq-out-of-order'
    | 'seq-gap'
    | 'prev-hash-mismatch'
    | 'record-hash-mismatch'
    | 'digest-mismatch'
    | 'outcome-without-attempt';
  detail: string;
}

export interface VerifyReport {
  ok: boolean;
  count: number;
  computedDigest: string;
  issues: VerifyIssue[];
}

export function verifyLedger(records: readonly SealedRecord[], anchoredDigest?: string): VerifyReport {
  const issues: VerifyIssue[] = [];
  const attemptedIds = new Set<string>();

  // Recompute the chain from the record bytes. Chaining on the recomputed hash (not the
  // stored one) propagates any body mutation to the tail digest.
  let prevRecomputed = GENESIS_HASH;

  records.forEach((rec, i) => {
    // 1. Each record's event must still be schema-valid.
    const parsed = auditEventSchema.safeParse(rec.event);
    if (!parsed.success) {
      issues.push({ seq: rec.seq, kind: 'schema-invalid', detail: parsed.error.message });
    }

    // 2. Sequence must be contiguous from 0 (a gap ⇒ a record was dropped).
    if (rec.seq !== i) {
      issues.push({ seq: rec.seq, kind: rec.seq > i ? 'seq-gap' : 'seq-out-of-order', detail: `expected seq ${i}, got ${rec.seq}` });
    }

    const recomputed = computeRecordHash(rec.event, rec.seq, rec.host_ts, prevRecomputed);

    // 3. Stored prev_hash must link to the recomputed previous hash.
    if (rec.prev_hash !== prevRecomputed) {
      issues.push({ seq: rec.seq, kind: 'prev-hash-mismatch', detail: 'prev_hash does not link to previous record' });
    }

    // 4. Stored record_hash must equal the recomputation over the committed bytes (localizes
    //    any mutation of event / seq / host_ts).
    if (rec.record_hash !== recomputed) {
      issues.push({ seq: rec.seq, kind: 'record-hash-mismatch', detail: 'stored record_hash != recomputed' });
    }

    // 5. An outcome with no preceding attempt is an inconsistency.
    if (rec.event.outcome === 'attempted') {
      attemptedIds.add(rec.event.id);
    } else if (!attemptedIds.has(rec.event.id)) {
      issues.push({ seq: rec.seq, kind: 'outcome-without-attempt', detail: `outcome=${rec.event.outcome} id=${rec.event.id}` });
    }

    prevRecomputed = recomputed;
  });

  const computedDigest = prevRecomputed;
  if (anchoredDigest !== undefined && anchoredDigest !== computedDigest) {
    issues.push({ seq: null, kind: 'digest-mismatch', detail: `anchored ${anchoredDigest} != computed ${computedDigest}` });
  }

  return { ok: issues.length === 0, count: records.length, computedDigest, issues };
}
