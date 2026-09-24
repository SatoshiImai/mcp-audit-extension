import { auditEventSchema } from '../schema/event.js';
import { GENESIS_HASH, computeRecordHash, type SealedRecord, witnessPayload } from '../ledger/ledger.js';

// Verifier (§11.4): proves non-tampering and completeness over a sealed ledger. Recomputes the hash
// chain, detects seq gaps, checks the anchored digest, and correlates attempts with outcomes.
//
// Witness determination (§5.2) needs the out-of-band registry that binds host_key_id to a host's
// key. §11.4 requires a verifier without it to report that the check did not run, rather than
// return a result in which its anomalies are simply absent: an unchecked signature and a valid one
// are not the same finding.

// §11.4's Identity Matching is conditional - "where the deployment binds identity (§10.10)" - and
// this demonstration seals a bare a-MCP event for one principal, so nothing binds one. §10.10 says
// a single-principal deployment needs neither construction; a deployment that stores records for
// more than one principal in a shared medium wraps them (SEP-3004) or binds the identity inside the
// sealed record, and its verifier compares that against an expectation supplied out-of-band.

// Resolves a host_key_id and verifies a witness signature over the canonical host-assigned fields.
export type WitnessChecker = (hostKeyId: string, signature: string, payload: string) => boolean;

// Tier-1 anomaly kinds only (§7.6); finer classification (out-of-order vs gap, prev-hash vs
// body-hash, never-accepted) is carried as Tier-2 text in `detail`.
export interface VerifyIssue {
  seq: number | null;
  kind:
    | 'schema-invalid'
    | 'seq-gap'
    | 'record-hash-mismatch'
    | 'digest-mismatch'
    | 'orphaned-outcome'
    | 'host-signature-invalid';
  detail: string;
}

export interface VerifyReport {
  ok: boolean; // the checks that ran found nothing - not the same as having checked everything
  count: number;
  computedDigest: string;
  issues: VerifyIssue[];
  unchecked: string[]; // every check that was applicable and did not run (§11.4)
  complete: boolean; // nothing found and nothing applicable skipped
}

export function verifyLedger(
  records: readonly SealedRecord[],
  anchoredDigest?: string,
  witnessChecker?: WitnessChecker,
): VerifyReport {
  const issues: VerifyIssue[] = [];
  const attemptedIds = new Set<string>();
  let witnessUnchecked = false;

  // Recompute the chain from the record bytes. Chaining on the recomputed hash (not the
  // stored one) propagates any body mutation to the tail digest.
  let prevRecomputed = GENESIS_HASH;

  records.forEach((rec, i) => {
    const parsed = auditEventSchema.safeParse(rec.event);
    if (!parsed.success) {
      issues.push({ seq: rec.seq, kind: 'schema-invalid', detail: parsed.error.message });
    }

    // A seq discontinuity => a record was dropped (gap) or reordered (out-of-order).
    if (rec.seq !== i) {
      const sub = rec.seq > i ? 'gap' : 'out-of-order';
      issues.push({ seq: rec.seq, kind: 'seq-gap', detail: `${sub}: expected seq ${i}, got ${rec.seq}` });
    }

    const recomputed = computeRecordHash(rec.event, rec.seq, rec.host_ts, prevRecomputed);

    if (rec.previous_hash !== prevRecomputed) {
      issues.push({ seq: rec.seq, kind: 'record-hash-mismatch', detail: 'prev-hash: previous_hash does not link to previous record' });
    }

    // Recomputing over the committed bytes localizes any mutation of event / seq / host_ts.
    if (rec.record_hash !== recomputed) {
      issues.push({ seq: rec.seq, kind: 'record-hash-mismatch', detail: 'stored record_hash != recomputed' });
    }

    // §11.4 Witness Determination: established from the record's own signature, never inferred from
    // any other field. A half-present pair is not a conforming record (§7.1).
    const hasSignature = rec.host_signature !== undefined;
    const hasKeyId = rec.host_key_id !== undefined;
    if (hasSignature !== hasKeyId) {
      issues.push({
        seq: rec.seq,
        kind: 'host-signature-invalid',
        detail: 'half-pair: host_signature and host_key_id appear together or not at all',
      });
    } else if (hasSignature && rec.host_signature !== undefined && rec.host_key_id !== undefined) {
      if (witnessChecker === undefined) {
        witnessUnchecked = true;
      } else {
        const payload = witnessPayload(rec.seq, rec.host_ts, rec.previous_hash, rec.record_hash);
        if (!witnessChecker(rec.host_key_id, rec.host_signature, payload)) {
          issues.push({
            seq: rec.seq,
            kind: 'host-signature-invalid',
            detail: `witness signature does not verify against ${rec.host_key_id}`,
          });
        }
      }
    }

    // An outcome with no preceding attempt is an inconsistency.
    if (rec.event.outcome === 'attempted') {
      attemptedIds.add(rec.event.id);
    } else if (!attemptedIds.has(rec.event.id)) {
      issues.push({ seq: rec.seq, kind: 'orphaned-outcome', detail: `never-accepted: outcome=${rec.event.outcome} id=${rec.event.id}` });
    }

    prevRecomputed = recomputed;
  });

  const computedDigest = prevRecomputed;
  if (anchoredDigest !== undefined && anchoredDigest !== computedDigest) {
    issues.push({ seq: null, kind: 'digest-mismatch', detail: `anchored ${anchoredDigest} != computed ${computedDigest}` });
  }

  const unchecked = witnessUnchecked ? ['witness'] : [];
  return {
    ok: issues.length === 0,
    count: records.length,
    computedDigest,
    issues,
    unchecked,
    complete: issues.length === 0 && unchecked.length === 0,
  };
}
