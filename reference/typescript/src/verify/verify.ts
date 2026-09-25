import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import Ajv2020, { type ValidateFunction } from 'ajv/dist/2020.js';
import { checkEventStructure } from '../schema/validate.js';
import { canonicalDomainError } from '../ledger/canonical.js';
import { GENESIS_HASH, computeRecordHash, countersignaturePayload, type SealedRecord } from '../ledger/ledger.js';
import { countersignatureCheck, decodeBase64, decodeBase64url, verifyEventSignature } from '../l2/signing.js';
import { assertDisjointRegistries, type KeyRegistry } from '../l2/keys.js';
import { SPEC_SCHEMA_DIR } from '../paths.js';
import { SPEC_VERSION } from '../schema/event.js';

// Verifier (§11.4): proves non-tampering and completeness over a sealed ledger. Recomputes the hash
// chain, detects seq gaps, checks the anchored digest, correlates attempts with outcomes, and
// accounts for every Level-2 signer_seq. A malformed record is a finding, never an exception: it is
// reported and the chain is checked on either side of it.
//
// Level-2 verification and countersignature determination need the out-of-band registries (§5.1,
// §7.1). §11.4 requires a verifier without one to report that the check did not run, rather than
// return a result in which its anomalies are simply absent: an unchecked signature and a valid one
// are not the same finding.

// Resolves a host_key_id and verifies a countersignature over the canonical host-assigned fields.
export type CountersignatureChecker = (hostKeyId: string, signature: string, payload: string) => boolean;

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
    | 'signature-invalid'
    | 'replay-detected'
    | 'signer-seq-gap'
    | 'host-signature-invalid'
    | 'principal-mismatch';
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

export interface VerifyOptions {
  // The registry binding tool key_ids to keys, for Level-2 signatures (§5.1). A revoked entry still
  // verifies the records sealed under it (§10.9).
  keyRegistry?: KeyRegistry;
  // The registry binding host_key_ids to keys, for countersignatures (§7.1), in place of a
  // CountersignatureChecker. Given with `keyRegistry`, the two must share no key (§10.9).
  hostKeyRegistry?: KeyRegistry;
  // The identity the partition is expected to hold, supplied out-of-band (§10.10 construction 1). A
  // record naming another log_id, countersigned under a host_key_id outside the set, or carrying no
  // countersignature, is `principal-mismatch`.
  expectedIdentity?: ExpectedIdentity;
  // The chain must be countersigned, supplied out-of-band (§11.4): an uncountersigned record is then
  // `host-signature-invalid`, since a countersignature can be stripped though not forged (§10.1).
  countersignatureRequired?: boolean;
}

// A log_id is distinct only among one host's chains, so the identity is the log_id together with
// the keys that host countersigns under (§10.10).
export interface ExpectedIdentity {
  logId: string;
  hostKeyIds: readonly string[];
}

// Records sealed under an earlier published version are read under that version's schema and
// signature encoding (§11.4): before 0.3 an event named its call `call_id` and encoded its signature
// as padded standard base64. The schemas are the published bytes of those versions.
const EARLIER_VERSIONS = ['0.1', '0.1.1', '0.2'] as const;
// Published versions in order; a chain's versions do not go backwards (§11.4).
const VERSION_RANK = new Map<string, number>([...EARLIER_VERSIONS.map((v) => `auditable-mcp/${v}`), SPEC_VERSION].map((v, i) => [v, i]));
const ajv = new Ajv2020({ strict: false, validateFormats: false });
const earlierSchemas = new Map<string, ValidateFunction>(
  EARLIER_VERSIONS.map((v) => [
    `auditable-mcp/${v}`,
    ajv.compile(JSON.parse(readFileSync(resolve(SPEC_SCHEMA_DIR, 'earlier', v, 'audit-event.schema.json'), 'utf8'))),
  ]),
);

type Event = Record<string, unknown>;

function asEvent(value: unknown): Event {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Event) : {};
}

function isEarlier(event: Event): boolean {
  return typeof event.spec_version === 'string' && earlierSchemas.has(event.spec_version);
}

// Why a sealed event fails validation under its own version's schema, or undefined.
function structureError(raw: unknown): string | undefined {
  const event = asEvent(raw);
  const earlier = typeof event.spec_version === 'string' ? earlierSchemas.get(event.spec_version) : undefined;
  if (earlier === undefined) {
    const check = checkEventStructure(raw);
    return check.ok ? undefined : check.detail;
  }
  if (!earlier(raw)) return ajv.errorsText(earlier.errors);
  return canonicalDomainError(raw);
}

// The audit session an event belongs to: `session_id`, or `call_id` for versions before 0.3.
function sessionOf(event: Event): string {
  const session = event.session_id ?? event.call_id;
  return typeof session === 'string' ? session : '';
}

function correlationKey(event: Event): string {
  return `${sessionOf(event)}\u0000${String(event.id)}`;
}

interface Numbered {
  key_id: string;
  session_id: string;
  signer_seq: number;
  event: Event;
  // An attempt with the same session_id and id was sealed before this record (§7.2).
  correlated: boolean;
}

// The current-version records that carry a Level-2 number. Earlier versions numbered per key across
// calls, not per session, so the per-session procedures below do not apply to them.
function numbered(records: readonly SealedRecord[]): Numbered[] {
  const out: Numbered[] = [];
  const attempted = new Set<string>();
  for (const rec of records) {
    const event = asEvent(rec.event);
    const correlated = attempted.has(correlationKey(event));
    if (event.outcome === 'attempted') attempted.add(correlationKey(event));
    const { key_id, signer_seq, session_id } = event;
    if (isEarlier(event) || typeof key_id !== 'string' || typeof session_id !== 'string') continue;
    if (typeof signer_seq !== 'number' || !Number.isSafeInteger(signer_seq) || signer_seq < 0) continue;
    out.push({ key_id, session_id, signer_seq, event, correlated });
  }
  return out;
}

export interface UnaccountedRun {
  key_id: string;
  session_id: string;
  first: number;
  last: number;
}

// Values from 0 to the largest sealed one that are not sealed, as maximal runs. Computed from the gaps
// between sealed values, so a sealed value near 2^53 costs one run, not 2^53 entries.
function missingRuns(present: ReadonlySet<number>): Array<[number, number]> {
  const runs: Array<[number, number]> = [];
  let next = 0;
  for (const value of [...present].sort((a, b) => a - b)) {
    if (value > next) runs.push([next, value - 1]);
    next = value + 1;
  }
  return runs;
}

// The §11.4 procedure: for each key and session, the maximal runs of signer_seq values missing from
// the sealed sequence that no sealed refusal accounts for. Exported so the conformance vector can drive it.
export function unaccountedSignerSeq(records: readonly SealedRecord[]): UnaccountedRun[] {
  const groups = new Map<string, Numbered[]>();
  for (const entry of numbered(records)) {
    const group = `${entry.key_id}\u0000${entry.session_id}`;
    groups.set(group, [...(groups.get(group) ?? []), entry]);
  }
  const unaccounted: UnaccountedRun[] = [];
  for (const group of groups.values()) {
    const { key_id, session_id } = group[0]!;
    const missing = missingRuns(new Set(group.map((r) => r.signer_seq)));
    const refusals = group
      .filter(
        (r) =>
          r.event.outcome === 'aborted' &&
          (r.event.reason === 'host-rejected' || r.event.reason === 'host-unavailable') &&
          !r.correlated,
      )
      .map((r) => r.signer_seq)
      .sort((a, b) => a - b);
    // Each refusal accounts for the smallest value still missing below its own, which is always the
    // first value of the first run.
    for (const refusal of refusals) {
      const run = missing[0];
      if (run === undefined || run[0] >= refusal) continue;
      run[0] += 1;
      if (run[0] > run[1]) missing.shift();
    }
    for (const [first, last] of missing) unaccounted.push({ key_id, session_id, first, last });
  }
  return unaccounted;
}

// Two sealed records sharing a signer_seq within one key and session (§7.4, §11.4): one issue for
// each record after the first.
function sharedSignerSeq(records: readonly SealedRecord[]): Array<{ key_id: string; session_id: string; signer_seq: number }> {
  const seen = new Set<string>();
  const shared: Array<{ key_id: string; session_id: string; signer_seq: number }> = [];
  for (const { key_id, session_id, signer_seq } of numbered(records)) {
    const slot = `${key_id}\u0000${session_id}\u0000${signer_seq}`;
    if (seen.has(slot)) shared.push({ key_id, session_id, signer_seq });
    seen.add(slot);
  }
  return shared;
}

export function verifyLedger(
  records: readonly SealedRecord[],
  anchoredDigest?: string,
  countersignatureChecker?: CountersignatureChecker,
  options: VerifyOptions = {},
): VerifyReport {
  if (options.keyRegistry !== undefined && options.hostKeyRegistry !== undefined) {
    assertDisjointRegistries(options.keyRegistry, options.hostKeyRegistry);
  }
  const checkCountersignature =
    countersignatureChecker ?? (options.hostKeyRegistry === undefined ? undefined : countersignatureCheck(options.hostKeyRegistry, 'verifier'));
  const issues: VerifyIssue[] = [];
  const attempted = new Set<string>();
  let countersignatureUnchecked = false;
  let level2Unchecked = false;
  let latestVersion = -1;

  // Recompute the chain from the record bytes. Chaining on the recomputed hash (not the stored one)
  // propagates any body mutation to the tail digest.
  let prevRecomputed = GENESIS_HASH;

  records.forEach((rec, i) => {
    const seq = typeof rec.seq === 'number' ? rec.seq : null;
    const event = asEvent(rec.event);
    const invalid = structureError(rec.event);
    if (invalid !== undefined) issues.push({ seq, kind: 'schema-invalid', detail: invalid });
    const version = typeof event.spec_version === 'string' ? VERSION_RANK.get(event.spec_version) : undefined;
    if (version !== undefined) {
      if (version < latestVersion) {
        issues.push({ seq, kind: 'schema-invalid', detail: `version-regression: ${String(event.spec_version)} sealed after a later version` });
      }
      latestVersion = Math.max(latestVersion, version);
    }

    // A seq discontinuity => a record was dropped (gap) or reordered (out-of-order).
    if (rec.seq !== i) {
      const sub = seq !== null && seq > i ? 'gap' : 'out-of-order';
      issues.push({ seq, kind: 'seq-gap', detail: `${sub}: expected seq ${i}, got ${String(rec.seq)}` });
    }

    // A record outside the canonicalization domain has no record hash to recompute; it is reported
    // above, and the chain continues from the hash it stores.
    let recomputed: string;
    const hashable = canonicalDomainError(rec) === undefined;
    if (hashable) {
      recomputed = computeRecordHash(rec.event, rec.seq, rec.host_ts, prevRecomputed);
      if (rec.previous_hash !== prevRecomputed) {
        issues.push({ seq, kind: 'record-hash-mismatch', detail: 'prev-hash: previous_hash does not link to previous record' });
      }
      // Recomputing over the committed bytes localizes any mutation of event / seq / host_ts.
      if (rec.record_hash !== recomputed) {
        issues.push({ seq, kind: 'record-hash-mismatch', detail: 'stored record_hash != recomputed' });
      }
    } else {
      recomputed = typeof rec.record_hash === 'string' ? rec.record_hash : prevRecomputed;
    }

    // Level-2 Validation: the signature against the tool-key registry, decoded as the record's own
    // version encoded it.
    if (typeof event.signature === 'string' && typeof event.key_id === 'string') {
      if (options.keyRegistry === undefined) {
        level2Unchecked = true;
      } else {
        const key = options.keyRegistry.get(event.key_id);
        const decode = isEarlier(event) ? decodeBase64 : decodeBase64url;
        if (key === undefined || !verifyEventSignature(event, key, decode)) {
          issues.push({ seq, kind: 'signature-invalid', detail: `signature does not verify against ${event.key_id}` });
        }
      }
    }

    // §11.4 Countersignature Determination: established from the record's own signature, never
    // inferred from any other field. A partial triple is not a conforming record (§7.1).
    const present = [rec.host_signature, rec.host_key_id, rec.log_id].filter((v) => v !== undefined).length;
    if (present === 0 && options.countersignatureRequired === true) {
      issues.push({ seq, kind: 'host-signature-invalid', detail: 'uncountersigned: the chain must be countersigned' });
    } else if (present !== 0 && present !== 3) {
      issues.push({
        seq,
        kind: 'host-signature-invalid',
        detail: 'partial: host_signature, host_key_id, and log_id appear together or not at all',
      });
    } else if (present === 3 && hashable) {
      if (checkCountersignature === undefined) {
        countersignatureUnchecked = true;
      } else {
        const payload = countersignaturePayload(rec.seq, rec.host_ts, rec.log_id as string, rec.previous_hash, rec.record_hash);
        if (!checkCountersignature(rec.host_key_id as string, rec.host_signature as string, payload)) {
          issues.push({ seq, kind: 'host-signature-invalid', detail: `countersignature does not verify against ${rec.host_key_id}` });
        }
      }
    }

    // Identity Matching (§10.10 construction 1): the expectation is an input, never read from the
    // ledger, and a record without the full triple carries no binding. Compared as strings, so it
    // runs for a record that fails every other check (§11.4).
    const expected = options.expectedIdentity;
    if (expected !== undefined) {
      const mismatch =
        present !== 3
          ? 'uncountersigned: no countersignature binds the record'
          : rec.log_id !== expected.logId
            ? `log_id ${String(rec.log_id)}`
            : !expected.hostKeyIds.includes(rec.host_key_id as string)
              ? `host_key_id ${String(rec.host_key_id)}`
              : undefined;
      if (mismatch !== undefined) {
        issues.push({
          seq,
          kind: 'principal-mismatch',
          detail: `${mismatch}; expected ${expected.logId} under ${expected.hostKeyIds.join(', ')}`,
        });
      }
    }

    // Correlation by (session_id, id) with an attempt sealed before the outcome (§7.2): a success or
    // failed outcome with none is an inconsistency; an aborted one with none is a sealed refusal.
    if (event.outcome === 'attempted') {
      attempted.add(correlationKey(event));
    } else if ((event.outcome === 'success' || event.outcome === 'failed') && !attempted.has(correlationKey(event))) {
      issues.push({ seq, kind: 'orphaned-outcome', detail: `never-accepted: outcome=${event.outcome} id=${String(event.id)}` });
    }

    prevRecomputed = recomputed;
  });

  for (const dup of sharedSignerSeq(records)) {
    issues.push({
      seq: null,
      kind: 'replay-detected',
      detail: `${dup.key_id} in session ${dup.session_id}: signer_seq ${dup.signer_seq} is sealed twice`,
    });
  }
  for (const gap of unaccountedSignerSeq(records)) {
    issues.push({
      seq: null,
      kind: 'signer-seq-gap',
      detail: `${gap.key_id} in session ${gap.session_id}: signer_seq ${gap.first}..${gap.last} is missing`,
    });
  }

  const computedDigest = prevRecomputed;
  if (anchoredDigest !== undefined && anchoredDigest !== computedDigest) {
    issues.push({ seq: null, kind: 'digest-mismatch', detail: `anchored ${anchoredDigest} != computed ${computedDigest}` });
  }

  const unchecked = [...(countersignatureUnchecked ? ['countersignature'] : []), ...(level2Unchecked ? ['level-2-signature'] : [])];
  return {
    ok: issues.length === 0,
    count: records.length,
    computedDigest,
    issues,
    unchecked,
    complete: issues.length === 0 && unchecked.length === 0,
  };
}

