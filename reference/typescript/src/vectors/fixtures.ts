import type { AuditEvent } from '../schema/event.js';

// Conformance fixtures - the fixed inputs a golden vector file is derived from. Any
// independent Auditable MCP implementation must reproduce the same canonical bytes and hashes from
// these inputs. Kept JSON-representable (no undefined, no floats) so they round-trip through
// the committed golden files and cross-language ports.

export interface CanonicalizationCase {
  name: string;
  value: unknown;
}

// Stress the canonicalization algorithm itself (key ordering, nesting, unicode, numbers).
export const CANONICALIZATION_CASES: CanonicalizationCase[] = [
  { name: 'key-order', value: { b: 1, a: 2, c: 3 } },
  { name: 'nested-object-and-array', value: { z: { y: 2, x: 1 }, a: [3, 2, 1], m: { n: [{ q: 1, p: 2 }] } } },
  // 2/3/4-byte UTF-8, incl. a surrogate-pair emoji: verifies canonical output emits raw UTF-8, not \u escapes.
  { name: 'unicode', value: { note: 'café — Ünïcödé — 🔒 lock' } },
  { name: 'scalars', value: { i: 0, big: 1234567890, neg: -5, t: true, f: false, z: null, s: 'x' } },
  // Boundary of the JSON-safe integer domain (§8.1); values beyond this are rejected, not canonicalized.
  { name: 'max-safe-int', value: { n: 9007199254740991 } },
  // Non-integer floats + exponents: pins ECMAScript Number-to-String agreement across ports.
  { name: 'floats', value: { a: 0.1, b: 1.5, c: -2.25, d: 1e-7 } },
  // Non-ASCII and astral keys: pins UTF-16 code-unit key ordering across ports.
  { name: 'non-ascii-keys', value: { é: 1, Ä: 2, a: 3, '🔒': 4 } },
  // Control characters: pins the mandatory JSON escapes and lowercase \u00xx form.
  { name: 'control-chars', value: { s: '\b\t\n\f\r' } },
  { name: 'empty', value: {} },
];

function pid(n: number): string {
  return `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
}

// Audit sessions the host issued (§6.3). Fixed, so the vectors are reproducible.
export const SESSION_ABC = '0198f3a2-5c1e-7000-8000-00000000abc0';
export const SESSION_XYZ = '0198f3a2-5c1e-7000-8000-00000000abc1';
export const SESSION_L2 = '0198f3a2-5c1e-7000-8000-00000000abc2';

// The seeds of the keys the signed vectors are made with. Ed25519 signing is deterministic, so a
// port that holds these seeds reproduces every signature byte-for-byte, and one that holds only
// the public keys the vectors publish verifies them. They are test data and nothing else.
export const TOOL_KEY_ID = 'tool-key-2026';
export const TOOL_KEY_SEED_HEX = '01'.repeat(32);
export const HOST_KEY_ID = 'host-key-2026';
export const HOST_KEY_SEED_HEX = '02'.repeat(32);

// A Level-2 attempt and its correlated outcome, before signing. The generator signs them with the
// tool key above, in signer_seq order from 0 as §7.4 numbers them, so the vector pins both that
// record_hash covers the FULL event including `signature` (§8.2) and a verifiable signature.
export const SIGNED_CHAIN_EVENTS: AuditEvent[] = [
  {
    id: pid(10),
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:10.000Z',
    session_id: SESSION_L2,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'ledger_entries' },
    outcome: 'attempted',
    action_context_hash: `sha256:${'a'.repeat(64)}`,
  },
  {
    id: pid(10),
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:11.000Z',
    session_id: SESSION_L2,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'ledger_entries' },
    outcome: 'success',
    action_context_hash: `sha256:${'a'.repeat(64)}`,
  },
];

const ZERO_HASH = `sha256:${'0'.repeat(64)}`;

// Valid AuditEvents covering: minimal (both context fields absent), a db.query carrying both
// cleartext action_context and a sealed action_context_hash, and a Level-2 event committing
// action_context_hash with signature/signer_seq/unicode - the shared-schema shape and the two
// confidentiality choices (§4.3) in one file.
export const EVENT_CASES: Array<{ name: string; event: AuditEvent }> = [
  {
    name: 'db-read-minimal',
    event: {
      id: pid(1),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:01.000Z',
      session_id: SESSION_ABC,
      action_type: 'db.read',
      mutates: false,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'attempted',
    },
  },
  {
    name: 'db-query-with-trace-and-context',
    event: {
      id: pid(2),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:02.000Z',
      session_id: SESSION_ABC,
      traceparent: '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01',
      action_type: 'db.query',
      mutates: false,
      egress: true,
      target_resource: { kind: 'database', ref: 'analytics-postgres' },
      outcome: 'success',
      action_context: { dialect: 'postgres', tables_accessed: ['users', 'payments'] },
      action_context_hash: `sha256:${'a'.repeat(64)}`,
    },
  },
  {
    name: 'ext-l2-signed-unicode',
    event: {
      id: pid(3),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:03.000Z',
      session_id: SESSION_XYZ,
      action_type: 'ext.stripe.refund_charge',
      mutates: true,
      egress: true,
      target_resource: { kind: 'endpoint', ref: 'https://api.stripe.com/v1/refunds', scope_hint: 'clïent:c_1' },
      outcome: 'attempted',
      action_context_hash: `sha256:${'a'.repeat(64)}`,
      signer_seq: 42,
      key_id: 'tool-key-2026',
      signature: 'ZmFrZS1zaWduYXR1cmU',
    },
  },
  {
    name: 'secret-read',
    event: {
      id: pid(4),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:04.000Z',
      session_id: SESSION_ABC,
      action_type: 'secret.read',
      mutates: false,
      egress: false,
      target_resource: { kind: 'secret', ref: 'db/password' },
      outcome: 'success',
      action_context_hash: ZERO_HASH,
    },
  },
  {
    // Pins the byte form of an aborted outcome carrying a Tier-1 abort code in `reason` (§7.2).
    name: 'aborted-outcome-host-rejected',
    event: {
      id: pid(5),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:05.000Z',
      session_id: SESSION_ABC,
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'aborted',
      reason: 'host-rejected',
    },
  },
  {
    // The countersignature axis adds two abort codes: a record no distinct party confirmed (§5.2, §7.2)...
    name: 'aborted-outcome-host-uncountersigned',
    event: {
      id: pid(6),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:06.000Z',
      session_id: SESSION_ABC,
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'aborted',
      reason: 'host-uncountersigned',
    },
  },
  {
    // ...and one whose countersignature was present and did not verify (§7.2, §11.4).
    name: 'aborted-outcome-host-signature-invalid',
    event: {
      id: pid(7),
      spec_version: 'auditable-mcp/0.3',
      ts: '2026-07-15T00:00:07.000Z',
      session_id: SESSION_ABC,
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 'customers' },
      outcome: 'aborted',
      reason: 'host-signature-invalid',
    },
  },
];

// Negative conformance cases: an event a Level-1 host MUST refuse. An `attempt`-channel case is
// submitted to handleAttempt and MUST be rejected with the given Tier-1 reason; an `outcome`-channel
// case is submitted to handleOutcome and MUST be flagged with the given anomaly kind and not sealed.
// Pins cross-port agreement on the reject/anomaly vocabulary, including cases a pure JSON Schema
// cannot express (the numeric-domain boundary, §8.1) or that live only on the outcome channel.
export type ErrorCase =
  | { name: string; channel: 'attempt'; event: Record<string, unknown>; expect: { status: 'reject'; reason: string } }
  | { name: string; channel: 'outcome'; event: Record<string, unknown>; expect: { sealed: false; anomaly_kind: string } };

function attemptBase(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    id: pid(6),
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:06.000Z',
    session_id: SESSION_ABC,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
    action_context_hash: ZERO_HASH,
    ...overrides,
  };
}

export const ERROR_CASES: ErrorCase[] = [
  {
    name: 'numeric-domain-overflow',
    channel: 'attempt',
    event: attemptBase({ action_context: { rows: 9007199254740992 } }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    name: 'non-attempted-outcome-on-attempt',
    channel: 'attempt',
    event: attemptBase({ outcome: 'success' }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    name: 'malformed-action-context-hash',
    channel: 'attempt',
    event: attemptBase({ action_context_hash: 'not-a-sha256-hash' }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    // A UUID is written in lowercase and compared as a string (§4).
    name: 'uppercase-uuid-id',
    channel: 'attempt',
    event: attemptBase({ id: '00000000-0000-4000-8000-00000000000A' }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    // A session_id is never the nil UUID (§4, §6.3).
    name: 'nil-session-id',
    channel: 'attempt',
    event: attemptBase({ session_id: '00000000-0000-0000-0000-000000000000' }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    // The Level-2 fields appear together or not at all (§4), whatever level the host requires.
    name: 'partial-level-2-fields',
    channel: 'attempt',
    event: attemptBase({ key_id: TOOL_KEY_ID, signer_seq: 0 }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    // A lone surrogate is not a Unicode scalar value, so JCS cannot serialize it (§8.1).
    name: 'lone-surrogate-string',
    channel: 'attempt',
    event: attemptBase({ action_context: { note: 'a\ud800b' } }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    // A pattern anchors the whole string: `$` does not match before a trailing newline (§4).
    name: 'trailing-newline-id',
    channel: 'attempt',
    event: attemptBase({ id: `${pid(6)}\n` }),
    expect: { status: 'reject', reason: 'schema-invalid' },
  },
  {
    // The aborted-reason presence MUST (§7.2): an aborted outcome with no Tier-1 abort code is
    // structurally invalid (schema if/then) and MUST NOT be sealed.
    name: 'aborted-missing-reason',
    channel: 'outcome',
    event: attemptBase({ outcome: 'aborted', action_context_hash: undefined }),
    expect: { sealed: false, anomaly_kind: 'schema-invalid' },
  },
  {
    // An outcome whose session is not the call's is dropped and recorded (§6, §6.3).
    name: 'outcome-for-another-session',
    channel: 'outcome',
    event: attemptBase({ outcome: 'success', session_id: SESSION_XYZ }),
    expect: { sealed: false, anomaly_kind: 'replay-detected' },
  },
];

// The Level-2 host's replay window (§7.4) driven step by step against one host requiring Level 2,
// with the tool key registered. Each step names whether the host is available, the signed event, and
// what the host answers (attempts) or whether it seals (outcomes), with the anomaly kinds that step
// records. The events are signed by the generator.
export interface ReplayStep {
  name: string;
  channel: 'attempt' | 'outcome';
  host_available: boolean;
  signer_seq: number;
  event: AuditEvent;
  expect: { status?: 'accept' | 'reject' | 'unavailable'; reason?: string; seq?: number; sealed?: boolean; anomalies: string[] };
}

function l2(n: number, outcome: AuditEvent['outcome'], ts: string): AuditEvent {
  return {
    id: pid(n),
    spec_version: 'auditable-mcp/0.3',
    ts,
    session_id: SESSION_L2,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'ledger_entries' },
    outcome,
  };
}

const A = l2(20, 'attempted', '2026-07-15T00:00:20.000Z');
const B = l2(21, 'attempted', '2026-07-15T00:00:21.000Z');
const C = l2(23, 'attempted', '2026-07-15T00:00:23.000Z');

export const REPLAY_STEPS: ReplayStep[] = [
  { name: 'attempt A at 0 while unavailable decides nothing', channel: 'attempt', host_available: false, signer_seq: 0, event: A, expect: { status: 'unavailable', reason: 'internal-error', anomalies: [] } },
  { name: 'attempt B at 1 is accepted', channel: 'attempt', host_available: true, signer_seq: 1, event: B, expect: { status: 'accept', seq: 0, anomalies: [] } },
  { name: 'A sent again byte-identical at 0, below a decided value, is accepted', channel: 'attempt', host_available: true, signer_seq: 0, event: A, expect: { status: 'accept', seq: 1, anomalies: [] } },
  { name: 'B sent again byte-identical is answered from the ledger', channel: 'attempt', host_available: true, signer_seq: 1, event: B, expect: { status: 'accept', seq: 0, anomalies: [] } },
  { name: 'another attempt at the decided value 1 is a replay', channel: 'attempt', host_available: true, signer_seq: 1, event: l2(22, 'attempted', '2026-07-15T00:00:22.000Z'), expect: { status: 'reject', reason: 'replay-detected', anomalies: ['replay-detected'] } },
  { name: 'the success of B at 2 is sealed', channel: 'outcome', host_available: true, signer_seq: 2, event: { ...B, outcome: 'success' }, expect: { sealed: true, anomalies: [] } },
  { name: 'a different outcome for B is not sealed', channel: 'outcome', host_available: true, signer_seq: 3, event: { ...B, outcome: 'failed' }, expect: { sealed: false, anomalies: ['replay-detected'] } },
  { name: 'the success of B sent again byte-identical is ignored', channel: 'outcome', host_available: true, signer_seq: 2, event: { ...B, outcome: 'success' }, expect: { sealed: false, anomalies: [] } },
  { name: 'the success of A at 4 is sealed', channel: 'outcome', host_available: true, signer_seq: 4, event: { ...A, outcome: 'success' }, expect: { sealed: true, anomalies: [] } },
  { name: 'attempt C at 5 while unavailable decides nothing', channel: 'attempt', host_available: false, signer_seq: 5, event: C, expect: { status: 'unavailable', reason: 'internal-error', anomalies: [] } },
  { name: 'the refusal of C at 6 is sealed', channel: 'outcome', host_available: true, signer_seq: 6, event: { ...C, outcome: 'aborted', reason: 'host-unavailable' }, expect: { sealed: true, anomalies: [] } },
  { name: 'C sent again byte-identical after its sealed outcome is a replay', channel: 'attempt', host_available: true, signer_seq: 5, event: C, expect: { status: 'reject', reason: 'replay-detected', anomalies: ['replay-detected'] } },
];

// §11.4's accounting for signer_seq in a sealed chain. Each case lists the sealed records' events -
// only the fields the procedure reads - and the maximal runs of values it MUST report as
// `signer-seq-gap`, so two verifiers report the same values for one ledger.
export interface AccountingRecord {
  id: string;
  outcome: 'attempted' | 'success' | 'failed' | 'aborted';
  reason?: string;
  key_id: string;
  session_id: string;
  signer_seq: number;
}

export interface AccountingCase {
  name: string;
  records: AccountingRecord[];
  unaccounted: Array<{ key_id: string; session_id: string; first: number; last: number }>;
}

function acc(n: number, outcome: AccountingRecord['outcome'], signer_seq: number, extra: Partial<AccountingRecord> = {}): AccountingRecord {
  return { id: pid(n), outcome, key_id: TOOL_KEY_ID, session_id: SESSION_ABC, signer_seq, ...extra };
}

export const ACCOUNTING_CASES: AccountingCase[] = [
  {
    name: 'contiguous',
    records: [acc(1, 'attempted', 0), acc(1, 'success', 1), acc(2, 'attempted', 2), acc(2, 'failed', 3)],
    unaccounted: [],
  },
  {
    // The rejected attempt at 2 is not sealed; its refusal at 3 accounts for it.
    name: 'rejected-attempt-accounted-by-its-refusal',
    records: [acc(1, 'attempted', 0), acc(1, 'success', 1), acc(2, 'aborted', 3, { reason: 'host-rejected' }), acc(3, 'attempted', 4)],
    unaccounted: [],
  },
  {
    name: 'missing-value-without-a-refusal',
    records: [acc(1, 'attempted', 0), acc(2, 'attempted', 2)],
    unaccounted: [{ key_id: TOOL_KEY_ID, session_id: SESSION_ABC, first: 1, last: 1 }],
  },
  {
    // A session starts at 0 (§7.4): a first value of 2 leaves 0 and 1 missing, and one refusal
    // accounts for the smallest of them only.
    name: 'first-value-not-zero',
    records: [acc(1, 'aborted', 2, { reason: 'host-unavailable' })],
    unaccounted: [{ key_id: TOOL_KEY_ID, session_id: SESSION_ABC, first: 1, last: 1 }],
  },
  {
    name: 'two-sessions-each-from-zero',
    records: [acc(1, 'attempted', 0), acc(2, 'attempted', 0, { session_id: SESSION_XYZ }), acc(1, 'success', 1), acc(2, 'success', 1, { session_id: SESSION_XYZ })],
    unaccounted: [],
  },
  {
    // An abort after an accept (Polluted Stop) has its attempt sealed, so it accounts for nothing.
    name: 'abort-after-accept-accounts-for-nothing',
    records: [acc(1, 'attempted', 0), acc(1, 'aborted', 2, { reason: 'hash-mismatch' })],
    unaccounted: [{ key_id: TOOL_KEY_ID, session_id: SESSION_ABC, first: 1, last: 1 }],
  },
  {
    // A refusal correlates only with an attempt of its own session (§7.2): the sealed attempt with the
    // same id in another session does not stop it accounting for the missing 0.
    name: 'refusal-correlates-within-its-own-session',
    records: [acc(1, 'attempted', 0), acc(1, 'aborted', 1, { reason: 'host-rejected', session_id: SESSION_XYZ })],
    unaccounted: [],
  },
  {
    // Concurrent operations of one call: attempt 1 is rejected and its refusal comes after another
    // operation's attempt.
    name: 'refusal-after-an-interleaved-attempt',
    records: [acc(1, 'attempted', 0), acc(3, 'attempted', 2), acc(2, 'aborted', 3, { reason: 'host-rejected' }), acc(1, 'success', 4), acc(3, 'success', 5)],
    unaccounted: [],
  },
  {
    // Consecutive missing values are one run; a refusal accounts for the first value of it only.
    name: 'a-run-of-missing-values',
    records: [acc(1, 'attempted', 0), acc(2, 'aborted', 5, { reason: 'host-rejected' })],
    unaccounted: [{ key_id: TOOL_KEY_ID, session_id: SESSION_ABC, first: 2, last: 4 }],
  },
  {
    // A refusal correlates only with an attempt sealed before it (§7.2): the attempt with its id
    // sealed after it does not stop it accounting for the missing 1.
    name: 'refusal-sealed-before-an-attempt-with-its-id',
    records: [acc(2, 'attempted', 0), acc(1, 'aborted', 2, { reason: 'host-rejected' }), acc(1, 'attempted', 3)],
    unaccounted: [],
  },
  {
    // A sealed value at the top of the §8.1 domain leaves one run, which a verifier reports without
    // enumerating it.
    name: 'a-value-at-the-top-of-the-domain',
    records: [acc(1, 'attempted', 0), acc(2, 'attempted', 9007199254740991)],
    unaccounted: [{ key_id: TOOL_KEY_ID, session_id: SESSION_ABC, first: 1, last: 9007199254740990 }],
  },
];

// Verifier findings over small countersigned ledgers (§11.4), with the out-of-band inputs a verifier
// is given. `countersign` names, per record, the host key that countersigns it or `none`; the
// generator seals and countersigns the records. `expect_kinds` is the sorted list of issue kinds.
export const OTHER_HOST_KEY_ID = 'other-host-key-2026';
export const OTHER_HOST_KEY_SEED_HEX = '03'.repeat(32);
export const VERIFIER_LOG_ID = 'acme#2026-07-15';

export interface VerifierOptions {
  countersignature_required?: boolean;
  expected_identity?: { log_id: string; host_key_ids: string[] };
}

export interface VerifierCase {
  name: string;
  events: Array<Record<string, unknown>>;
  countersign: Array<'host' | 'other-host' | 'none'>;
  options: VerifierOptions;
  expect_kinds: string[];
}

function l1(n: number, outcome: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: pid(n),
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:30.000Z',
    session_id: SESSION_ABC,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome,
    ...extra,
  };
}

const IDENTITY = { log_id: VERIFIER_LOG_ID, host_key_ids: [HOST_KEY_ID] };

export const VERIFIER_CASES: VerifierCase[] = [
  {
    name: 'countersigned-under-the-expected-identity',
    events: [l1(30, 'attempted'), l1(30, 'success')],
    countersign: ['host', 'host'],
    options: { countersignature_required: true, expected_identity: IDENTITY },
    expect_kinds: [],
  },
  {
    // A countersignature can be stripped though not forged (§10.1).
    name: 'stripped-countersignature-where-one-is-required',
    events: [l1(30, 'attempted'), l1(30, 'success')],
    countersign: ['host', 'none'],
    options: { countersignature_required: true },
    expect_kinds: ['host-signature-invalid'],
  },
  {
    name: 'uncountersigned-record-where-none-is-required',
    events: [l1(30, 'attempted'), l1(30, 'success')],
    countersign: ['host', 'none'],
    options: {},
    expect_kinds: [],
  },
  {
    // A log_id is distinct only among one host's chains; the key tells two hosts apart (§10.10).
    name: 'another-host-under-the-same-log-id',
    events: [l1(30, 'attempted'), l1(30, 'success')],
    countersign: ['other-host', 'other-host'],
    options: { expected_identity: IDENTITY },
    expect_kinds: ['principal-mismatch', 'principal-mismatch'],
  },
  {
    name: 'uncountersigned-where-identity-is-bound',
    events: [l1(30, 'attempted'), l1(30, 'success')],
    countersign: ['none', 'none'],
    options: { expected_identity: IDENTITY },
    expect_kinds: ['principal-mismatch', 'principal-mismatch'],
  },
  {
    // An outcome correlates only with an attempt sealed before it (§7.2).
    name: 'outcome-sealed-before-its-attempt',
    events: [l1(31, 'success'), l1(31, 'attempted')],
    countersign: ['host', 'host'],
    options: {},
    expect_kinds: ['orphaned-outcome'],
  },
  {
    // A chain's versions do not go backwards (§11.4).
    name: 'earlier-version-sealed-after-a-later-one',
    events: [
      l1(32, 'attempted'),
      {
        id: pid(33),
        spec_version: 'auditable-mcp/0.2',
        ts: '2026-07-15T00:00:30.000Z',
        call_id: '7',
        action_type: 'db.write',
        mutates: true,
        egress: false,
        target_resource: { kind: 'table', ref: 'customers' },
        outcome: 'attempted',
      },
    ],
    countersign: ['host', 'host'],
    options: {},
    expect_kinds: ['schema-invalid'],
  },
  {
    // Identity is compared as strings, so it is checked for a record that cannot be canonicalized
    // (§11.4). The record has no computable hash; its stored one is the zero hash.
    name: 'identity-of-a-record-that-cannot-be-canonicalized',
    events: [l1(34, 'attempted', { action_context: { note: 'a\ud800b' } })],
    countersign: ['other-host'],
    options: { expected_identity: IDENTITY },
    expect_kinds: ['principal-mismatch', 'schema-invalid'],
  },
];
