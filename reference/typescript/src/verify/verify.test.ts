import { describe, it, expect } from 'vitest';
import { runCleanScenario } from '../demo/scenario.js';
import { sign } from 'node:crypto';
import { verifyLedger, type VerifyReport } from './verify.js';
import type { AuditEvent } from '../schema/event.js';
import { canonicalize } from '../ledger/canonical.js';
import { computeRecordHash, GENESIS_HASH, type SealedRecord } from '../ledger/ledger.js';
import { generateToolKey, KeyRegistry } from '../l2/keys.js';
import { signEvent } from '../l2/signing.js';

describe('verifyLedger - proof of non-tampering + completeness', () => {
  it('a clean ledger VERIFIES (zero issues) and matches the anchored digest', async () => {
    const host = await runCleanScenario();
    const anchored = host.ledger.digest();
    const report = verifyLedger(host.records(), anchored);
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
    expect(report.computedDigest).toBe(anchored);
  });

  it('detects tampering of a sealed field via record-hash mismatch', async () => {
    const host = await runCleanScenario();
    const anchored = host.ledger.digest();
    const rec = host.ledger.unsafeMutableRecords()[1];
    if (!rec) throw new Error('fixture missing record');
    rec.event.target_resource.ref = 'https://evil.example/exfil'; // forge the target
    const report = verifyLedger(host.records(), anchored);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === 'record-hash-mismatch')).toBe(true);
    expect(report.issues.some((i) => i.kind === 'digest-mismatch')).toBe(true);
  });

  it('detects a dropped record via a sequence gap (completeness)', async () => {
    const host = await runCleanScenario();
    host.ledger.unsafeMutableRecords().splice(2, 1);
    const report = verifyLedger(host.records());
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === 'seq-gap' || i.kind === 'record-hash-mismatch')).toBe(true);
  });

  it('detects a swapped anchor digest (anchor consistency)', async () => {
    const host = await runCleanScenario();
    const report = verifyLedger(host.records(), 'deadbeef');
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === 'digest-mismatch')).toBe(true);
  });
});

const SESSION_A = '0198f3a2-5c1e-7000-8000-00000000abc0';
const SESSION_B = '0198f3a2-5c1e-7000-8000-00000000abc1';

function ev(n: number, outcome: AuditEvent['outcome'], extra: Record<string, unknown> = {}): AuditEvent {
  return {
    id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:01.000Z',
    session_id: SESSION_A,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome,
    ...extra,
  } as AuditEvent;
}

// Seal events into a chain without the host's validation, as a ledger another implementation wrote.
function chain(events: unknown[]): SealedRecord[] {
  let prev = GENESIS_HASH;
  return events.map((event, seq) => {
    const host_ts = `2026-07-15T00:00:${String(10 + seq).padStart(2, '0')}.000Z`;
    const record_hash = computeRecordHash(event as AuditEvent, seq, host_ts, prev);
    const rec = { event: event as AuditEvent, seq, host_ts, previous_hash: prev, record_hash };
    prev = record_hash;
    return rec;
  });
}

function kinds(report: { issues: Array<{ kind: string }> }): string[] {
  return report.issues.map((i) => i.kind);
}

describe('verifyLedger - record validation (§11.4)', () => {
  it('reports a record outside the canonicalization domain and checks the chain on either side of it', () => {
    const bad = ev(2, 'attempted', { action_context: { rows: 1e300 } });
    const first = chain([ev(1, 'attempted')])[0]!;
    const middle = { event: bad, seq: 1, host_ts: '2026-07-15T00:00:11.000Z', previous_hash: first.record_hash, record_hash: 'f'.repeat(64) };
    const last = ev(3, 'attempted');
    const lastHash = computeRecordHash(last, 2, '2026-07-15T00:00:12.000Z', middle.record_hash);
    const records = [first, middle, { event: last, seq: 2, host_ts: '2026-07-15T00:00:12.000Z', previous_hash: middle.record_hash, record_hash: lastHash }];
    let report: VerifyReport | undefined;
    expect(() => {
      report = verifyLedger(records);
    }).not.toThrow();
    expect(kinds(report!)).toEqual(['schema-invalid']);
    expect(report!.computedDigest).toBe(lastHash);
  });

  it('reports an aborted record without a reason as schema-invalid', () => {
    expect(kinds(verifyLedger(chain([ev(1, 'aborted')])))).toEqual(['schema-invalid']);
  });

  it('reads a record of an earlier version under that version’s schema and signature encoding', () => {
    const key = generateToolKey('legacy');
    const registry = new KeyRegistry();
    registry.register('legacy', key.publicKey, 'Ed25519');
    const { session_id: _s, ...rest } = ev(1, 'attempted');
    void _s;
    const unsigned = { ...rest, spec_version: 'auditable-mcp/0.2', call_id: 'call-1', key_id: 'legacy', signer_seq: 7 };
    const signature = sign(null, Buffer.from(canonicalize(unsigned), 'utf8'), key.privateKey).toString('base64');
    const report = verifyLedger(chain([{ ...unsigned, signature }]), undefined, undefined, { keyRegistry: registry });
    expect(report.issues).toEqual([]);
    expect(report.complete).toBe(true);
    expect(kinds(verifyLedger(chain([{ ...unsigned, signature }])))).toEqual([]);
  });
});

describe('verifyLedger - Level-2 validation (§11.4)', () => {
  function signed() {
    const key = generateToolKey('tool');
    const registry = new KeyRegistry();
    registry.register('tool', key.publicKey, 'Ed25519');
    const at = (e: AuditEvent, n: number) => signEvent(e, 'tool', n, 'Ed25519', key.privateKey);
    return { registry, at };
  }

  it('verifies signatures against the registry, and says so when it has none', () => {
    const { registry, at } = signed();
    const records = chain([at(ev(1, 'attempted'), 0), at(ev(1, 'success'), 1)]);
    expect(verifyLedger(records, undefined, undefined, { keyRegistry: registry }).complete).toBe(true);
    const unchecked = verifyLedger(records);
    expect(unchecked.ok).toBe(true);
    expect(unchecked.unchecked).toEqual(['level-2-signature']);
    expect(unchecked.complete).toBe(false);
  });

  it('reports a signature that does not verify, including one under an unregistered key', () => {
    const { registry, at } = signed();
    const forged = { ...at(ev(1, 'attempted'), 0), mutates: false };
    const stranger = signEvent(ev(2, 'attempted'), 'stranger', 0, 'Ed25519', generateToolKey('s').privateKey);
    expect(kinds(verifyLedger(chain([forged, stranger]), undefined, undefined, { keyRegistry: registry }))).toEqual([
      'signature-invalid',
      'signature-invalid',
    ]);
  });

  it('verifies a record signed under a key revoked since (§10.9)', () => {
    const { registry, at } = signed();
    const records = chain([at(ev(1, 'attempted'), 0)]);
    registry.revoke('tool');
    expect(verifyLedger(records, undefined, undefined, { keyRegistry: registry }).issues).toEqual([]);
  });

  it('reports two sealed records sharing a signer_seq in one key and session as replay-detected', () => {
    const { registry, at } = signed();
    const records = chain([at(ev(1, 'attempted'), 0), at(ev(2, 'attempted'), 0), at(ev(3, 'attempted', { session_id: SESSION_B }), 0)]);
    expect(kinds(verifyLedger(records, undefined, undefined, { keyRegistry: registry }))).toEqual(['replay-detected']);
  });

  it('correlates by (session_id, id): an attempt of another session does not resolve an outcome', () => {
    const records = chain([ev(1, 'attempted'), ev(1, 'success', { session_id: SESSION_B })]);
    expect(kinds(verifyLedger(records))).toEqual(['orphaned-outcome']);
  });

  it('refuses tool and host registries that share a key (§10.9)', () => {
    const { registry } = signed();
    expect(() => verifyLedger([], undefined, undefined, { keyRegistry: registry, hostKeyRegistry: registry })).toThrow('share a key');
  });
});

describe('verifyLedger - identity matching (§10.10 construction 1)', () => {
  const identity = { logId: 'tenant-a', hostKeyIds: ['h'] };

  it('reports a record whose log_id differs, whose host_key_id is not expected, or which is uncountersigned', () => {
    const [a, b, c, d] = chain([ev(1, 'attempted'), ev(1, 'success'), ev(2, 'attempted'), ev(2, 'success')]);
    const records = [
      { ...a!, host_signature: 'AA', host_key_id: 'h', log_id: 'tenant-a' },
      { ...b!, host_signature: 'AA', host_key_id: 'h', log_id: 'tenant-b' },
      { ...c!, host_signature: 'AA', host_key_id: 'other', log_id: 'tenant-a' },
      d!,
    ];
    const report = verifyLedger(records, undefined, () => true, { expectedIdentity: identity });
    expect(report.issues.map((i) => [i.seq, i.kind])).toEqual([
      [1, 'principal-mismatch'],
      [2, 'principal-mismatch'],
      [3, 'principal-mismatch'],
    ]);
  });

  it('checks the identity of a record that cannot be canonicalized', () => {
    const [a] = chain([ev(1, 'attempted')]);
    const broken = { ...a!, event: { ...a!.event, action_context: { note: 'a\ud800b' } }, host_signature: 'AA', host_key_id: 'h', log_id: 'tenant-b' };
    expect(kinds(verifyLedger([broken], undefined, () => true, { expectedIdentity: identity }))).toEqual(['schema-invalid', 'principal-mismatch']);
  });
});

describe('verifyLedger - a required countersignature (§11.4)', () => {
  it('reports an uncountersigned record as host-signature-invalid only when the chain must be countersigned', () => {
    const [a, b] = chain([ev(1, 'attempted'), ev(1, 'success')]);
    const records = [{ ...a!, host_signature: 'AA', host_key_id: 'h', log_id: 'tenant-a' }, b!];
    expect(kinds(verifyLedger(records, undefined, () => true))).toEqual([]);
    const report = verifyLedger(records, undefined, () => true, { countersignatureRequired: true });
    expect(report.issues.map((i) => [i.seq, i.kind])).toEqual([[1, 'host-signature-invalid']]);
  });
});

describe('verifyLedger - order of sealing', () => {
  it('does not correlate an outcome with an attempt sealed after it (§7.2)', () => {
    expect(kinds(verifyLedger(chain([ev(1, 'success'), ev(1, 'attempted')])))).toEqual(['orphaned-outcome']);
  });

  it('reports a record of an earlier version sealed after a later one as schema-invalid', () => {
    const earlier = {
      id: '00000000-0000-4000-8000-000000000009',
      spec_version: 'auditable-mcp/0.2',
      ts: '2026-07-15T00:00:01.000Z',
      call_id: '7',
      action_type: 'db.write',
      mutates: true,
      egress: false,
      target_resource: { kind: 'table', ref: 't' },
      outcome: 'attempted',
    } as unknown as AuditEvent;
    expect(kinds(verifyLedger(chain([earlier, ev(1, 'attempted')])))).toEqual([]);
    expect(kinds(verifyLedger(chain([ev(1, 'attempted'), earlier])))).toEqual(['schema-invalid']);
  });
});
