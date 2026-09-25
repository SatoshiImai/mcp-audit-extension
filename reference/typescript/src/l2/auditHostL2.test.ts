import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import type { AuditEvent } from '../schema/event.js';
import { generateToolKey, KeyRegistry } from './keys.js';
import { signEvent } from './signing.js';

const L2_CAP = {
  spec_version: 'auditable-mcp/0.3' as const,
  level: 'L2' as const,
  attempt: 'request' as const,
  countersign: 'none' as const,
};

function attempt(n: number): AuditEvent {
  return {
    id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:01.000Z',
    session_id: SESSION,
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
    action_context_hash: `sha256:${'0'.repeat(64)}`,
  };
}

const SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0';
const OTHER_SESSION = '0198f3a2-5c1e-7000-8000-00000000abc1';

function newL2Host() {
  const key = generateToolKey('tool-key-1');
  const registry = new KeyRegistry();
  registry.register(key.keyId, key.publicKey, key.alg);
  const host = new AuditHost('t#d', L2_CAP, registry);
  host.openSession(SESSION);
  return { host, key, registry };
}

describe('AuditHost L2 policy', () => {
  it('accepts a valid signed attempt and seals it', () => {
    const { host, key } = newL2Host();
    const signed = signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey);
    expect(host.handleAttempt(signed).status).toBe('accept');
    expect(host.records()).toHaveLength(1);
  });

  it('rejects an unsigned event under L2 (needs escalation)', () => {
    const { host } = newL2Host();
    const res = host.handleAttempt(attempt(1));
    expect(res).toMatchObject({ status: 'reject', reason: 'l2-unsigned' });
    expect(host.records()).toHaveLength(0);
  });

  it('rejects a signature from an unregistered key', () => {
    const { host } = newL2Host();
    const stranger = generateToolKey('stranger');
    const signed = signEvent(attempt(1), stranger.keyId, 0, stranger.alg, stranger.privateKey);
    expect(host.handleAttempt(signed)).toMatchObject({ status: 'reject', reason: 'unknown-key' });
  });

  it('rejects a forged (post-signature tampered) record', () => {
    const { host, key } = newL2Host();
    const signed = signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey);
    const forged: AuditEvent = { ...signed, target_resource: { kind: 'table', ref: 'salaries' } };
    expect(host.handleAttempt(forged)).toMatchObject({ status: 'reject', reason: 'signature-invalid' });
    expect(host.records()).toHaveLength(0);
  });

  it('rejects a replayed sequence', () => {
    const { host, key } = newL2Host();
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey));
    // A second event re-using sequence 0 (a replay) with a fresh id.
    const replay = signEvent(attempt(2), key.keyId, 0, key.alg, key.privateKey);
    expect(host.handleAttempt(replay)).toMatchObject({ status: 'reject', reason: 'replay-detected' });
  });

  it('flags a first signer_seq other than 0 in a session as a gap, and accepts the record (§7.4)', () => {
    const { host, key } = newL2Host();
    const res = host.handleAttempt(signEvent(attempt(1), key.keyId, 5, key.alg, key.privateKey));
    expect(res.status).toBe('accept');
    expect(host.getAnomalies().map((a) => a.kind)).toEqual(['signer-seq-gap']);
  });

  it('numbers each session from 0, so one key serves concurrent calls without a gap (§7.4)', () => {
    const { host, key } = newL2Host();
    host.openSession(OTHER_SESSION);
    expect(host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey)).status).toBe('accept');
    const other = { ...attempt(2), session_id: OTHER_SESSION };
    expect(host.handleAttempt(signEvent(other, key.keyId, 0, key.alg, key.privateKey)).status).toBe('accept');
    expect(host.getAnomalies()).toHaveLength(0);
  });

  it('flags a forward sequence gap (suppressed prior event) but accepts the record', () => {
    const { host, key } = newL2Host();
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey));
    // Jump from 0 to 2 - sequence 1 was suppressed.
    const res = host.handleAttempt(signEvent(attempt(2), key.keyId, 2, key.alg, key.privateKey));
    expect(res.status).toBe('accept');
    expect(host.getAnomalies().some((a) => a.kind === 'signer-seq-gap')).toBe(true);
  });

  it('counts a sealed outcome in signer_seq: attempt(0) -> outcome(1) -> attempt(2) is contiguous, no gap (§7.4)', () => {
    const { host, key } = newL2Host();
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey));
    // The correlated signed success outcome consumes signer_seq 1 and is sealed.
    host.handleOutcome(signEvent({ ...attempt(1), outcome: 'success' }, key.keyId, 1, key.alg, key.privateKey));
    // The next attempt at signer_seq 2 is contiguous with the outcome's 1 - not a gap.
    const res = host.handleAttempt(signEvent(attempt(2), key.keyId, 2, key.alg, key.privateKey));
    expect(res.status).toBe('accept');
    expect(host.getAnomalies().some((a) => a.kind === 'signer-seq-gap')).toBe(false);
    expect(host.records()).toHaveLength(3);
  });

  it('does not move the replay bound on unavailable: the identical attempt sent again is accepted (§7.1, §7.4)', () => {
    const { host, key } = newL2Host();
    host.unavailable = true;
    const signed = signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey);
    expect(host.handleAttempt(signed).status).toBe('unavailable');
    host.unavailable = false;
    expect(host.handleAttempt(signed).status).toBe('accept');
    expect(host.records()).toHaveLength(1);
    expect(host.getAnomalies()).toHaveLength(0);
  });

  it('seals the aborted outcome of an unavailable attempt without flagging a gap (§7.2, §7.4)', () => {
    const { host, key } = newL2Host();
    host.unavailable = true;
    expect(host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey)).status).toBe('unavailable');
    host.unavailable = false;
    // The tool gives up and emits its signed refusal at the next value; the host received 0, so 1 is
    // no gap, and the refusal is sealed.
    const aborted = signEvent({ ...attempt(1), outcome: 'aborted', reason: 'host-unavailable' }, key.keyId, 1, key.alg, key.privateKey);
    host.handleOutcome(aborted);
    expect(host.getAnomalies()).toHaveLength(0);
    expect(host.records()).toHaveLength(1);
  });

  it('continues the sequence after a rejected attempt: its refusal and the next attempt are no gap (§7.4)', () => {
    const { host, key } = newL2Host();
    // A reject after the signature verified is a decision: the replay bound moves past it.
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey));
    const duplicate = signEvent({ ...attempt(1), ts: '2026-07-15T00:00:09.000Z' }, key.keyId, 1, key.alg, key.privateKey);
    expect(host.handleAttempt(duplicate)).toMatchObject({ status: 'reject', reason: 'replay-detected' });
    const next = signEvent(attempt(3), key.keyId, 2, key.alg, key.privateKey);
    expect(host.handleAttempt(next).status).toBe('accept');
    expect(host.getAnomalies().some((a) => a.kind === 'signer-seq-gap')).toBe(false);
  });
  it('keeps the set of decided values: a value sent again after unavailable is accepted even below a decided one (§7.4)', () => {
    const { host, key } = newL2Host();
    const first = signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey);
    host.unavailable = true;
    expect(host.handleAttempt(first).status).toBe('unavailable');
    host.unavailable = false;
    expect(host.handleAttempt(signEvent(attempt(2), key.keyId, 1, key.alg, key.privateKey)).status).toBe('accept');
    expect(host.handleAttempt(first).status).toBe('accept');
    // A repeat of the decided value 1 under another id is a replay.
    expect(host.handleAttempt(signEvent(attempt(3), key.keyId, 1, key.alg, key.privateKey))).toMatchObject({
      status: 'reject',
      reason: 'replay-detected',
    });
    expect(host.getAnomalies().map((a) => a.kind)).toEqual(['replay-detected']);
    expect(host.records()).toHaveLength(2);
  });

  it('counts an outcome as received when the host is unavailable for it, so the next value is no gap (§7.4)', () => {
    const { host, key } = newL2Host();
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey));
    host.unavailable = true;
    host.handleOutcome(signEvent({ ...attempt(1), outcome: 'success' }, key.keyId, 1, key.alg, key.privateKey));
    host.unavailable = false;
    expect(host.handleAttempt(signEvent(attempt(2), key.keyId, 2, key.alg, key.privateKey)).status).toBe('accept');
    expect(host.getAnomalies().some((a) => a.kind === 'signer-seq-gap')).toBe(false);
  });

  it('records dropped outcomes under their Tier-1 anomaly kinds and never throws (§6)', () => {
    const { host, key } = newL2Host();
    const stranger = generateToolKey('stranger');
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey));
    const success = { ...attempt(1), outcome: 'success' as const };
    host.handleOutcome(success); // unsigned
    host.handleOutcome(signEvent(success, stranger.keyId, 1, stranger.alg, stranger.privateKey)); // unknown key
    host.handleOutcome({ ...signEvent(success, key.keyId, 1, key.alg, key.privateKey), mutates: false }); // bad signature
    host.handleOutcome(signEvent({ ...attempt(9), outcome: 'aborted', reason: 'host-rejected' }, key.keyId, 0, key.alg, key.privateKey)); // decided
    host.handleOutcome({ ...success, signature: 'AAAA' }); // partial Level-2 trio
    expect(host.getAnomalies().map((a) => a.kind)).toEqual([
      'signature-invalid',
      'signature-invalid',
      'signature-invalid',
      'replay-detected',
      'schema-invalid',
    ]);
    expect(host.records()).toHaveLength(1);
  });

  it('checks the outcome signature before correlation: a forged orphan is signature-invalid, not orphaned (§7.2)', () => {
    const { host, key } = newL2Host();
    const forged = { ...signEvent({ ...attempt(5), outcome: 'success' }, key.keyId, 0, key.alg, key.privateKey), mutates: false };
    host.handleOutcome(forged);
    expect(host.getAnomalies().map((a) => a.kind)).toEqual(['signature-invalid']);
  });

  it('rejects an event under a revoked key as unknown-key (§10.9)', () => {
    const { host, key, registry } = newL2Host();
    registry.revoke(key.keyId);
    expect(host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey))).toMatchObject({
      status: 'reject',
      reason: 'unknown-key',
    });
  });
});
