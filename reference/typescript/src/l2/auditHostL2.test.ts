import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import type { AuditEvent } from '../schema/event.js';
import { generateToolKey, KeyRegistry } from './keys.js';
import { signEvent } from './signing.js';

const L2_CAP = {
  spec_version: 'auditable-mcp/0.3' as const,
  level: 'L2' as const,
  attempt: 'request' as const,
  witness: 'none' as const,
};

function attempt(n: number): AuditEvent {
  return {
    id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
    spec_version: 'auditable-mcp/0.3',
    ts: '2026-07-15T00:00:01.000Z',
    call_id: 'call_abc',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
    action_context_hash: `sha256:${'0'.repeat(64)}`,
  };
}

function newL2Host() {
  const key = generateToolKey('tool-key-1');
  const registry = new KeyRegistry();
  registry.register(key.keyId, key.publicKey, key.alg);
  const host = new AuditHost('t#d', L2_CAP, registry);
  return { host, key };
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

  it('accepts a first observation with signer_seq > 0 as the baseline, without flagging a gap (§7.4)', () => {
    const { host, key } = newL2Host();
    // A key whose counter starts above 0 (persisted across restart, or reused across partitions).
    const res = host.handleAttempt(signEvent(attempt(1), key.keyId, 5, key.alg, key.privateKey));
    expect(res.status).toBe('accept');
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

  it('advances the sequence only on seal: a retry after unavailable is accepted, not replay-rejected', () => {
    const { host, key } = newL2Host();
    host.unavailable = true;
    const signed = signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey);
    expect(host.handleAttempt(signed).status).toBe('unavailable');
    host.unavailable = false;
    expect(host.handleAttempt(signed).status).toBe('accept');
    expect(host.records()).toHaveLength(1);
  });

  it('does not flag a fail-closed aborted outcome under L2 as a sequence gap (§10.4)', () => {
    const { host, key } = newL2Host();
    host.unavailable = true;
    // Attempt seq 0 is refused (unavailable), never sealed, so the sequence never advances.
    expect(host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.alg, key.privateKey)).status).toBe('unavailable');
    host.unavailable = false;
    // The tool honors §11.3 and emits a signed aborted outcome; the signer's next sequence (1)
    // outran the unsealed attempt. This must not be flagged as a suppression gap.
    const aborted = signEvent({ ...attempt(1), outcome: 'aborted', reason: 'host-unavailable' }, key.keyId, 1, key.alg, key.privateKey);
    host.handleOutcome(aborted);
    expect(host.getAnomalies()).toHaveLength(0);
    expect(host.records()).toHaveLength(0);
  });
});
