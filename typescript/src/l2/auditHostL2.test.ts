import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import type { AuditEvent } from '../schema/event.js';
import { generateToolKey, KeyRegistry } from './keys.js';
import { signEvent } from './signing.js';

const L2_CAP = {
  level: 'L2' as const,
  attempt: 'request' as const,
  attempt_ack_deadline_ms: 500,
  block_disposition: ['abort' as const],
  outcome_mode: 'batched' as const,
  outcome_batch_window_ms: 200,
};

function attempt(n: number): AuditEvent {
  return {
    id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
    spec_version: 'a-mcp/0.1',
    ts: '2026-07-15T00:00:01.000Z',
    call_id: 'call_abc',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
    params_hash: `sha256:${'0'.repeat(64)}`,
  };
}

function newL2Host() {
  const key = generateToolKey('tool-key-1');
  const registry = new KeyRegistry();
  registry.register(key.keyId, key.publicKey);
  const host = new AuditHost('t#d', L2_CAP, registry);
  return { host, key };
}

describe('AuditHost L2 policy', () => {
  it('accepts a valid signed attempt and seals it', () => {
    const { host, key } = newL2Host();
    const signed = signEvent(attempt(1), key.keyId, 0, key.privateKey);
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
    const signed = signEvent(attempt(1), stranger.keyId, 0, stranger.privateKey);
    expect(host.handleAttempt(signed)).toMatchObject({ status: 'reject', reason: 'unknown-key' });
  });

  it('rejects a forged (post-signature tampered) record', () => {
    const { host, key } = newL2Host();
    const signed = signEvent(attempt(1), key.keyId, 0, key.privateKey);
    const forged: AuditEvent = { ...signed, target_resource: { kind: 'table', ref: 'salaries' } };
    expect(host.handleAttempt(forged)).toMatchObject({ status: 'reject', reason: 'signature-invalid' });
    expect(host.records()).toHaveLength(0);
  });

  it('rejects a replayed sequence', () => {
    const { host, key } = newL2Host();
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.privateKey));
    // A second event re-using sequence 0 (a replay) with a fresh id.
    const replay = signEvent(attempt(2), key.keyId, 0, key.privateKey);
    expect(host.handleAttempt(replay)).toMatchObject({ status: 'reject', reason: 'sequence-replay' });
  });

  it('flags a forward sequence gap (suppressed prior event) but accepts the record', () => {
    const { host, key } = newL2Host();
    host.handleAttempt(signEvent(attempt(1), key.keyId, 0, key.privateKey));
    // Jump from 0 to 2 — sequence 1 was suppressed.
    const res = host.handleAttempt(signEvent(attempt(2), key.keyId, 2, key.privateKey));
    expect(res.status).toBe('accept');
    expect(host.getAnomalies().some((a) => a.kind === 'sequence-gap')).toBe(true);
  });
});
