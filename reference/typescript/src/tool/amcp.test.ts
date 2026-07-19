import { describe, it, expect, vi } from 'vitest';
import { AmcpSession, AmcpBlockedError, deterministicDeps } from './amcp.js';
import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import type { AttemptResponse, AuditTransport } from '../transport/transport.js';
import type { AuditEvent } from '../schema/event.js';
import { DEFAULT_L1_CAPABILITY, type NegotiationResult } from '../schema/capability.js';
import { generateToolKey } from '../l2/keys.js';
import { Ed25519Signer } from '../l2/signing.js';

function session(host: AuditHost): AmcpSession {
  return new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps());
}

// Transport double: returns a canned attempt response, captures outcome events.
class StubTransport implements AuditTransport {
  readonly outcomes: AuditEvent[] = [];
  constructor(private readonly response: AttemptResponse) {}
  negotiate(): NegotiationResult {
    return { required: DEFAULT_L1_CAPABILITY, satisfied: true };
  }
  async sendAttempt(): Promise<AttemptResponse> {
    return this.response;
  }
  async sendOutcome(event: AuditEvent): Promise<void> {
    this.outcomes.push(event);
  }
}

// accept whose record_hash does not match the tool's recomputation.
const ACCEPT_BAD_HASH: AttemptResponse = {
  status: 'accept',
  seq: 0,
  record_hash: 'deadbeef',
  host_ts: '2026-07-15T00:00:01.000Z',
  previous_hash: '0'.repeat(64),
};

const specFor = (action_type: string): Parameters<AmcpSession['audited']>[0] => ({
  action_type,
  target_resource: { kind: 'table', ref: 'notes' },
  effect: { mutates: action_type === 'db.write', egress: false },
});

describe('AmcpSession — audit-before-act discipline', () => {
  it('emits attempt, awaits accept, performs the action, then emits outcome', async () => {
    const host = new AuditHost('t#d');
    const s = session(host);
    const perform = vi.fn(async () => 'result');
    const out = await s.audited(
      { action_type: 'db.read', target_resource: { kind: 'table', ref: 'customers' }, effect: { mutates: false, egress: false }, disclose: { q: 1 } },
      perform,
    );
    expect(out).toBe('result');
    expect(perform).toHaveBeenCalledTimes(1);
    // Sealed records: attempted, then success.
    const outcomes = host.records().map((r) => r.event.outcome);
    expect(outcomes).toEqual(['attempted', 'success']);
  });

  it('does not perform the action when Tier1 is unavailable (fail-closed)', async () => {
    const host = new AuditHost('t#d');
    host.unavailable = true;
    const s = session(host);
    const perform = vi.fn(async () => 'result');
    await expect(
      s.audited({ action_type: 'db.write', target_resource: { kind: 'table', ref: 'customers' }, effect: { mutates: true, egress: false } }, perform),
    ).rejects.toBeInstanceOf(AmcpBlockedError);
    expect(perform).not.toHaveBeenCalled();
    expect(host.records()).toHaveLength(0);
  });

  it('seals a failed outcome when the action throws, and rethrows', async () => {
    const host = new AuditHost('t#d');
    const s = session(host);
    const boom = new Error('boom');
    await expect(
      s.audited({ action_type: 'db.write', target_resource: { kind: 'table', ref: 'customers' }, effect: { mutates: true, egress: false } }, async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
    const outcomes = host.records().map((r) => r.event.outcome);
    expect(outcomes).toEqual(['attempted', 'failed']);
  });
});

describe('AmcpSession — Polluted Stop and abort signaling', () => {
  it('Level 2: aborts on a record_hash mismatch and emits aborted/hash-mismatch', async () => {
    const key = generateToolKey('polluted-stop-key');
    const signer = new Ed25519Signer(key.keyId, key.privateKey);
    const transport = new StubTransport(ACCEPT_BAD_HASH);
    const s = new AmcpSession(transport, 'call_abc', deterministicDeps(), signer);
    const perform = vi.fn(async () => 'result');
    await expect(s.audited(specFor('db.write'), perform)).rejects.toBeInstanceOf(AmcpBlockedError);
    expect(perform).not.toHaveBeenCalled();
    const aborted = transport.outcomes.filter((o) => o.outcome === 'aborted');
    expect(aborted).toHaveLength(1);
    expect(aborted[0]?.reason).toBe('hash-mismatch');
  });

  it('Level 1: skips the Polluted Stop check and proceeds despite a mismatched hash', async () => {
    const transport = new StubTransport(ACCEPT_BAD_HASH);
    const s = new AmcpSession(transport, 'call_abc', deterministicDeps());
    const perform = vi.fn(async () => 'ok');
    const out = await s.audited(specFor('db.read'), perform);
    expect(out).toBe('ok');
    expect(perform).toHaveBeenCalledTimes(1);
    expect(transport.outcomes.some((o) => o.outcome === 'aborted')).toBe(false);
  });

  it('emits aborted/host-rejected when the host rejects the attempt', async () => {
    const transport = new StubTransport({ status: 'reject', reason: 'schema-invalid' });
    const s = new AmcpSession(transport, 'call_abc', deterministicDeps());
    await expect(s.audited(specFor('db.write'), vi.fn(async () => 'x'))).rejects.toBeInstanceOf(AmcpBlockedError);
    const aborted = transport.outcomes.filter((o) => o.outcome === 'aborted');
    expect(aborted).toHaveLength(1);
    expect(aborted[0]?.reason).toBe('host-rejected');
  });

  it('emits aborted/host-unavailable when the host is unavailable', async () => {
    const transport = new StubTransport({ status: 'unavailable', reason: 'tier1-durability-failure', retryable: true });
    const s = new AmcpSession(transport, 'call_abc', deterministicDeps());
    await expect(s.audited(specFor('db.read'), vi.fn(async () => 'x'))).rejects.toBeInstanceOf(AmcpBlockedError);
    const aborted = transport.outcomes.filter((o) => o.outcome === 'aborted');
    expect(aborted).toHaveLength(1);
    expect(aborted[0]?.reason).toBe('host-unavailable');
  });
});
