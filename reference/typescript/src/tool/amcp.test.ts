import { describe, it, expect, vi } from 'vitest';
import { AmcpSession, AmcpAbortedError, deterministicDeps } from './amcp.js';
import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import type { AttemptResponse, AuditTransport } from '../transport/transport.js';
import type { AuditEvent } from '../schema/event.js';
import { DEFAULT_L1_CAPABILITY, negotiateCapability, type NegotiationResult } from '../schema/capability.js';
import { generateToolKey } from '../l2/keys.js';
import { KeySigner } from '../l2/signing.js';

const SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0';

function session(host: AuditHost): AmcpSession {
  return new AmcpSession(new InProcessTransport(host), host.openSession(), deterministicDeps());
}

// Transport double: returns a canned attempt response, captures outcome events.
class StubTransport implements AuditTransport {
  readonly outcomes: AuditEvent[] = [];
  constructor(private readonly response: AttemptResponse) {}
  negotiate(): NegotiationResult {
    return negotiateCapability(DEFAULT_L1_CAPABILITY, DEFAULT_L1_CAPABILITY);
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
  record_hash: 'd'.repeat(64),
  host_ts: '2026-07-15T00:00:01.000Z',
  previous_hash: '0'.repeat(64),
};

const specFor = (action_type: string): Parameters<AmcpSession['audited']>[0] => ({
  action_type,
  target_resource: { kind: 'table', ref: 'notes' },
  effect: { mutates: action_type === 'db.write', egress: false },
});

describe('AmcpSession - audit-before-act discipline', () => {
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

  it('does not perform the action when the host is unavailable (fail-closed)', async () => {
    const host = new AuditHost('t#d');
    host.unavailable = true;
    const s = session(host);
    const perform = vi.fn(async () => 'result');
    await expect(
      s.audited({ action_type: 'db.write', target_resource: { kind: 'table', ref: 'customers' }, effect: { mutates: true, egress: false } }, perform),
    ).rejects.toBeInstanceOf(AmcpAbortedError);
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

describe('AmcpSession - an outcome that cannot be delivered', () => {
  it('a performed action whose outcome is lost is neither recorded failed nor rethrown (§10.8)', async () => {
    const host = new AuditHost('t#d');
    const inner = new InProcessTransport(host);
    let failed = false;
    const transport: AuditTransport = {
      negotiate: (offered) => inner.negotiate(offered),
      sendAttempt: (event) => inner.sendAttempt(event),
      sendOutcome: async (event) => {
        if (!failed) {
          failed = true;
          throw new Error('the wire went away');
        }
        return inner.sendOutcome(event);
      },
    };
    const s = new AmcpSession(transport, host.openSession(), deterministicDeps());
    const perform = vi.fn(async () => 'ok');
    await expect(s.audited(specFor('db.write'), perform)).resolves.toBe('ok');
    expect(perform).toHaveBeenCalledTimes(1);
    expect(host.records().map((r) => r.event.outcome)).toEqual(['attempted']);
  });
});

describe('AmcpSession - Polluted Stop and abort signaling', () => {
  it('Level 2: aborts on a record_hash mismatch and emits aborted/hash-mismatch', async () => {
    const key = generateToolKey('polluted-stop-key');
    const signer = new KeySigner(key.keyId, key.alg, key.privateKey);
    const transport = new StubTransport(ACCEPT_BAD_HASH);
    const s = new AmcpSession(transport, SESSION, deterministicDeps(), signer);
    const perform = vi.fn(async () => 'result');
    await expect(s.audited(specFor('db.write'), perform)).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(perform).not.toHaveBeenCalled();
    const aborted = transport.outcomes.filter((o) => o.outcome === 'aborted');
    expect(aborted).toHaveLength(1);
    expect(aborted[0]?.reason).toBe('hash-mismatch');
  });

  it('Level 1: skips the Polluted Stop check and proceeds despite a mismatched hash', async () => {
    const transport = new StubTransport(ACCEPT_BAD_HASH);
    const s = new AmcpSession(transport, SESSION, deterministicDeps());
    const perform = vi.fn(async () => 'ok');
    const out = await s.audited(specFor('db.read'), perform);
    expect(out).toBe('ok');
    expect(perform).toHaveBeenCalledTimes(1);
    expect(transport.outcomes.some((o) => o.outcome === 'aborted')).toBe(false);
  });

  it('emits aborted/host-rejected when the host rejects the attempt', async () => {
    const transport = new StubTransport({ status: 'reject', reason: 'schema-invalid' });
    const s = new AmcpSession(transport, SESSION, deterministicDeps());
    await expect(s.audited(specFor('db.write'), vi.fn(async () => 'x'))).rejects.toBeInstanceOf(AmcpAbortedError);
    const aborted = transport.outcomes.filter((o) => o.outcome === 'aborted');
    expect(aborted).toHaveLength(1);
    expect(aborted[0]?.reason).toBe('host-rejected');
  });

  it('emits aborted/host-unavailable when the host is unavailable', async () => {
    const transport = new StubTransport({ status: 'unavailable', reason: 'internal-error' });
    const s = new AmcpSession(transport, SESSION, deterministicDeps());
    await expect(s.audited(specFor('db.read'), vi.fn(async () => 'x'))).rejects.toBeInstanceOf(AmcpAbortedError);
    const aborted = transport.outcomes.filter((o) => o.outcome === 'aborted');
    expect(aborted).toHaveLength(1);
    expect(aborted[0]?.reason).toBe('host-unavailable');
  });
  it('treats a transport fault as unanswered: aborted/host-unavailable, action not performed (§6)', async () => {
    const outcomes: AuditEvent[] = [];
    const failing: AuditTransport = {
      negotiate: () => negotiateCapability(DEFAULT_L1_CAPABILITY, DEFAULT_L1_CAPABILITY),
      sendAttempt: async () => {
        throw new Error('connection reset');
      },
      sendOutcome: async (event) => {
        outcomes.push(event);
      },
    };
    const perform = vi.fn(async () => 'x');
    await expect(new AmcpSession(failing, SESSION, deterministicDeps()).audited(specFor('db.write'), perform)).rejects.toThrow('host-unavailable');
    expect(perform).not.toHaveBeenCalled();
    expect(outcomes.map((o) => o.reason)).toEqual(['host-unavailable']);
  });

  it('treats an answer outside the Attempt Response schema - a partial countersignature triple - as unanswered (§6)', async () => {
    const partial = { ...ACCEPT_BAD_HASH, host_signature: 'AAAA' } as AttemptResponse;
    const transport = new StubTransport(partial);
    const verify = vi.fn(() => true);
    const s = new AmcpSession(transport, SESSION, deterministicDeps(), undefined, verify, true);
    await expect(s.audited(specFor('db.write'), vi.fn(async () => 'x'))).rejects.toThrow('host-unavailable');
    expect(verify).not.toHaveBeenCalled();
    expect(transport.outcomes.map((o) => o.reason)).toEqual(['host-unavailable']);
  });

  it('performs Polluted Stop at Level 1 when it requires a countersignature: a genuine accept for another record aborts (§7.2)', async () => {
    const countersigned = { ...ACCEPT_BAD_HASH, host_signature: 'AAAA', host_key_id: 'host', log_id: 'log' } as AttemptResponse;
    const transport = new StubTransport(countersigned);
    const perform = vi.fn(async () => 'x');
    const s = new AmcpSession(transport, SESSION, deterministicDeps(), undefined, () => true, true);
    await expect(s.audited(specFor('db.write'), perform)).rejects.toThrow('hash-mismatch');
    expect(perform).not.toHaveBeenCalled();
  });

  it('sends the identical attempt again after unavailable and performs the operation once (§6, §7.1)', async () => {
    const host = new AuditHost('t#d');
    const sessionId = host.openSession();
    let first = true;
    const flaky: AuditTransport = {
      negotiate: () => host.negotiate(DEFAULT_L1_CAPABILITY),
      sendAttempt: async (event) => {
        host.unavailable = first;
        first = false;
        const answer = host.handleAttempt(event);
        host.unavailable = false;
        return answer;
      },
      sendOutcome: async (event) => host.handleOutcome(event),
    };
    const perform = vi.fn(async () => 'x');
    const s = new AmcpSession(flaky, sessionId, deterministicDeps(), undefined, undefined, false, 1);
    await expect(s.audited(specFor('db.write'), perform)).resolves.toBe('x');
    expect(perform).toHaveBeenCalledTimes(1);
    expect(host.records().map((r) => r.event.outcome)).toEqual(['attempted', 'success']);
  });
});
