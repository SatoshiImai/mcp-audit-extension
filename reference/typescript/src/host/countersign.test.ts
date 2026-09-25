import { describe, expect, it } from 'vitest';
import { AmcpAbortedError, AmcpSession, type AmcpDeps } from '../tool/amcp.js';
import { AuditHost } from './auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { countersignaturePayload } from '../ledger/ledger.js';
import { verifyLedger } from '../verify/verify.js';
import { DEFAULT_L1_CAPABILITY, type AuditCapability } from '../schema/capability.js';

// The countersignature axis (§5.2): what a record carries, and what the tool does about it (§7.1, §7.2).
const COUNTERSIGNING: AuditCapability = { ...DEFAULT_L1_CAPABILITY, countersign: 'host' };
const TARGET = { kind: 'table', ref: 'customers' } as const;

const SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0';

// A stand-in scheme: these tests are about where the countersignature is required and checked, not
// about the algorithm, which the vectors exercise with a real key.
const signer = {
  keyId: 'host-key-2026',
  sign: (payload: string) => Buffer.from(`countersigned:${payload}`, 'utf8').toString('base64url'),
};
const forger = { keyId: 'host-key-2026', sign: () => Buffer.from('not-the-host', 'utf8').toString('base64url') };
const verify = (keyId: string, signature: string, payload: string) =>
  keyId === 'host-key-2026' && signature === signer.sign(payload);

class Deps implements AmcpDeps {
  #n = 0;
  newId(): string {
    this.#n += 1;
    return `00000000-0000-4000-8000-${String(this.#n).padStart(12, '0')}`;
  }
  now(): string {
    return '2026-07-15T00:00:01.000Z';
  }
}

const run = (session: AmcpSession) =>
  session.audited(
    { action_type: 'db.read', target_resource: TARGET, effect: { mutates: false, egress: false } },
    async () => undefined,
  );

describe('the countersignature axis (§5.2)', () => {
  it('a countersigning host signs every record it seals', async () => {
    const host = new AuditHost('t#w', COUNTERSIGNING, undefined, signer);
    await run(new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps()));
    const records = host.records();
    expect(records.length).toBeGreaterThan(0);
    expect(records.every((r) => r.host_signature !== undefined && r.host_key_id === 'host-key-2026' && r.log_id === 't#w')).toBe(true);
  });

  it('a host declaring none returns no countersignature', async () => {
    const host = new AuditHost('t#d');
    await run(new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps()));
    expect(host.records().every((r) => r.host_signature === undefined && r.host_key_id === undefined && r.log_id === undefined)).toBe(true);
  });

  it('a host cannot declare a countersignature it cannot produce', () => {
    expect(() => new AuditHost('t#w', COUNTERSIGNING)).toThrow('requires a Countersigner');
    expect(() => new AuditHost('t#d', DEFAULT_L1_CAPABILITY, undefined, signer)).toThrow('must not hold');
  });

  it('a tool that requires a countersignature aborts on an uncountersigned accept', async () => {
    const plain = new AuditHost('t#d');
    const session = new AmcpSession(
      new InProcessTransport(plain),
      plain.openSession(),
      new Deps(),
      undefined,
      verify,
      true,
    );
    await expect(run(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    await expect(run(session)).rejects.toThrow('host-uncountersigned');
  });

  it('a tool aborts on a countersignature that does not verify', async () => {
    const host = new AuditHost('t#w', COUNTERSIGNING, undefined, forger);
    const session = new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps(), undefined, verify, true);
    await expect(run(session)).rejects.toThrow('host-signature-invalid');
  });

  it('requiring a countersignature without a verifier is refused', () => {
    expect(
      () =>
        new AmcpSession(new InProcessTransport(new AuditHost('t#d')), SESSION, new Deps(), undefined, undefined, true),
    ).toThrow('CountersignatureVerifier');
  });

  it('the countersignature preimage is the host-assigned fields and the ledger name alone (§7.1)', () => {
    const payload = countersignaturePayload(0, '2026-07-15T00:00:01.000Z', 't#w', '0'.repeat(64), 'a'.repeat(64));
    expect(Object.keys(JSON.parse(payload))).toEqual(['host_ts', 'log_id', 'previous_hash', 'record_hash', 'seq']);
    expect(payload.includes('signature')).toBe(false);
  });

  it('a countersignature does not verify for another ledger (§7.1)', async () => {
    const host = new AuditHost('t#w', COUNTERSIGNING, undefined, signer);
    await run(new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps()));
    const moved = host.records().map((r) => ({ ...r, log_id: 't#other' }));
    expect(verifyLedger(moved, undefined, verify).issues.map((i) => i.kind)).toContain('host-signature-invalid');
  });
});

describe('verifier conformance for the countersignature (§11.4)', () => {
  it('a verifier without the registry says the countersignature was not checked', async () => {
    const host = new AuditHost('t#w', COUNTERSIGNING, undefined, signer);
    await run(new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps()));
    const report = verifyLedger(host.records());
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['countersignature']);
    expect(report.complete).toBe(false);
  });

  it('a verifier with the registry determines the countersignature', async () => {
    const host = new AuditHost('t#w', COUNTERSIGNING, undefined, signer);
    await run(new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps()));
    expect(verifyLedger(host.records(), undefined, verify).complete).toBe(true);
  });

  it('an uncountersigned chain is complete without a checker', async () => {
    const host = new AuditHost('t#d');
    await run(new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps()));
    expect(verifyLedger(host.records()).complete).toBe(true);
  });

  it('a countersignature that does not verify is reported', async () => {
    const host = new AuditHost('t#w', COUNTERSIGNING, undefined, forger);
    await run(new AmcpSession(new InProcessTransport(host), host.openSession(), new Deps()));
    const report = verifyLedger(host.records(), undefined, verify);
    expect(report.ok).toBe(false);
    expect(report.issues.every((i) => i.kind === 'host-signature-invalid')).toBe(true);
  });
});
