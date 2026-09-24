import { describe, expect, it } from 'vitest';
import { AmcpAbortedError, AmcpSession, type AmcpDeps } from '../tool/amcp.js';
import { AuditHost } from './auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { witnessPayload } from '../ledger/ledger.js';
import { verifyLedger } from '../verify/verify.js';
import { DEFAULT_L1_CAPABILITY, type AuditCapability } from '../schema/capability.js';

// The witness axis (§5.2): what a record carries, and what the tool does about it (§7.1, §7.2).
const WITNESSING: AuditCapability = { ...DEFAULT_L1_CAPABILITY, witness: 'host' };
const TARGET = { kind: 'table', ref: 'customers' } as const;

// The vectors pin the preimage and the field placement, not the signature scheme.
const signer = {
  keyId: 'host-key-2026',
  sign: (_payload: string) => Buffer.from('fake-witness-signature', 'utf8').toString('base64'),
};
const forger = { keyId: 'host-key-2026', sign: () => Buffer.from('not-the-host', 'utf8').toString('base64') };
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

describe('the witness axis (§5.2)', () => {
  it('a witnessing host signs every record it seals', async () => {
    const host = new AuditHost('t#w', WITNESSING, undefined, signer);
    await run(new AmcpSession(new InProcessTransport(host), 'call-1', new Deps()));
    const records = host.records();
    expect(records.length).toBeGreaterThan(0);
    expect(records.every((r) => r.host_signature !== undefined && r.host_key_id === 'host-key-2026')).toBe(true);
  });

  it('a host declaring none returns no witness', async () => {
    const host = new AuditHost('t#d');
    await run(new AmcpSession(new InProcessTransport(host), 'call-1', new Deps()));
    expect(host.records().every((r) => r.host_signature === undefined && r.host_key_id === undefined)).toBe(true);
  });

  it('a host cannot declare a witness it cannot produce', () => {
    expect(() => new AuditHost('t#w', WITNESSING)).toThrow('requires a WitnessSigner');
    expect(() => new AuditHost('t#d', DEFAULT_L1_CAPABILITY, undefined, signer)).toThrow('must not hold');
  });

  it('a tool that requires a witness aborts on an unwitnessed accept', async () => {
    const session = new AmcpSession(
      new InProcessTransport(new AuditHost('t#d')),
      'call-1',
      new Deps(),
      undefined,
      verify,
      true,
    );
    await expect(run(session)).rejects.toBeInstanceOf(AmcpAbortedError);
    await expect(run(session)).rejects.toThrow('host-unwitnessed');
  });

  it('a tool aborts on a witness signature that does not verify', async () => {
    const host = new AuditHost('t#w', WITNESSING, undefined, forger);
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', new Deps(), undefined, verify, true);
    await expect(run(session)).rejects.toThrow('host-signature-invalid');
  });

  it('requiring a witness without a verifier is refused', () => {
    expect(
      () =>
        new AmcpSession(new InProcessTransport(new AuditHost('t#d')), 'call-1', new Deps(), undefined, undefined, true),
    ).toThrow('WitnessVerifier');
  });

  it('the witness preimage is the host-assigned fields alone', () => {
    const payload = witnessPayload(0, '2026-07-15T00:00:01.000Z', '0'.repeat(64), 'a'.repeat(64));
    expect(payload.startsWith('{"host_ts":')).toBe(true);
    expect(payload.includes('signature')).toBe(false);
  });
});

describe('verifier conformance for the witness (§11.4)', () => {
  it('a verifier without the registry says the witness was not checked', async () => {
    const host = new AuditHost('t#w', WITNESSING, undefined, signer);
    await run(new AmcpSession(new InProcessTransport(host), 'call-1', new Deps()));
    const report = verifyLedger(host.records());
    expect(report.ok).toBe(true);
    expect(report.unchecked).toEqual(['witness']);
    expect(report.complete).toBe(false);
  });

  it('a verifier with the registry determines the witness', async () => {
    const host = new AuditHost('t#w', WITNESSING, undefined, signer);
    await run(new AmcpSession(new InProcessTransport(host), 'call-1', new Deps()));
    expect(verifyLedger(host.records(), undefined, verify).complete).toBe(true);
  });

  it('an unwitnessed chain is complete without a checker', async () => {
    const host = new AuditHost('t#d');
    await run(new AmcpSession(new InProcessTransport(host), 'call-1', new Deps()));
    expect(verifyLedger(host.records()).complete).toBe(true);
  });

  it('a witness signature that does not verify is reported', async () => {
    const host = new AuditHost('t#w', WITNESSING, undefined, forger);
    await run(new AmcpSession(new InProcessTransport(host), 'call-1', new Deps()));
    const report = verifyLedger(host.records(), undefined, verify);
    expect(report.ok).toBe(false);
    expect(report.issues.every((i) => i.kind === 'host-signature-invalid')).toBe(true);
  });
});
