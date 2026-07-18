import { describe, it, expect } from 'vitest';
import { auditEventSchema, type AuditEvent } from '../schema/event.js';
import { generateToolKey } from './keys.js';
import { signEvent, verifyEventSignature, Ed25519Signer } from './signing.js';

function baseEvent(): AuditEvent {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    spec_version: 'auditable-mcp/0.1',
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

describe('L2 signing', () => {
  it('a signed event verifies against the registered public key', () => {
    const key = generateToolKey('k1');
    const signed = signEvent(baseEvent(), key.keyId, 0, key.privateKey);
    expect(signed.signature).toBeTruthy();
    expect(verifyEventSignature(signed, key.publicKey)).toBe(true);
  });

  it('tampering any signed field invalidates the signature (forgery blocked)', () => {
    const key = generateToolKey('k1');
    const signed = signEvent(baseEvent(), key.keyId, 0, key.privateKey);
    const forged: AuditEvent = { ...signed, target_resource: { ...signed.target_resource, ref: 'salaries' } };
    expect(verifyEventSignature(forged, key.publicKey)).toBe(false);
  });

  it('a different key does not verify', () => {
    const key = generateToolKey('k1');
    const other = generateToolKey('k2');
    const signed = signEvent(baseEvent(), key.keyId, 0, key.privateKey);
    expect(verifyEventSignature(signed, other.publicKey)).toBe(false);
  });

  it('L1 ⊆ L2: an unsigned (L1) event and a signed (L2) event both validate against the one schema', () => {
    const l1 = baseEvent();
    expect(auditEventSchema.safeParse(l1).success).toBe(true);
    expect(l1.signature).toBeUndefined();

    const key = generateToolKey('k1');
    const l2 = signEvent(l1, key.keyId, 7, key.privateKey);
    const parsed = auditEventSchema.safeParse(l2);
    expect(parsed.success).toBe(true);
    expect(l2.key_id).toBe('k1');
    expect(l2.sequence).toBe(7);
  });

  it('Ed25519Signer stamps a monotonic per-tool sequence', () => {
    const key = generateToolKey('k1');
    const signer = new Ed25519Signer(key.keyId, key.privateKey);
    const a = signer.sign(baseEvent());
    const b = signer.sign({ ...baseEvent(), id: '00000000-0000-4000-8000-000000000002' });
    expect(a.sequence).toBe(0);
    expect(b.sequence).toBe(1);
    expect(verifyEventSignature(a, key.publicKey)).toBe(true);
    expect(verifyEventSignature(b, key.publicKey)).toBe(true);
  });
});
