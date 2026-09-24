import { describe, it, expect } from 'vitest';
import { auditEventSchema, type AuditEvent } from '../schema/event.js';
import { generateToolKey } from './keys.js';
import { signEvent, verifyEventSignature, KeySigner } from './signing.js';

function baseEvent(): AuditEvent {
  return {
    id: '00000000-0000-4000-8000-000000000001',
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

describe('L2 signing', () => {
  it('a signed event verifies against the registered public key', () => {
    const key = generateToolKey('k1');
    const signed = signEvent(baseEvent(), key.keyId, 0, key.alg, key.privateKey);
    expect(signed.signature).toBeTruthy();
    expect(verifyEventSignature(signed, key)).toBe(true);
  });

  it('tampering any signed field invalidates the signature (forgery blocked)', () => {
    const key = generateToolKey('k1');
    const signed = signEvent(baseEvent(), key.keyId, 0, key.alg, key.privateKey);
    const forged: AuditEvent = { ...signed, target_resource: { ...signed.target_resource, ref: 'salaries' } };
    expect(verifyEventSignature(forged, key)).toBe(false);
  });

  it('a different key does not verify', () => {
    const key = generateToolKey('k1');
    const other = generateToolKey('k2');
    const signed = signEvent(baseEvent(), key.keyId, 0, key.alg, key.privateKey);
    expect(verifyEventSignature(signed, other)).toBe(false);
  });

  it('shared schema: an unsigned (L1) event and a signed (L2) event both validate against the one schema', () => {
    const l1 = baseEvent();
    expect(auditEventSchema.safeParse(l1).success).toBe(true);
    expect(l1.signature).toBeUndefined();

    const key = generateToolKey('k1');
    const l2 = signEvent(l1, key.keyId, 7, key.alg, key.privateKey);
    const parsed = auditEventSchema.safeParse(l2);
    expect(parsed.success).toBe(true);
    expect(l2.key_id).toBe('k1');
    expect(l2.signer_seq).toBe(7);
  });

  it('KeySigner stamps a monotonic per-key signer_seq', () => {
    const key = generateToolKey('k1');
    const signer = new KeySigner(key.keyId, key.alg, key.privateKey);
    const a = signer.sign(baseEvent());
    const b = signer.sign({ ...baseEvent(), id: '00000000-0000-4000-8000-000000000002' });
    expect(a.signer_seq).toBe(0);
    expect(b.signer_seq).toBe(1);
    expect(verifyEventSignature(a, key)).toBe(true);
    expect(verifyEventSignature(b, key)).toBe(true);
  });

  it('ECDSA P-256 (KMS/PKI profile) signs and verifies as fixed-length r||s (§5.1)', () => {
    const key = generateToolKey('kms-key', 'ECDSA_P256_SHA256');
    expect(key.alg).toBe('ECDSA_P256_SHA256');
    const signed = signEvent(baseEvent(), key.keyId, 0, key.alg, key.privateKey);
    // IEEE P1363 r||s: 64 raw bytes, not DER, so a foreign verifier decodes it unambiguously.
    expect(Buffer.from(signed.signature ?? '', 'base64')).toHaveLength(64);
    expect(verifyEventSignature(signed, key)).toBe(true);
    const forged: AuditEvent = { ...signed, target_resource: { ...signed.target_resource, ref: 'salaries' } };
    expect(verifyEventSignature(forged, key)).toBe(false);
  });

  it('the verifier dispatches on the key-bound algorithm, so a mixed Ed25519 + ECDSA fleet works', () => {
    const edKey = generateToolKey('ed', 'Ed25519');
    const ecKey = generateToolKey('ec', 'ECDSA_P256_SHA256');
    const edSigned = signEvent(baseEvent(), edKey.keyId, 0, edKey.alg, edKey.privateKey);
    const ecSigned = signEvent(baseEvent(), ecKey.keyId, 0, ecKey.alg, ecKey.privateKey);
    expect(verifyEventSignature(edSigned, edKey)).toBe(true);
    expect(verifyEventSignature(ecSigned, ecKey)).toBe(true);
    // Verifying under the other algorithm's key fails: the algorithm comes from the registry.
    expect(verifyEventSignature(edSigned, ecKey)).toBe(false);
    expect(verifyEventSignature(ecSigned, edKey)).toBe(false);
  });
});
