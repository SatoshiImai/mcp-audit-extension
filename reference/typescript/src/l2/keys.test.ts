import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { assertDisjointRegistries, generateToolKey, KeyRegistry } from './keys.js';
import { countersignatureCheck, signEvent, verifyDetached, verifyEventSignature } from './signing.js';
import type { AuditEvent } from '../schema/event.js';
import { canonicalize } from '../ledger/canonical.js';

const EVENT: AuditEvent = {
  id: '00000000-0000-4000-8000-000000000001',
  spec_version: 'auditable-mcp/0.3',
  ts: '2026-07-15T00:00:01.000Z',
  session_id: '0198f3a2-5c1e-7000-8000-00000000abc0',
  action_type: 'db.write',
  mutates: true,
  egress: false,
  target_resource: { kind: 'table', ref: 'customers' },
  outcome: 'attempted',
};

describe('key registry entries (§5.1)', () => {
  it('refuses a key whose algorithm disagrees with the entry', () => {
    const registry = new KeyRegistry();
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey;
    expect(() => registry.register('k', p384, 'ES256')).toThrow('not a ES256 public key');
    expect(() => registry.register('k', generateToolKey('k', 'Ed25519').publicKey, 'ES256')).toThrow('not a ES256');
    expect(() => registry.register('k', generateToolKey('k', 'ES256').publicKey, 'Ed25519')).toThrow('not a Ed25519');
    expect(() => registry.register('k', generateToolKey('k').privateKey, 'Ed25519')).toThrow('not a Ed25519');
  });

  it('refuses an empty key_id', () => {
    expect(() => new KeyRegistry().register('', generateToolKey('k').publicKey, 'Ed25519')).toThrow('non-empty');
  });

  it('refuses JWK material of the wrong length, off the curve, or carrying the private half', () => {
    const registry = new KeyRegistry();
    const ed = generateToolKey('ed').publicKey.export({ format: 'jwk' });
    const ec = generateToolKey('ec', 'ES256').publicKey.export({ format: 'jwk' });
    expect(() => registry.registerJwk('a', { ...ed, x: ed.x!.slice(0, -4) }, 'Ed25519')).toThrow('not a valid public key');
    expect(() => registry.registerJwk('b', { ...ec, y: ec.x }, 'ES256')).toThrow('not a valid public key');
    expect(() => registry.registerJwk('c', { ...ed, d: ed.x }, 'Ed25519')).toThrow('private key');
    registry.registerJwk('d', ec, 'ES256');
    expect(registry.get('d')?.alg).toBe('ES256');
  });

  it('binds a key_id to one key for its lifetime (§10.9)', () => {
    const registry = new KeyRegistry();
    const key = generateToolKey('k');
    registry.register('k', key.publicKey, 'Ed25519');
    registry.register('k', key.publicKey, 'Ed25519');
    expect(() => registry.register('k', generateToolKey('k').publicKey, 'Ed25519')).toThrow('already bound');
  });

  it('keeps a revoked entry for historical records, and offers it for nothing new (§10.9)', () => {
    const registry = new KeyRegistry();
    const key = generateToolKey('k');
    registry.register('k', key.publicKey, 'Ed25519');
    const signed = signEvent(EVENT, 'k', 0, 'Ed25519', key.privateKey);
    registry.revoke('k');
    expect(registry.current('k')).toBeUndefined();
    expect(verifyEventSignature(signed, registry.get('k')!)).toBe(true);
  });

  it('a tool refuses a countersignature under a revoked host key; a verifier still checks it (§10.9)', () => {
    const host = generateToolKey('host');
    const registry = new KeyRegistry();
    registry.register('host', host.publicKey, 'Ed25519');
    const payload = '{"seq":0}';
    const signature = sign(null, Buffer.from(payload, 'utf8'), host.privateKey).toString('base64url');
    expect(countersignatureCheck(registry, 'tool')('host', signature, payload)).toBe(true);
    registry.revoke('host');
    expect(countersignatureCheck(registry, 'tool')('host', signature, payload)).toBe(false);
    expect(countersignatureCheck(registry, 'verifier')('host', signature, payload)).toBe(true);
  });

  it('refuses tool and host registries that share a key (§10.9)', () => {
    const key = generateToolKey('k');
    const tools = new KeyRegistry();
    const hosts = new KeyRegistry();
    tools.register('tool', key.publicKey, 'Ed25519');
    hosts.register('host', generateToolKey('h').publicKey, 'Ed25519');
    expect(() => assertDisjointRegistries(tools, hosts)).not.toThrow();
    hosts.register('host-2', key.publicKey, 'Ed25519');
    expect(() => assertDisjointRegistries(tools, hosts)).toThrow('share a key');
  });
});

describe('raw signature encoding (§5.1)', () => {
  it('rejects a DER-encoded ES256 signature that verifies as DER', () => {
    const key = generateToolKey('ec', 'ES256');
    const data = Buffer.from('payload', 'utf8');
    const der = sign('sha256', data, key.privateKey);
    expect(der.length).not.toBe(64);
    expect(verifyDetached('ES256', key.publicKey, data, der)).toBe(false);
    const signed = signEvent(EVENT, 'ec', 0, 'ES256', key.privateKey);
    const { signature: _raw, ...unsigned } = signed;
    void _raw;
    const derOverInput = sign('sha256', Buffer.from(canonicalize(unsigned), 'utf8'), key.privateKey);
    const derSigned = { ...signed, signature: derOverInput.toString('base64url') };
    expect(verifyEventSignature(derSigned, key)).toBe(false);
  });

  it('rejects an Ed25519 signature of the wrong length', () => {
    const key = generateToolKey('ed');
    const data = Buffer.from('payload', 'utf8');
    const good = sign(null, data, key.privateKey);
    expect(verifyDetached('Ed25519', key.publicKey, data, good)).toBe(true);
    expect(verifyDetached('Ed25519', key.publicKey, data, Buffer.concat([good, Buffer.alloc(1)]))).toBe(false);
  });
});
