import { generateKeyPairSync, type KeyObject } from 'node:crypto';

// L2 key material. A tool holds a private key and signs its self-attestations; the host verifies
// against a public key registered out-of-band at onboarding. The signature gives non-repudiation,
// not real-time control.

// Signature algorithms defined by the spec (§5.1). The algorithm is bound to the key_id by the
// registry, not carried in the event, so a host verifies a mixed fleet without an in-band alg.
export type SignatureAlg = 'Ed25519' | 'ECDSA_P256_SHA256';

export interface ToolKey {
  keyId: string;
  alg: SignatureAlg;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function generateToolKey(keyId: string, alg: SignatureAlg = 'Ed25519'): ToolKey {
  const { publicKey, privateKey } =
    alg === 'Ed25519' ? generateKeyPairSync('ed25519') : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { keyId, alg, publicKey, privateKey };
}

// A registered key binds a public key to its algorithm (§5.1).
export interface RegisteredKey {
  publicKey: KeyObject;
  alg: SignatureAlg;
}

// Maps key_id -> registered key (public key + algorithm). A key_id the host has never onboarded is
// untrusted: its events are rejected as unverifiable (a forged record), never silently accepted.
export class KeyRegistry {
  private readonly keys = new Map<string, RegisteredKey>();

  register(keyId: string, publicKey: KeyObject, alg: SignatureAlg): void {
    this.keys.set(keyId, { publicKey, alg });
  }

  get(keyId: string): RegisteredKey | undefined {
    return this.keys.get(keyId);
  }
}
