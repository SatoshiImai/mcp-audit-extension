import { generateKeyPairSync, type KeyObject } from 'node:crypto';

// L2 key material. A tool holds a private key and signs its self-attestations; the host
// verifies against a public key registered out-of-band at onboarding. The signature gives
// non-repudiation, not real-time control.

export interface ToolKey {
  keyId: string;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function generateToolKey(keyId: string): ToolKey {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { keyId, publicKey, privateKey };
}

// Maps key_id -> registered public key. A key_id the host has never onboarded is untrusted:
// its events are rejected as unverifiable (a forged record), never silently accepted.
export class KeyRegistry {
  private readonly keys = new Map<string, KeyObject>();

  register(keyId: string, publicKey: KeyObject): void {
    this.keys.set(keyId, publicKey);
  }

  get(keyId: string): KeyObject | undefined {
    return this.keys.get(keyId);
  }
}
