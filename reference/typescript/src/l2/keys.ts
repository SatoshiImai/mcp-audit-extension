import { createPublicKey, generateKeyPairSync, type JsonWebKey, type KeyObject } from 'node:crypto';

// L2 key material. A tool holds a private key and signs its self-attestations; the host verifies
// against a public key registered out-of-band at onboarding. The signature gives non-repudiation,
// not real-time control.

// Signature algorithms defined by the spec (§5.1): the fully-specified JOSE names (RFC 9864). The
// algorithm is bound to the key_id by the registry, not carried in the event, so a host verifies a
// mixed fleet without an in-band algorithm.
export type SignatureAlg = 'Ed25519' | 'ES256';

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

// A registered key binds a public key to its algorithm (§5.1). A revoked entry stays in the registry:
// records sealed while the key was valid still verify against it, and nothing new is accepted under
// it (§10.9).
export interface RegisteredKey {
  publicKey: KeyObject;
  alg: SignatureAlg;
  revoked: boolean;
}

// Whether a public key is a key of the algorithm (§5.1). Node refuses a JWK whose material has the
// wrong length or is not a point on the curve when it builds the KeyObject, so what is left to check
// here is the key type and the curve.
function isKeyOf(publicKey: KeyObject, alg: SignatureAlg): boolean {
  if (publicKey.type !== 'public') return false;
  if (alg === 'Ed25519') return publicKey.asymmetricKeyType === 'ed25519';
  return publicKey.asymmetricKeyType === 'ec' && publicKey.asymmetricKeyDetails?.namedCurve === 'prime256v1';
}

function spki(publicKey: KeyObject): string {
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

// Maps key_id -> registered key. A key_id the host has never onboarded is untrusted: its events are
// rejected as unverifiable, never silently accepted.
export class KeyRegistry {
  private readonly keys = new Map<string, RegisteredKey>();

  // §5.1: an entry binds a non-empty key_id to one algorithm and a key of that algorithm; one whose
  // key and algorithm disagree is refused here, not carried to verification time, where every event
  // bound to it would fail as `signature-invalid` - a forged signature, a different fact from a
  // misprovisioned registry. §10.9: a key_id binds one key for its lifetime.
  register(keyId: string, publicKey: KeyObject, alg: SignatureAlg): void {
    if (keyId.length === 0) throw new Error('a registry entry binds a non-empty key_id (§5.1)');
    if (!isKeyOf(publicKey, alg)) throw new Error(`the key registered as ${keyId} is not a ${alg} public key (§5.1)`);
    const existing = this.keys.get(keyId);
    if (existing !== undefined && (existing.alg !== alg || spki(existing.publicKey) !== spki(publicKey))) {
      throw new Error(`${keyId} is already bound to another key (§10.9)`);
    }
    if (existing === undefined) this.keys.set(keyId, { publicKey, alg, revoked: false });
  }

  // A public JWK (RFC 7517), the form a registry is commonly provisioned from (§5.1).
  registerJwk(keyId: string, jwk: JsonWebKey, alg: SignatureAlg): void {
    if (jwk.d !== undefined) throw new Error(`the JWK registered as ${keyId} carries a private key`);
    let publicKey: KeyObject;
    try {
      publicKey = createPublicKey({ key: jwk, format: 'jwk' });
    } catch (err) {
      throw new Error(`the JWK registered as ${keyId} is not a valid public key (§5.1)`, { cause: err });
    }
    this.register(keyId, publicKey, alg);
  }

  revoke(keyId: string): void {
    const entry = this.keys.get(keyId);
    if (entry === undefined) throw new Error(`${keyId} is not registered`);
    entry.revoked = true;
  }

  // The entry, revoked or not: a verifier checks a sealed record against a revoked entry (§10.9).
  get(keyId: string): RegisteredKey | undefined {
    return this.keys.get(keyId);
  }

  // The entry an event arriving now may be accepted under: a revoked key confirms nothing new (§10.9).
  current(keyId: string): RegisteredKey | undefined {
    const entry = this.keys.get(keyId);
    return entry === undefined || entry.revoked ? undefined : entry;
  }

  sharesKeyWith(other: KeyRegistry): boolean {
    const mine = new Set([...this.keys.values()].map((entry) => spki(entry.publicKey)));
    return [...other.keys.values()].some((entry) => mine.has(spki(entry.publicKey)));
  }
}

// §10.9: a key registered for a tool is never also registered for a host. A tool holding a key the
// countersignature registry binds to a host would manufacture the countersigned state (§5.2).
export function assertDisjointRegistries(tool: KeyRegistry, host: KeyRegistry): void {
  if (tool.sharesKeyWith(host)) throw new Error('the tool and host registries share a key (§10.9)');
}
