import { sign, verify, type KeyObject } from 'node:crypto';
import type { AuditEvent } from '../schema/event.js';
import { canonicalize } from '../ledger/canonical.js';
import type { KeyRegistry, RegisteredKey, SignatureAlg } from './keys.js';

// L2 signing. The signature covers canonical(event minus signature), so key_id and signer_seq are
// inside the signed bytes and tampering any field invalidates it.

function signatureInput(event: AuditEvent): Buffer {
  // canonicalize omits undefined-valued keys, so a not-yet-set signature is excluded.
  const { signature: _drop, ...rest } = event;
  void _drop;
  return Buffer.from(canonicalize(rest), 'utf8');
}

// Raw detached signing/verification dispatched on the key's algorithm (§5.1). Both algorithms
// produce a fixed-length raw signature carried as base64url without padding, as JWS writes one:
// Ed25519 is 64 bytes; ES256 is the r||s form (64 bytes), not DER, so the wire signature is one
// unambiguous encoding a foreign verifier decodes without guessing.
function signBytes(alg: SignatureAlg, data: Buffer, privateKey: KeyObject): Buffer {
  if (alg === 'Ed25519') return sign(null, data, privateKey);
  return sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
}

// Both algorithms produce exactly 64 raw bytes (§5.1); anything else - a DER-encoded ECDSA signature
// among them - fails verification rather than being reinterpreted.
const RAW_SIGNATURE_BYTES = 64;

export function verifyDetached(alg: SignatureAlg, publicKey: KeyObject, data: Buffer, sig: Buffer): boolean {
  if (sig.length !== RAW_SIGNATURE_BYTES) return false;
  try {
    if (alg === 'Ed25519') return verify(null, data, publicKey, sig);
    return verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig);
  } catch {
    return false;
  }
}

export function signEvent(
  event: AuditEvent,
  keyId: string,
  signerSeq: number,
  alg: SignatureAlg,
  privateKey: KeyObject,
): AuditEvent {
  const signed: AuditEvent = { ...event, key_id: keyId, signer_seq: signerSeq };
  const signature = signBytes(alg, signatureInput(signed), privateKey).toString('base64url');
  return { ...signed, signature };
}

// Verify against the registered key, dispatching on its bound algorithm (§7.4). `decode` reads the
// signature field; records of versions before 0.3 encoded it as padded standard base64 (§11.4).
export function verifyEventSignature(
  event: AuditEvent | Record<string, unknown>,
  key: Pick<RegisteredKey, 'publicKey' | 'alg'>,
  decode: (value: string) => Buffer | undefined = decodeBase64url,
): boolean {
  const signature = (event as { signature?: unknown }).signature;
  if (typeof signature !== 'string' || signature.length === 0) return false;
  const raw = decode(signature);
  if (raw === undefined) return false;
  let input: Buffer;
  try {
    input = signatureInput(event as AuditEvent);
  } catch {
    return false;
  }
  return verifyDetached(key.alg, key.publicKey, input, raw);
}

// A countersignature check over a host-key registry (§7.2, §11.4). A tool accepts only a key that is
// registered and not revoked, since a revoked key confirms nothing new; a verifier checks a sealed
// record against a revoked entry as before (§10.9).
export function countersignatureCheck(
  hostRegistry: KeyRegistry,
  purpose: 'tool' | 'verifier',
): (hostKeyId: string, signature: string, payload: string) => boolean {
  return (hostKeyId, signature, payload) => {
    const entry = purpose === 'tool' ? hostRegistry.current(hostKeyId) : hostRegistry.get(hostKeyId);
    const raw = decodeBase64url(signature);
    return entry !== undefined && raw !== undefined && verifyDetached(entry.alg, entry.publicKey, Buffer.from(payload, 'utf8'), raw);
  };
}

// Strict base64url without padding (§5.1). Node's decoder skips characters outside the alphabet
// rather than refusing them, so the input is checked against the alphabet and the round trip first.
export function decodeBase64url(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return undefined;
  const raw = Buffer.from(value, 'base64url');
  return raw.toString('base64url') === value ? raw : undefined;
}

// Strict padded standard base64, the signature encoding of versions before 0.3.
export function decodeBase64(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return undefined;
  const raw = Buffer.from(value, 'base64');
  return raw.toString('base64') === value ? raw : undefined;
}

// Tool-side signer: holds the private key and numbers the events it signs per audit session, from
// 0 (§7.4). A suppressed event leaves a gap in its session's sequence.
export interface EventSigner {
  sign(event: AuditEvent): AuditEvent;
}

export class KeySigner implements EventSigner {
  private readonly next = new Map<string, number>();

  constructor(
    private readonly keyId: string,
    private readonly alg: SignatureAlg,
    private readonly privateKey: KeyObject,
  ) {}

  // Nothing here awaits, so numbering and emission are one step and §7.4's atomic numbering holds
  // by construction; a signer that awaits (a KMS call) holds a per-session lock across the same span.
  sign(event: AuditEvent): AuditEvent {
    const signerSeq = this.next.get(event.session_id) ?? 0;
    const signed = signEvent(event, this.keyId, signerSeq, this.alg, this.privateKey);
    this.next.set(event.session_id, signerSeq + 1);
    return signed;
  }
}
