import { sign, verify, type KeyObject } from 'node:crypto';
import type { AuditEvent } from '../schema/event.js';
import { canonicalize } from '../ledger/canonical.js';
import type { RegisteredKey, SignatureAlg } from './keys.js';

// L2 signing. The signature covers canonical(event minus signature), so key_id and signer_seq are
// inside the signed bytes and tampering any field invalidates it.

function signatureInput(event: AuditEvent): Buffer {
  // canonicalize omits undefined-valued keys, so a not-yet-set signature is excluded.
  const { signature: _drop, ...rest } = event;
  void _drop;
  return Buffer.from(canonicalize(rest), 'utf8');
}

// Raw detached signing/verification dispatched on the key's algorithm (§5.1). Both algorithms
// produce a fixed-length raw signature carried as standard base64: Ed25519 is 64 bytes; ECDSA
// P-256 uses the IEEE P1363 r||s form (64 bytes), not DER, so the wire signature is one unambiguous
// encoding a foreign verifier decodes without guessing.
function signBytes(alg: SignatureAlg, data: Buffer, privateKey: KeyObject): Buffer {
  if (alg === 'Ed25519') return sign(null, data, privateKey);
  return sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
}

function verifyBytes(alg: SignatureAlg, data: Buffer, publicKey: KeyObject, sig: Buffer): boolean {
  if (alg === 'Ed25519') return verify(null, data, publicKey, sig);
  return verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig);
}

export function signEvent(
  event: AuditEvent,
  keyId: string,
  signerSeq: number,
  alg: SignatureAlg,
  privateKey: KeyObject,
): AuditEvent {
  const signed: AuditEvent = { ...event, key_id: keyId, signer_seq: signerSeq };
  const signature = signBytes(alg, signatureInput(signed), privateKey).toString('base64');
  return { ...signed, signature };
}

// Verify against the registered key, dispatching on its bound algorithm (§7.4).
export function verifyEventSignature(event: AuditEvent, key: RegisteredKey): boolean {
  if (!event.signature) return false;
  try {
    return verifyBytes(key.alg, signatureInput(event), key.publicKey, Buffer.from(event.signature, 'base64'));
  } catch {
    return false;
  }
}

// Tool-side signer: holds the private key and a monotonic per-key signer_seq counter that advances
// across every emitted event, so a suppressed event leaves a detectable gap.
export interface EventSigner {
  sign(event: AuditEvent): AuditEvent;
}

export class KeySigner implements EventSigner {
  private seq = 0;

  constructor(
    private readonly keyId: string,
    private readonly alg: SignatureAlg,
    private readonly privateKey: KeyObject,
  ) {}

  sign(event: AuditEvent): AuditEvent {
    const signed = signEvent(event, this.keyId, this.seq, this.alg, this.privateKey);
    this.seq += 1;
    return signed;
  }
}
