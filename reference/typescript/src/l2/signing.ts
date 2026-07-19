import { sign, verify, type KeyObject } from 'node:crypto';
import type { AuditEvent } from '../schema/event.js';
import { canonicalize } from '../ledger/canonical.js';

// L2 signing. The signature covers canonical(event minus signature), so key_id and sequence
// are inside the signed bytes and tampering any field invalidates it.

function signatureInput(event: AuditEvent): Buffer {
  // canonicalize omits undefined-valued keys, so a not-yet-set signature is excluded.
  const { signature: _drop, ...rest } = event;
  void _drop;
  return Buffer.from(canonicalize(rest), 'utf8');
}

export function signEvent(event: AuditEvent, keyId: string, sequence: number, privateKey: KeyObject): AuditEvent {
  const signed: AuditEvent = { ...event, key_id: keyId, sequence };
  const signature = sign(null, signatureInput(signed), privateKey).toString('base64');
  return { ...signed, signature };
}

export function verifyEventSignature(event: AuditEvent, publicKey: KeyObject): boolean {
  if (!event.signature) return false;
  try {
    return verify(null, signatureInput(event), publicKey, Buffer.from(event.signature, 'base64'));
  } catch {
    return false;
  }
}

// Tool-side signer: holds the private key and a monotonic per-tool sequence counter that
// advances across every emitted event, so a suppressed event leaves a detectable gap.
export interface EventSigner {
  sign(event: AuditEvent): AuditEvent;
}

export class Ed25519Signer implements EventSigner {
  private seq = 0;

  constructor(
    private readonly keyId: string,
    private readonly privateKey: KeyObject,
  ) {}

  sign(event: AuditEvent): AuditEvent {
    const signed = signEvent(event, this.keyId, this.seq, this.privateKey);
    this.seq += 1;
    return signed;
  }
}
