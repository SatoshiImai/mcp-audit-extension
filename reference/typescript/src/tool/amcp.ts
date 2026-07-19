import { SPEC_VERSION, type AuditEvent } from '../schema/event.js';
import { hashCanonical } from '../ledger/canonical.js';
import { computeRecordHash } from '../ledger/ledger.js';
import type { AttemptResponse, AuditTransport } from '../transport/transport.js';
import type { EventSigner } from '../l2/signing.js';

// Tool-side audit-before-act (§6): emit attempt, await durable accept, perform the domain
// action, emit outcome. reject or unavailable => action not performed.

// Effect axis (§4.2). Both flags declared per operation; action_type is opaque, so no inference.
export interface Effect {
  mutates: boolean;
  egress: boolean;
}

// Tool-side fail-closed halt: the tool did not perform the domain action (outcome=aborted). Named
// for the tool's own abort, not host "blocking" - the host never prevents a domain action (§2).
export class AmcpAbortedError extends Error {
  constructor(
    readonly action_type: string,
    readonly target_ref: string,
    readonly reason: string,
  ) {
    super(`auditable-mcp aborted ${action_type} on ${target_ref}: ${reason}`);
    this.name = 'AmcpAbortedError';
  }
}

export interface ActionSpec {
  action_type: string;
  target_resource: AuditEvent['target_resource'];
  effect: Effect;
  // Confidentiality is the tool's choice (§4.3): disclose cleartext, seal a hash, both, or neither.
  disclose?: Record<string, unknown>; // -> event.action_context
  commit?: unknown; // -> event.action_context_hash = sha256(canonical(commit))
}

export interface AmcpDeps {
  newId: () => string;
  now: () => string; // ISO datetime
}

export class AmcpSession {
  constructor(
    private readonly transport: AuditTransport,
    private readonly callId: string,
    private readonly deps: AmcpDeps,
    // Signer presence is the only L1/L2 emission difference (§5).
    private readonly signer?: EventSigner,
  ) {}

  private stamp(event: AuditEvent): AuditEvent {
    return this.signer ? this.signer.sign(event) : event;
  }

  // Wrap one domain operation in audit-before-act (§6).
  async audited<T>(spec: ActionSpec, perform: () => Promise<T>): Promise<T> {
    const base = {
      id: this.deps.newId(),
      spec_version: SPEC_VERSION,
      ts: this.deps.now(),
      call_id: this.callId,
      action_type: spec.action_type,
      mutates: spec.effect.mutates,
      egress: spec.effect.egress,
      target_resource: spec.target_resource,
      ...(spec.disclose !== undefined ? { action_context: spec.disclose } : {}),
      ...(spec.commit !== undefined ? { action_context_hash: hashCanonical(spec.commit) } : {}),
    } as const;

    const attempt = this.stamp({ ...base, outcome: 'attempted' });
    const resp: AttemptResponse = await this.transport.sendAttempt(attempt);
    if (resp.status !== 'accept') {
      // reject (invalid/forged) or unavailable (not persisted): do not act; signal aborted (§11.3).
      const reason = resp.status === 'reject' ? 'host-rejected' : 'host-unavailable';
      await this.transport.sendOutcome(this.stamp({ ...base, outcome: 'aborted', reason }));
      throw new AmcpAbortedError(spec.action_type, spec.target_resource.ref, reason);
    }

    // Polluted Stop (§7.2): MUST under L2 (signer present), OPTIONAL under L1. Recompute
    // record_hash over the attempt bytes; mismatch means the host sealed a different record.
    if (this.signer) {
      const expected = computeRecordHash(attempt, resp.seq, resp.host_ts, resp.previous_hash);
      if (expected !== resp.record_hash) {
        await this.transport.sendOutcome(this.stamp({ ...base, outcome: 'aborted', reason: 'hash-mismatch' }));
        throw new AmcpAbortedError(spec.action_type, spec.target_resource.ref, 'hash-mismatch');
      }
    }

    try {
      const result = await perform();
      await this.transport.sendOutcome(this.stamp({ ...base, id: attempt.id, outcome: 'success' }));
      return result;
    } catch (err) {
      await this.transport.sendOutcome(this.stamp({ ...base, id: attempt.id, outcome: 'failed' }));
      throw err;
    }
  }
}

// Deterministic deps for reproducible test vectors: no wall clock, no random uuid.
export function deterministicDeps(): AmcpDeps {
  let n = 0;
  return {
    newId: () => {
      n += 1;
      // uuid-shaped id to satisfy the schema uuid() check.
      const h = n.toString(16).padStart(12, '0');
      return `00000000-0000-4000-8000-${h}`;
    },
    now: () => {
      // Fixed base + counter; stable ts across runs.
      const secs = 1000 + n;
      return new Date(secs * 1000).toISOString();
    },
  };
}
