import { SPEC_VERSION, type AuditEvent } from '../schema/event.js';
import { resolveEffect, type Effect } from '../schema/actionType.js';
import { hashParams } from '../ledger/canonical.js';
import type { AttemptResponse, AuditTransport } from '../transport/transport.js';
import type { EventSigner } from '../l2/signing.js';

// Tool-side A-MCP library. Implements audit-before-act: emit `attempt`, await a durable
// accept, only THEN perform the internal domain action, then emit the outcome. If the
// record is rejected (a lie) or unavailable (infra), the action is not performed —
// fail-closed on record completeness, not on action authorization (design §6.1).

export class AmcpBlockedError extends Error {
  constructor(
    readonly action_type: string,
    readonly target_ref: string,
    readonly reason: string,
  ) {
    super(`a-mcp blocked ${action_type} on ${target_ref}: ${reason}`);
    this.name = 'AmcpBlockedError';
  }
}

export interface ActionSpec {
  action_type: string;
  target_resource: AuditEvent['target_resource'];
  params: unknown; // hashed, never stored raw
  effect?: Partial<Effect>; // self-declared; resolved with fail-safe floor
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
    // Optional signer. Its presence is the ONLY difference between L1 and L2 emission —
    // the audit-before-act logic below is identical (design INV-1, portable escalation).
    private readonly signer?: EventSigner,
  ) {}

  private stamp(event: AuditEvent): AuditEvent {
    return this.signer ? this.signer.sign(event) : event;
  }

  // Wrap one internal domain operation in the audit-before-act discipline.
  async audited<T>(spec: ActionSpec, perform: () => Promise<T>): Promise<T> {
    const effect = resolveEffect(spec.action_type, spec.effect);
    const base = {
      id: this.deps.newId(),
      spec_version: SPEC_VERSION,
      ts: this.deps.now(),
      call_id: this.callId,
      action_type: spec.action_type,
      mutates: effect.mutates,
      egress: effect.egress,
      target_resource: spec.target_resource,
      params_hash: hashParams(spec.params),
    } as const;

    const attempt = this.stamp({ ...base, outcome: 'attempted' });
    const resp: AttemptResponse = await this.transport.sendAttempt(attempt);
    if (resp.status !== 'accept') {
      // No valid record → do NOT perform the action.
      throw new AmcpBlockedError(spec.action_type, spec.target_resource.ref, resp.reason);
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

// Deterministic deps for reproducible test vectors (no wall clock / random uuid).
export function deterministicDeps(prefix = 'ev'): AmcpDeps {
  let n = 0;
  return {
    newId: () => {
      n += 1;
      // uuid-shaped deterministic id so it satisfies the schema's uuid() check.
      const h = n.toString(16).padStart(12, '0');
      return `00000000-0000-4000-8000-${h}`;
    },
    now: () => {
      // Fixed base + counter keeps ts stable across runs.
      const secs = 1000 + n;
      return new Date(secs * 1000).toISOString();
    },
  };
}
