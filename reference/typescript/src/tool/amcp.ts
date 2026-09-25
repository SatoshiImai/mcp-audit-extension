import { SPEC_VERSION, type AuditEvent } from '../schema/event.js';
import { hashCanonical } from '../ledger/canonical.js';
import { computeRecordHash, countersignaturePayload } from '../ledger/ledger.js';
import type { AttemptResponse, AuditTransport } from '../transport/transport.js';
import type { EventSigner } from '../l2/signing.js';
import { AuditAttemptResultSchema } from '../transport/mcpWire.js';

type AbortReason = NonNullable<AuditEvent['reason']>;
type EventOf = (outcome: AuditEvent['outcome'], reason?: AbortReason) => AuditEvent;

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

// Resolves a `host_key_id` and verifies a countersignature over the host-assigned fields and log_id (§7.2).
export type CountersignatureVerifier = (hostKeyId: string, signature: string, payload: string) => boolean;

export class AmcpSession {
  constructor(
    private readonly transport: AuditTransport,
    // The audit session the host issued for this call (§6.3), carried verbatim in every event.
    private readonly sessionId: string,
    private readonly deps: AmcpDeps,
    // Signer presence is the only L1/L2 emission difference (§5).
    private readonly signer?: EventSigner,
    // A tool that requires `countersign: "host"` (§5.2) verifies every accept and aborts rather than
    // act on a record no distinct party confirmed (§7.2). Requiring it without a verifier would
    // abort every action against a host that is signing correctly, so the pairing is enforced.
    private readonly countersignatureVerifier?: CountersignatureVerifier,
    private readonly requireCountersign = false,
    // How many times the identical attempt is sent again after `unavailable` or no answer (§7.1).
    private readonly attemptRetries = 0,
  ) {
    if (requireCountersign && countersignatureVerifier === undefined) {
      throw new Error('requireCountersign needs a CountersignatureVerifier (§7.2, §11.3)');
    }
  }

  private stamp(event: AuditEvent): AuditEvent {
    return this.signer ? this.signer.sign(event) : event;
  }

  // One Attempt Response, or undefined when the attempt went unanswered: a transport fault, a
  // protocol error, or an answer that does not validate against the Attempt Response schema - a
  // partial countersignature triple among them - is not an Attempt Response (§6).
  private async ask(attempt: AuditEvent): Promise<AttemptResponse | undefined> {
    let answer: unknown;
    try {
      answer = await this.transport.sendAttempt(attempt);
    } catch {
      return undefined;
    }
    const parsed = AuditAttemptResultSchema.safeParse(answer);
    return parsed.success ? (answer as AttemptResponse) : undefined;
  }

  private async abort(event: EventOf, spec: ActionSpec, reason: AbortReason): Promise<never> {
    await this.transport.sendOutcome(this.stamp(event('aborted', reason)));
    throw new AmcpAbortedError(spec.action_type, spec.target_resource.ref, reason);
  }

  // Wrap one domain operation in audit-before-act (§6). `perform` runs at most once, and only after an
  // accept that passed every check of §7.2 (§6).
  async audited<T>(spec: ActionSpec, perform: () => Promise<T>): Promise<T> {
    const head = {
      id: this.deps.newId(),
      spec_version: SPEC_VERSION,
      ts: this.deps.now(),
      session_id: this.sessionId,
      action_type: spec.action_type,
      mutates: spec.effect.mutates,
      egress: spec.effect.egress,
      target_resource: spec.target_resource,
    } as const;
    const context = {
      ...(spec.disclose !== undefined ? { action_context: spec.disclose } : {}),
      ...(spec.commit !== undefined ? { action_context_hash: hashCanonical(spec.commit) } : {}),
    };
    // Members in the order the schema lists them.
    const event: EventOf = (outcome, reason) => ({ ...head, outcome, ...(reason !== undefined ? { reason } : {}), ...context });

    // Signed once: a retry sends the byte-identical attempt, which keeps its signer_seq (§6, §7.1).
    const attempt = this.stamp(event('attempted'));
    let resp = await this.ask(attempt);
    for (let retry = 0; retry < this.attemptRetries && (resp === undefined || resp.status === 'unavailable'); retry += 1) {
      resp = await this.ask(attempt);
    }
    if (resp === undefined || resp.status !== 'accept') {
      // reject, unavailable, or unanswered: do not act; signal aborted (§7.2).
      return this.abort(event, spec, resp?.status === 'reject' ? 'host-rejected' : 'host-unavailable');
    }

    // §7.2 evaluates in precedence order: the response's status above, then the countersignature
    // that authenticates the host-assigned fields, then the hash computed over them. The reason is
    // sealed into the ledger and compared across implementations, so the order is not incidental.
    if (this.requireCountersign && resp.host_signature === undefined) {
      return this.abort(event, spec, 'host-uncountersigned');
    }
    if (resp.host_signature !== undefined && this.countersignatureVerifier !== undefined) {
      const payload = countersignaturePayload(resp.seq, resp.host_ts, resp.log_id as string, resp.previous_hash, resp.record_hash);
      if (!this.countersignatureVerifier(resp.host_key_id as string, resp.host_signature, payload)) {
        return this.abort(event, spec, 'host-signature-invalid');
      }
    }

    // Polluted Stop (§7.2): MUST under L2 (signer present) and wherever a countersignature is
    // required, OPTIONAL otherwise. The countersignature binds the host-assigned fields to
    // record_hash and no further; recomputing record_hash over the attempt bytes is what binds it
    // to this attempt, so an accept for another record is refused.
    if (this.signer !== undefined || this.requireCountersign) {
      const expected = computeRecordHash(attempt, resp.seq, resp.host_ts, resp.previous_hash);
      if (expected !== resp.record_hash) return this.abort(event, spec, 'hash-mismatch');
    }

    let result: T;
    try {
      result = await perform();
    } catch (err) {
      await this.emitOutcome(event('failed'));
      throw err;
    }
    // Outside the `try`: an action that was performed is never recorded `failed`, and a lost outcome is a
    // completeness gap the host resolves (§10.8), not the caller's error to retry.
    await this.emitOutcome(event('success'));
    return result;
  }

  /** Send a terminal outcome, logging rather than throwing if it cannot be delivered (§6, §10.8). */
  private async emitOutcome(outcome: AuditEvent): Promise<void> {
    try {
      await this.transport.sendOutcome(this.stamp(outcome));
    } catch (err) {
      console.error(`could not deliver the ${outcome.outcome} outcome of ${outcome.id}; it is lost`, err);
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
