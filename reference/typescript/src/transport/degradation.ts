import type { NegotiationResult } from '../schema/capability.js';
import type { AuditTransport } from './transport.js';

// What a tool does with a call that is not audit-negotiated (§6.2).
//
// A tool that speaks this extension has to stay usable by hosts that do not, which is nearly every
// MCP host today. For an unnegotiated call it sends no audit message at all - an ordinary host has
// no way to answer one, so a tool that sends anyway fails closed against a peer that has done
// nothing wrong - and serves tools/call exactly as a build without this extension would.
//
// Two postures are admissible. Under `degraded` (the default) the tool serves the call and records
// into an audit host it provides for itself: the recording does not stop, the host's countersignature
// does, and §5.2 makes that legible in the records. Under `mandatory` the tool declines to serve,
// which [SEP-2133] permits for an extension a deployment treats as required.
//
// A third posture - serving the call while recording nothing and reporting nothing about the
// omission - is not conformant, so `transportFor` refuses to return a transport for it.

export const DEGRADED = 'degraded';
export const MANDATORY = 'mandatory';
export type Posture = typeof DEGRADED | typeof MANDATORY;

// The call is not audit-negotiated and the tool's posture is `mandatory` (§6.2).
export class UnnegotiatedCallError extends Error {
  constructor(readonly negotiation: NegotiationResult) {
    super(`call is not audit-negotiated (${negotiation.outcome}); posture is mandatory`);
    this.name = 'UnnegotiatedCallError';
  }
}

// Return the transport §6.2 permits for this call, or refuse to serve it. The degraded posture needs
// somewhere to record; a tool that requires `countersign: "host"` cannot take it at all, because the
// host it provides for itself holds no key a verifier's registry binds to a host (§5.2), so every
// action would abort `host-uncountersigned` (§7.2).
export function transportFor(
  negotiation: NegotiationResult,
  negotiated: AuditTransport,
  fallback?: AuditTransport,
  posture: Posture = DEGRADED,
): AuditTransport {
  if (negotiation.negotiated) return negotiated;
  if (posture === MANDATORY) throw new UnnegotiatedCallError(negotiation);
  if (negotiation.tool.countersign === 'host') {
    throw new Error('a tool that requires countersign "host" cannot degrade; use MANDATORY (§5.2, §6.2)');
  }
  if (fallback === undefined) {
    throw new Error('the degraded posture needs a fallback transport to record into (§6.2)');
  }
  return fallback;
}
