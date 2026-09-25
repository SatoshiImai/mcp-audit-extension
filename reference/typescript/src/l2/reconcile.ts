import type { SealedRecord } from '../ledger/ledger.js';

// Reconciliation cross-checks self-reported audit events against facts the host observes
// independently at the boundary (e.g. an egress a gateway sees). An observed egress with no
// self-report is a suppression that signatures and sequence gaps cannot catch, since the
// tool never emits the event.

export interface EgressObservation {
  session_id: string;
  destination: string;
}

export class BoundaryObserver {
  private readonly observations: EgressObservation[] = [];

  observeEgress(sessionId: string, destination: string): void {
    this.observations.push({ session_id: sessionId, destination });
  }

  forSession(sessionId: string): EgressObservation[] {
    return this.observations.filter((o) => o.session_id === sessionId);
  }
}

export interface ReconcileAnomaly {
  session_id: string;
  kind: 'unreported-egress';
  destination: string;
  detail: string;
}

export function reconcile(
  records: readonly SealedRecord[],
  observations: readonly EgressObservation[],
  sessionId: string,
): ReconcileAnomaly[] {
  // Self-reported egress destinations for this call (dedup by target ref across attempt/outcome).
  const reported = new Set<string>();
  for (const r of records) {
    if (r.event.session_id === sessionId && r.event.egress) reported.add(r.event.target_resource.ref);
  }
  const observed = new Set(observations.filter((o) => o.session_id === sessionId).map((o) => o.destination));

  // Reconciliation detects suppression by omission only (§7.5): an egress the boundary observed
  // but the tool never self-reported. The reverse (self-reported but boundary-unobserved) is not
  // an anomaly - a boundary is not omniscient, so its blind spots are not tool misbehavior.
  const anomalies: ReconcileAnomaly[] = [];
  for (const dest of observed) {
    if (!reported.has(dest)) {
      anomalies.push({ session_id: sessionId, kind: 'unreported-egress', destination: dest, detail: 'observed egress with no self-report' });
    }
  }
  // Python set iteration is hash-randomized; sort by destination so each port emits a stable,
  // deterministic ordering. This is not a sealed/conformance surface, so cross-port byte-identical
  // ordering is not required (JS UTF-16-unit vs Python code-point order differ only for astral
  // characters, which do not occur in egress destinations).
  anomalies.sort((a, b) => (a.destination < b.destination ? -1 : a.destination > b.destination ? 1 : 0));
  return anomalies;
}
