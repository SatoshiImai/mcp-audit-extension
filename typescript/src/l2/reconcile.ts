import type { SealedRecord } from '../ledger/ledger.js';

// Reconciliation cross-checks self-reported audit events against facts the host observes
// independently at the boundary (e.g. a network egress a gateway sees). Its point is the
// tamper-evidence byproduct that matters most: a tool that DOES something and DOESN'T report
// it. An observed egress with no self-report = suppression by omission — the one thing
// signatures and sequence gaps alone cannot catch, because the tool simply never emits.
// This is detection feeding governance (revisit the allowlist), not real-time control.

export interface EgressObservation {
  call_id: string;
  destination: string;
}

export class BoundaryObserver {
  private readonly observations: EgressObservation[] = [];

  observeEgress(callId: string, destination: string): void {
    this.observations.push({ call_id: callId, destination });
  }

  forCall(callId: string): EgressObservation[] {
    return this.observations.filter((o) => o.call_id === callId);
  }
}

export interface ReconcileAnomaly {
  call_id: string;
  kind: 'unreported-egress' | 'unobserved-egress';
  destination: string;
  detail: string;
}

export function reconcile(
  records: readonly SealedRecord[],
  observations: readonly EgressObservation[],
  callId: string,
): ReconcileAnomaly[] {
  // Self-reported egress destinations for this call (dedup across attempt/outcome by id).
  const reported = new Set<string>();
  for (const r of records) {
    if (r.event.call_id === callId && r.event.egress) reported.add(r.event.target_resource.ref);
  }
  const observed = new Set(observations.filter((o) => o.call_id === callId).map((o) => o.destination));

  const anomalies: ReconcileAnomaly[] = [];
  for (const dest of observed) {
    if (!reported.has(dest)) {
      // The killer case: the tool egressed and hid it.
      anomalies.push({ call_id: callId, kind: 'unreported-egress', destination: dest, detail: 'observed egress with no self-report' });
    }
  }
  for (const dest of reported) {
    if (!observed.has(dest)) {
      anomalies.push({ call_id: callId, kind: 'unobserved-egress', destination: dest, detail: 'self-reported egress not observed at boundary' });
    }
  }
  return anomalies;
}
