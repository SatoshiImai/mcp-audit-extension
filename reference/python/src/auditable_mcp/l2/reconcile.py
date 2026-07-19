"""Reconciliation: boundary-observed egress vs self-reported events.

Detects event suppression by comparing independent boundary observations (e.g., from a gateway)
against the tool's self-reported audit stream.
"""

from dataclasses import dataclass

from auditable_mcp.ledger import SealedRecord


@dataclass
class EgressObservation:
    """An egress the host observed independently at the boundary."""

    call_id: str
    destination: str


class BoundaryObserver:
    """Records egress facts the host sees independently (e.g. a gateway)."""

    def __init__(self) -> None:
        """Initialize with no observations."""
        self._observations: list[EgressObservation] = []

    def observe_egress(self, call_id: str, destination: str) -> None:
        """Record an observed egress for a call."""
        self._observations.append(EgressObservation(call_id=call_id, destination=destination))

    def for_call(self, call_id: str) -> list[EgressObservation]:
        """Return the observations recorded for a given call."""
        return [o for o in self._observations if o.call_id == call_id]


@dataclass
class ReconcileAnomaly:
    """A mismatch between self-reports and boundary observations."""

    call_id: str
    kind: str
    destination: str
    detail: str


def reconcile(
    records: list[SealedRecord], observations: list[EgressObservation], call_id: str
) -> list[ReconcileAnomaly]:
    """Compare self-reported egress against boundary observations for a call."""
    reported = {
        r.event['target_resource']['ref'] for r in records if r.event['call_id'] == call_id and r.event['egress']
    }
    observed = {o.destination for o in observations if o.call_id == call_id}

    # Reconciliation detects suppression by omission only (§7.5): an egress the boundary observed
    # but the tool never self-reported. The reverse (self-reported but boundary-unobserved) is not
    # an anomaly - a boundary is not omniscient, so its blind spots are not tool misbehavior.
    anomalies: list[ReconcileAnomaly] = []
    for destination in observed:
        if destination not in reported:
            anomalies.append(
                ReconcileAnomaly(
                    call_id=call_id,
                    kind='unreported-egress',
                    destination=destination,
                    detail='observed egress with no self-report',
                )
            )
    # Set iteration is hash-randomized (PYTHONHASHSEED); sort by destination so each port emits a
    # stable, deterministic ordering. This is not a sealed/conformance surface, so cross-port
    # byte-identical ordering is not required.
    anomalies.sort(key=lambda a: a.destination)
    return anomalies
