"""Reconciliation: boundary-observed egress vs self-reported events.

An observed egress with no self-report is suppression by omission -- the one lie signatures
and sequence gaps cannot catch, because the tool simply never emits. This is detection
feeding governance (revisit the allowlist), not real-time control.
"""

from dataclasses import dataclass

from auditable_mcp.ledger import SealedRecord


@dataclass
class EgressObservation:
    """An egress the host observed independently at the boundary."""

    call_id: str
    destination: str
    # end class


class BoundaryObserver:
    """Records egress facts the host sees independently (e.g. a gateway)."""

    def __init__(self) -> None:
        """Initialize with no observations."""
        self._observations: list[EgressObservation] = []
        # end def

    def observe_egress(self, call_id: str, destination: str) -> None:
        """Record an observed egress for a call."""
        self._observations.append(EgressObservation(call_id=call_id, destination=destination))
        # end def

    def for_call(self, call_id: str) -> list[EgressObservation]:
        """Return the observations recorded for a given call."""
        return [o for o in self._observations if o.call_id == call_id]
        # end def

    # end class


@dataclass
class ReconcileAnomaly:
    """A mismatch between self-reports and boundary observations."""

    call_id: str
    kind: str
    destination: str
    detail: str
    # end class


def reconcile(
    records: list[SealedRecord], observations: list[EgressObservation], call_id: str
) -> list[ReconcileAnomaly]:
    """Compare self-reported egress against boundary observations for a call."""
    reported = {
        r.event['target_resource']['ref'] for r in records if r.event['call_id'] == call_id and r.event['egress']
    }
    observed = {o.destination for o in observations if o.call_id == call_id}

    anomalies: list[ReconcileAnomaly] = []
    for destination in observed:
        if destination not in reported:
            # The killer case: the tool egressed and hid it.
            anomalies.append(
                ReconcileAnomaly(
                    call_id=call_id,
                    kind='unreported-egress',
                    destination=destination,
                    detail='observed egress with no self-report',
                )
            )
            # end if
        # end for
    for destination in reported:
        if destination not in observed:
            anomalies.append(
                ReconcileAnomaly(
                    call_id=call_id,
                    kind='unobserved-egress',
                    destination=destination,
                    detail='self-reported egress not observed at boundary',
                )
            )
            # end if
        # end for
    return anomalies
    # end def
