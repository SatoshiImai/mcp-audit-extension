"""Host-side audit subsystem (a monitoring camera, not a control point).

Receives self-attested events, decides accept/reject/unavailable, and seals accepted records
into the tamper-evident ledger. It never authorizes the tool's domain action (that is the
allowlist's job). The only thing it blocks is a lie into the ledger: a malformed or replayed
record gets rejected and never pollutes the chain (design §0, §6.1).
"""

from dataclasses import dataclass

from a_mcp.capability import DEFAULT_L1_CAPABILITY, AuditCapability
from a_mcp.l2.keys import KeyRegistry
from a_mcp.l2.signing import verify_event_signature
from a_mcp.ledger import Ledger, SealedRecord
from a_mcp.schema import validate_event
from a_mcp.transport import AttemptResponse, accept, reject, unavailable


@dataclass
class IntegrityAnomaly:
    """A detected lie or inconsistency in the audit stream."""

    id: str
    kind: str
    detail: str
    # end class


class AuditHost:
    """Receives self-attested events and seals valid ones into the tamper-evident ledger."""

    def __init__(
        self,
        partition: str,
        capability: AuditCapability = DEFAULT_L1_CAPABILITY,
        key_registry: KeyRegistry | None = None,
    ) -> None:
        """Initialize the host for a partition under the given capability and optional keys."""
        self.ledger = Ledger(partition)
        # Demo switch: simulate Tier1 durability failure (infra), which must fail-closed.
        self.unavailable = False
        self._capability = capability
        self._key_registry = key_registry
        self._accepted_attempts: set[str] = set()
        self._rejected_ids: set[str] = set()
        self._last_seq_by_key: dict[str, int] = {}
        self._anomalies: list[IntegrityAnomaly] = []
        self._host_clock = 0
        # end def

    def _flag(self, event_id: str, kind: str, detail: str) -> None:
        """Record an integrity anomaly."""
        self._anomalies.append(IntegrityAnomaly(id=event_id, kind=kind, detail=detail))
        # end def

    def _check_l2(self, event: dict) -> str | None:
        """Verify L2 non-repudiation and sequence continuity.

        A forged/altered/unsigned record or a replayed sequence is a lie into the ledger and
        returns a reject reason. A forward gap means a prior event was suppressed and is
        flagged (rejecting the current event would not recover the missing one). No-op under
        L1. This detects tampering; it never controls the tool's domain action.

        Args:
            event: The validated event.

        Returns:
            A reject reason string, or None to proceed.
        """
        if self._capability.level != 'L2':
            return None
            # end if
        key_id = event.get('key_id')
        if not event.get('signature') or not key_id or event.get('sequence') is None:
            self._flag(event['id'], 'l2-unsigned', 'L2 requires signature, key_id, sequence')
            return 'l2-unsigned'
            # end if
        public_key = self._key_registry.get(key_id) if self._key_registry is not None else None
        if public_key is None:
            self._flag(event['id'], 'unknown-key', f'no registered key for {key_id}')
            return 'unknown-key'
            # end if
        if not verify_event_signature(event, public_key):
            self._flag(event['id'], 'signature-invalid', 'signature does not verify (forged/altered)')
            return 'signature-invalid'
            # end if
        last = self._last_seq_by_key.get(key_id, -1)
        sequence = event['sequence']
        if sequence <= last:
            self._flag(event['id'], 'sequence-replay', f'sequence {sequence} <= last {last}')
            return 'sequence-replay'
            # end if
        if sequence > last + 1:
            self._flag(event['id'], 'sequence-gap', f'expected {last + 1}, got {sequence} (suppressed event)')
            # end if
        self._last_seq_by_key[key_id] = sequence
        return None
        # end def

    def negotiate(self) -> AuditCapability:
        """Return the host-declared audit capability."""
        return self._capability
        # end def

    def anomalies(self) -> list[IntegrityAnomaly]:
        """Return the detected integrity anomalies."""
        return list(self._anomalies)
        # end def

    def records(self) -> list[SealedRecord]:
        """Return the sealed ledger records."""
        return self.ledger.records()
        # end def

    def _next_host_ts(self) -> str:
        """Return a deterministic monotonic host timestamp (no wall clock)."""
        self._host_clock += 1
        return f'host-ts:{self._host_clock}'
        # end def

    def handle_attempt(self, event: object) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject/unavailable."""
        error = validate_event(event)
        if error is not None:
            self._anomalies.append(IntegrityAnomaly(id=_extract_id(event), kind='schema-invalid', detail=error))
            return reject('schema-invalid')
            # end if
        assert isinstance(event, dict)
        if event['outcome'] != 'attempted':
            self._anomalies.append(
                IntegrityAnomaly(id=event['id'], kind='schema-invalid', detail='attempt must carry outcome=attempted')
            )
            return reject('attempt-must-be-attempted')
            # end if
        # L2: reject forged/unsigned/replayed records before they touch the ledger.
        l2_reason = self._check_l2(event)
        if l2_reason is not None:
            self._rejected_ids.add(event['id'])
            return reject(l2_reason)
            # end if
        # Infra durability failure -> fail-closed. Not the tool's fault; retryable.
        if self.unavailable:
            return unavailable('tier1-durability-failure')
            # end if
        # A replayed attempt id is a forged/duplicate record -> reject the lie, keep the ledger clean.
        if event['id'] in self._accepted_attempts:
            self._rejected_ids.add(event['id'])
            self._anomalies.append(
                IntegrityAnomaly(id=event['id'], kind='attempt-replay', detail='duplicate attempt id')
            )
            return reject('attempt-replay')
            # end if
        sealed = self.ledger.append(event, self._next_host_ts())
        self._accepted_attempts.add(event['id'])
        return accept(sealed.seq, sealed.record_hash)
        # end def

    def handle_outcome(self, event: object) -> None:
        """Append an outcome; flag correlation anomalies (the tamper-evidence byproduct)."""
        error = validate_event(event)
        if error is not None:
            self._anomalies.append(IntegrityAnomaly(id=_extract_id(event), kind='schema-invalid', detail=error))
            return
            # end if
        assert isinstance(event, dict)
        # L2: an outcome with an invalid signature/sequence is a lie too; flag and drop it.
        if self._check_l2(event) is not None:
            return
            # end if
        if event['id'] in self._rejected_ids:
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'],
                    kind='outcome-after-reject',
                    detail=f'outcome={event["outcome"]} for rejected id',
                )
            )
            return
            # end if
        if event['id'] not in self._accepted_attempts:
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'],
                    kind='outcome-without-attempt',
                    detail=f'outcome={event["outcome"]} without accepted attempt',
                )
            )
            return
            # end if
        self.ledger.append(event, self._next_host_ts())
        # end def

    # end class


def _extract_id(raw: object) -> str:
    """Best-effort id extraction for anomaly logging."""
    if isinstance(raw, dict) and isinstance(raw.get('id'), str):
        return raw['id']
        # end if
    return '<unknown>'
    # end def
