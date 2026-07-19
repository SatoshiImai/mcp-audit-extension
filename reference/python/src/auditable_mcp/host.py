"""Host-side audit subsystem.

Responsibilities:
- Receive self-attested events from tools.
- Validate schema and sequence (rejecting malformed/replayed records).
- Seal accepted records into the tamper-evident ledger.

The host does not authorize domain actions; it only validates record integrity.
"""

from dataclasses import dataclass

from auditable_mcp.capability import DEFAULT_L1_CAPABILITY, AuditCapability, NegotiationResult, negotiate_capability
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.l2.signing import verify_event_signature
from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.schema import validate_event
from auditable_mcp.transport import AttemptResponse, accept, reject, unavailable


@dataclass
class IntegrityAnomaly:
    """A detected lie or inconsistency in the audit stream."""

    id: str
    kind: str
    detail: str


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
        # Test switch: simulate Tier1 durability failure; must fail closed.
        self.unavailable = False
        self._capability = capability
        self._key_registry = key_registry
        self._accepted_attempts: set[str] = set()
        self._rejected_ids: set[str] = set()
        self._last_seq_by_key: dict[str, int] = {}
        self._anomalies: list[IntegrityAnomaly] = []
        self._host_clock = 0

    def _flag(self, event_id: str, kind: str, detail: str) -> None:
        """Record an integrity anomaly."""
        self._anomalies.append(IntegrityAnomaly(id=event_id, kind=kind, detail=detail))

    def _check_l2(self, event: dict) -> str | None:
        """Verify the L2 signature and per-tool sequence. Return a reject reason, or None.

        Unsigned/forged/replayed records are rejected. A forward sequence gap is flagged but
        not rejected, since the missing event cannot be recovered. No-op under L1.
        """
        if self._capability.level != 'L2':
            return None
        key_id = event.get('key_id')
        if not event.get('signature') or not key_id or event.get('sequence') is None:
            self._flag(event['id'], 'l2-unsigned', 'L2 requires signature, key_id, sequence')
            return 'l2-unsigned'
        public_key = self._key_registry.get(key_id) if self._key_registry is not None else None
        if public_key is None:
            self._flag(event['id'], 'unknown-key', f'no registered key for {key_id}')
            return 'unknown-key'
        if not verify_event_signature(event, public_key):
            self._flag(event['id'], 'signature-invalid', 'signature does not verify (forged/altered)')
            return 'signature-invalid'
        last = self._last_seq_by_key.get(key_id, -1)
        sequence = event['sequence']
        if sequence <= last:
            self._flag(event['id'], 'sequence-replay', f'sequence {sequence} <= last {last}')
            return 'sequence-replay'
        if sequence > last + 1:
            self._flag(event['id'], 'sequence-gap', f'expected {last + 1}, got {sequence} (suppressed event)')
        self._last_seq_by_key[key_id] = sequence
        return None

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Compare the tool's offered capability against the host requirement (§6.1).

        Args:
            offered: The capability the tool declares it supports.

        Returns:
            A NegotiationResult carrying the host requirement and whether the offer satisfies it.
        """
        return negotiate_capability(self._capability, offered)

    def anomalies(self) -> list[IntegrityAnomaly]:
        """Return the detected integrity anomalies."""
        return list(self._anomalies)

    def records(self) -> list[SealedRecord]:
        """Return the sealed ledger records."""
        return self.ledger.records()

    def _next_host_ts(self) -> str:
        """Return a deterministic monotonic host timestamp in ISO-8601 (no wall clock)."""
        self._host_clock += 1
        return f'2026-07-15T00:00:{self._host_clock:02d}.000Z'

    def handle_attempt(self, event: object) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject/unavailable."""
        error = validate_event(event)
        if error is not None:
            self._anomalies.append(IntegrityAnomaly(id=_extract_id(event), kind='schema-invalid', detail=error))
            return reject('schema-invalid')
        assert isinstance(event, dict)
        if event['outcome'] != 'attempted':
            self._anomalies.append(
                IntegrityAnomaly(id=event['id'], kind='schema-invalid', detail='attempt must carry outcome=attempted')
            )
            return reject('attempt-must-be-attempted')
        # L2: reject forged/unsigned/replayed records before sealing.
        l2_reason = self._check_l2(event)
        if l2_reason is not None:
            self._rejected_ids.add(event['id'])
            return reject(l2_reason)
        # Durability failure: fail closed (retryable).
        if self.unavailable:
            return unavailable('tier1-durability-failure')
        # Replayed attempt id: reject as a duplicate.
        if event['id'] in self._accepted_attempts:
            self._rejected_ids.add(event['id'])
            self._anomalies.append(
                IntegrityAnomaly(id=event['id'], kind='attempt-replay', detail='duplicate attempt id')
            )
            return reject('attempt-replay')
        sealed = self.ledger.append(event, self._next_host_ts())
        self._accepted_attempts.add(event['id'])
        # Verifiable Accept (§7.1): return host-assigned fields the tool needs to reconstruct the
        # §8.2 preimage for Polluted Stop verification.
        return accept(sealed.seq, sealed.record_hash, sealed.host_ts, sealed.previous_hash)

    def handle_outcome(self, event: object) -> None:
        """Append an outcome, flagging an outcome that has no accepted attempt or follows a reject."""
        error = validate_event(event)
        if error is not None:
            self._anomalies.append(IntegrityAnomaly(id=_extract_id(event), kind='schema-invalid', detail=error))
            return
        assert isinstance(event, dict)
        # L2: drop an outcome with an invalid signature/sequence.
        if self._check_l2(event) is not None:
            return
        if event['id'] in self._rejected_ids:
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'],
                    kind='outcome-after-reject',
                    detail=f'outcome={event["outcome"]} for rejected id',
                )
            )
            return
        if event['id'] not in self._accepted_attempts:
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'],
                    kind='outcome-without-attempt',
                    detail=f'outcome={event["outcome"]} without accepted attempt',
                )
            )
            return
        self.ledger.append(event, self._next_host_ts())


def _extract_id(raw: object) -> str:
    """Best-effort id extraction for anomaly logging."""
    if isinstance(raw, dict) and isinstance(raw.get('id'), str):
        return raw['id']
    return '<unknown>'
