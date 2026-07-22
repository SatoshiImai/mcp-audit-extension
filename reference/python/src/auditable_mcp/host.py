"""Host-side audit subsystem.

Responsibilities:
- Receive self-attested events from tools.
- Validate schema and signer_seq (rejecting malformed/replayed records).
- Seal accepted records into the tamper-evident ledger.

The host does not authorize domain actions; it only validates record integrity.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from auditable_mcp.canonical import has_unsafe_number
from auditable_mcp.capability import DEFAULT_L1_CAPABILITY, AuditCapability, NegotiationResult, negotiate_capability
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.l2.signing import verify_event_signature
from auditable_mcp.ledger import Ledger, SealedRecord
from auditable_mcp.schema import validate_event
from auditable_mcp.transport import AttemptResponse, accept, reject, unavailable


@dataclass
class IntegrityAnomaly:
    """A detected integrity violation or inconsistency in the audit stream."""

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
        # Test switch: simulate a persistence/durability failure; must fail closed.
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
        """Verify the L2 signature and per-key_id signer_seq. Return a reject reason, or None.

        Unsigned/forged/replayed records are rejected. A forward signer_seq gap is flagged
        (signer-seq-gap) but not rejected, since the missing event cannot be recovered. No-op
        under L1. The first signer_seq for a key_id (no prior tracked value) is the baseline, accepted and never
        flagged as a gap.
        """
        if self._capability.level != 'L2':
            return None
        key_id = event.get('key_id')
        if not event.get('signature') or not key_id or event.get('signer_seq') is None:
            self._flag(event['id'], 'l2-unsigned', 'L2 requires signature, key_id, signer_seq')
            return 'l2-unsigned'
        registered = self._key_registry.get(key_id) if self._key_registry is not None else None
        if registered is None:
            self._flag(event['id'], 'unknown-key', f'no registered key for {key_id}')
            return 'unknown-key'
        if not verify_event_signature(event, registered):
            self._flag(event['id'], 'signature-invalid', 'signature does not verify (forged/altered)')
            return 'signature-invalid'
        signer_seq = event['signer_seq']
        last = self._last_seq_by_key.get(key_id)
        if last is None:
            # First observation for this key_id is the baseline (§7.4): accepted as-is, never a gap,
            # because there is no prior value to compare against (a persisted or cross-partition
            # counter may legitimately start above 0).
            return None
        if signer_seq <= last:
            self._flag(event['id'], 'replay-detected', f'signer_seq {signer_seq} <= last {last}')
            return 'replay-detected'
        if signer_seq > last + 1:
            self._flag(event['id'], 'signer-seq-gap', f'expected {last + 1}, got {signer_seq} (suppressed event)')
        return None

    def _advance_seq(self, event: dict) -> None:
        """Advance the per-key signer_seq tracker; called only after a record is sealed (§7.4).

        The tracker follows the last *accepted* (sealed) signer_seq, not the last seen, so an
        `unavailable`/retryable attempt does not poison the counter for a retry.
        """
        key_id = event.get('key_id')
        if key_id is not None and event.get('signer_seq') is not None:
            self._last_seq_by_key[key_id] = event['signer_seq']

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
        moment = datetime(2026, 7, 15, tzinfo=UTC) + timedelta(seconds=self._host_clock)
        return moment.strftime('%Y-%m-%dT%H:%M:%S.000Z')

    def handle_attempt(self, event: object) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject/unavailable."""
        error = validate_event(event)
        if error is not None:
            self._anomalies.append(IntegrityAnomaly(id=_extract_id(event), kind='schema-invalid', detail=error))
            return reject('schema-invalid')
        assert isinstance(event, dict)
        if event['outcome'] != 'attempted':
            # Tier-1 schema-invalid; the Tier-2 specifics go in detail (§7.6).
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'],
                    kind='schema-invalid',
                    detail='attempt-must-be-attempted: attempt must carry outcome=attempted',
                )
            )
            return reject('schema-invalid')
        # Not canonicalizable (§8.1): reject gracefully instead of raising at seal time.
        if has_unsafe_number(event):
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'], kind='schema-invalid', detail='numeric-domain: number not canonicalizable (§8.1)'
                )
            )
            return reject('schema-invalid')
        # L2: reject forged/unsigned/replayed records before sealing.
        l2_reason = self._check_l2(event)
        if l2_reason is not None:
            self._rejected_ids.add(event['id'])
            return reject(l2_reason)
        # Persistence failure: fail closed (retryable), returned as internal-error (§7.6).
        if self.unavailable:
            return unavailable('internal-error')
        # Replayed attempt id: reject as a duplicate.
        if event['id'] in self._accepted_attempts:
            self._rejected_ids.add(event['id'])
            self._anomalies.append(
                IntegrityAnomaly(id=event['id'], kind='replay-detected', detail='id-replay: duplicate attempt id')
            )
            return reject('replay-detected')
        sealed = self.ledger.append(event, self._next_host_ts())
        self._accepted_attempts.add(event['id'])
        self._advance_seq(event)
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
        # Not canonicalizable (§8.1): drop instead of raising at seal time.
        if has_unsafe_number(event):
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'], kind='schema-invalid', detail='numeric-domain: number not canonicalizable (§8.1)'
                )
            )
            return
        outcome = event['outcome']
        # §6: an `attempted` outcome on the audit/outcome channel is invalid; drop and flag it rather than
        # sealing a second attempt record for the id (§7.1 uniqueness).
        if outcome == 'attempted':
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'], kind='schema-invalid', detail='attempted outcome on the audit/outcome channel (§6)'
                )
            )
            return
        # §10.4: a fail-closed `aborted` outcome for a never-accepted or rejected attempt is the honest
        # refused-action signal, not a tampering anomaly. Exempt it before _check_l2, so a fresh signer
        # sequence that outran the unsealed attempt is not flagged as a suppression gap.
        if outcome == 'aborted' and event['id'] not in self._accepted_attempts:
            return
        # L2: drop an outcome with an invalid signature/signer_seq.
        if self._check_l2(event) is not None:
            return
        if event['id'] in self._accepted_attempts:
            # Each correlated outcome is sealed, not de-duplicated (§8.3). This reference imposes no
            # cap on outcomes per id; §8.3 makes that bound a host/SDK responsibility, so picking a
            # number here would be an arbitrary policy the spec deliberately leaves open.
            self.ledger.append(event, self._next_host_ts())
            self._advance_seq(event)
            return
        if event['id'] in self._rejected_ids:
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'], kind='orphaned-outcome', detail=f'after-reject: outcome={outcome} for rejected id'
                )
            )
        else:
            self._anomalies.append(
                IntegrityAnomaly(
                    id=event['id'],
                    kind='orphaned-outcome',
                    detail=f'never-accepted: outcome={outcome} without accepted attempt',
                )
            )


def _extract_id(raw: object) -> str:
    """Best-effort id extraction for anomaly logging."""
    if isinstance(raw, dict) and isinstance(raw.get('id'), str):
        return raw['id']
    return '<unknown>'
