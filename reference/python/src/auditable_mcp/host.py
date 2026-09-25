"""Host-side audit subsystem.

Responsibilities:
- Issue an audit session for each call it audits, and close it when the call ends (§6.3).
- Receive self-attested events from tools.
- Validate schema, session, signature, uniqueness, and signer_seq (rejecting malformed/replayed records).
- Seal accepted records into the tamper-evident ledger.

The host does not authorize domain actions; it only validates record integrity.
"""

import uuid
from collections.abc import Set
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from auditable_mcp.canonical import canonicalize
from auditable_mcp.capability import DEFAULT_L1_CAPABILITY, AuditCapability, NegotiationResult, negotiate_capability
from auditable_mcp.l2.keys import KeyRegistry
from auditable_mcp.l2.signing import verify_event_signature
from auditable_mcp.ledger import Countersigner, Ledger, SealedRecord
from auditable_mcp.schema import check_event_structure
from auditable_mcp.transport import AttemptResponse, accept, reject, unavailable


@dataclass
class IntegrityAnomaly:
    """A detected integrity violation or inconsistency in the audit stream, under its Tier-1 kind (§7.6)."""

    id: str
    kind: str
    detail: str


@dataclass
class _KeyTracker:
    """The replay window of one key in one audit session (§7.4).

    `decided` holds the signer_seq values the host has decided - sealed, or rejected after the
    signature verified; `unavailable` and an idempotent duplicate add nothing. `received` is the
    highest value received with a verifying signature.
    """

    decided: set[int] = field(default_factory=set)
    received: int | None = None


@dataclass
class _Session:
    """One audit session: one tools/call (§6.3)."""

    trackers: dict[str, _KeyTracker] = field(default_factory=dict)
    accepted: set[str] = field(default_factory=set)
    rejected: set[str] = field(default_factory=set)
    # The canonical form of the terminal outcome sealed for each id: one per operation (§7.2).
    outcomes: dict[str, str] = field(default_factory=dict)


@dataclass
class _Signature:
    """The result of the Level-2 check: a reject reason, or the tracker the event was received into."""

    reason: str | None = None
    tracker: _KeyTracker | None = None
    signer_seq: int | None = None

    def decide(self) -> None:
        """Add the event's signer_seq to the decided set (§7.4)."""
        if self.tracker is not None and self.signer_seq is not None:
            self.tracker.decided.add(self.signer_seq)

    def already_decided(self) -> bool:
        """Return True if the event's signer_seq was decided before (§7.4)."""
        return self.tracker is not None and self.signer_seq in self.tracker.decided


# A missing signature and an unknown key are signature failures in the anomaly code space (§7.6).
_SIGNATURE_ANOMALY = 'signature-invalid'


class AuditHost:
    """Receives self-attested events and seals valid ones into the tamper-evident ledger."""

    def __init__(
        self,
        partition: str,
        capability: AuditCapability = DEFAULT_L1_CAPABILITY,
        key_registry: KeyRegistry | None = None,
        countersigner: Countersigner | None = None,
    ) -> None:
        """Initialize the host for a partition under the given capability and optional keys.

        Raises:
            ValueError: The capability declares `countersign: "host"` without a signer, or declares
                `none` while holding one. A host that declares it countersigns and then does not
                leaves every record uncountersigned while its peers expect otherwise; a host that
                declares `none` MUST NOT return the triple (§7.1), and holding a signer is the only
                way to violate that, so both are refused at construction rather than at seal time.
        """
        if capability.countersign == 'host' and countersigner is None:
            raise ValueError('a host declaring countersign "host" requires a Countersigner (§5.2)')
        if capability.countersign == 'none' and countersigner is not None:
            raise ValueError('a host declaring countersign "none" must not hold a Countersigner (§7.1)')
        self._countersigner = countersigner
        self.ledger = Ledger(partition)
        # Test switch: simulate a persistence/durability failure; must fail closed.
        self.unavailable = False
        self._capability = capability
        self._key_registry = key_registry
        self._sessions: dict[str, _Session] = {}
        self._issued: set[str] = set()
        # The partition's sealed attempts by id, with the canonical bytes and the response they got,
        # so a byte-identical repeat is answered from the ledger (§7.1).
        self._sealed_attempts: dict[str, tuple[str, AttemptResponse]] = {}
        self._anomalies: list[IntegrityAnomaly] = []
        self._host_clock = 0

    def _flag(self, event_id: str, kind: str, detail: str) -> None:
        """Record an integrity anomaly."""
        self._anomalies.append(IntegrityAnomaly(id=event_id, kind=kind, detail=detail))

    def declaration(self) -> AuditCapability:
        """Return the capability object this host declares (§6.1)."""
        return self._capability

    def open_session(self, session_id: str | None = None) -> str:
        """Issue a fresh audit session for a call the host audits (§6.3).

        A session id is never issued twice, even after its session ended.

        Raises:
            ValueError: The session id was already issued.
        """
        issued = session_id if session_id is not None else str(uuid.uuid4())
        if issued in self._issued:
            raise ValueError(f'session {issued} was already issued (§6.3)')
        self._issued.add(issued)
        self._sessions[issued] = _Session()
        return issued

    def close_session(self, session_id: str) -> None:
        """Close an audit session because its call ended (§6.3).

        Every outcome of the session has been delivered by then, so an accepted attempt without a
        sealed terminal outcome was never resolved. The session accepts nothing further, and its
        replay window is discarded (§7.4).
        """
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        for event_id in sorted(session.accepted - session.outcomes.keys()):
            self._flag(event_id, 'unresolved-attempt', f'call ended with attempt {event_id} unresolved')

    def _admit(self, event: object, *, attempt: bool, arrived_on: Set[str] | None) -> tuple[dict, _Session] | str:
        """Check structure (§7.1 step 1, incl. which outcome each channel carries), then the session (step 2).

        `arrived_on` is the set of sessions the host issued for the calls in flight on the connection
        the event arrived on (§6.5); without it, any open session is the call's.

        Returns:
            The event and its session, or the Tier-1 reject reason.
        """
        error = check_event_structure(event)
        if error is not None:
            self._flag(_extract_id(event), 'schema-invalid', error)
            return 'schema-invalid'
        assert isinstance(event, dict)
        if (event['outcome'] == 'attempted') != attempt:
            detail = (
                'attempt must carry outcome=attempted' if attempt else 'attempted outcome on the outcome channel (§6)'
            )
            self._flag(event['id'], 'schema-invalid', detail)
            return 'schema-invalid'
        session = self._sessions.get(event['session_id'])
        if session is None or (arrived_on is not None and event['session_id'] not in arrived_on):
            self._flag(
                event['id'],
                'replay-detected',
                f'session: {event["session_id"]} is not the session of a call in flight (§6.3)',
            )
            return 'replay-detected'
        return event, session

    def _verify_signature(self, event: dict, session: _Session) -> _Signature:
        """Verify a Level-2 signature (§7.1 step 3, §7.4).

        Once the signature verifies the event counts as received: a value more than one past the
        highest received - or a first value other than 0 - is flagged, not rejected. No-op under L1.
        """
        if self._capability.level != 'L2':
            return _Signature()
        key_id = event.get('key_id')
        signer_seq = event.get('signer_seq')
        if event.get('signature') is None or key_id is None or signer_seq is None:
            self._flag(event['id'], _SIGNATURE_ANOMALY, 'l2-unsigned: Level 2 requires signature, key_id, signer_seq')
            return _Signature(reason='l2-unsigned')
        registered = self._key_registry.current(key_id) if self._key_registry is not None else None
        if registered is None:
            self._flag(event['id'], _SIGNATURE_ANOMALY, f'unknown-key: no current registry entry for {key_id}')
            return _Signature(reason='unknown-key')
        if not verify_event_signature(event, registered):
            self._flag(event['id'], _SIGNATURE_ANOMALY, 'signature does not verify (forged/altered)')
            return _Signature(reason='signature-invalid')
        tracker = session.trackers.setdefault(key_id, _KeyTracker())
        expected = 0 if tracker.received is None else tracker.received + 1
        if signer_seq > expected:
            self._flag(event['id'], 'signer-seq-gap', f'expected {expected}, got {signer_seq}')
        if tracker.received is None or signer_seq > tracker.received:
            tracker.received = signer_seq
        return _Signature(tracker=tracker, signer_seq=signer_seq)

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

    def handle_attempt(self, event: object, arrived_on: Set[str] | None = None) -> AttemptResponse:
        """Validate and, if durable, seal an attempt; otherwise reject/unavailable (§7.1)."""
        admitted = self._admit(event, attempt=True, arrived_on=arrived_on)
        if isinstance(admitted, str):
            return reject(admitted)
        event, session = admitted
        signed = self._verify_signature(event, session)
        if signed.reason is not None:
            session.rejected.add(event['id'])
            return reject(signed.reason)
        # §7.1 step 4: a sealed id answers a byte-identical repeat from the ledger and rejects anything else.
        canonical = canonicalize(event)
        sealed = self._sealed_attempts.get(event['id'])
        if sealed is not None:
            sealed_canonical, response = sealed
            if sealed_canonical == canonical:
                return response
            signed.decide()
            session.rejected.add(event['id'])
            self._flag(event['id'], 'replay-detected', 'id-replay: attempt id sealed with a different event')
            return reject('replay-detected')
        # §7.1 step 4: an operation with a sealed outcome has concluded, and no attempt is sealed after
        # its own terminal record.
        if event['id'] in session.outcomes:
            signed.decide()
            session.rejected.add(event['id'])
            self._flag(event['id'], 'replay-detected', 'concluded: the operation already has a sealed outcome')
            return reject('replay-detected')
        # §7.1 step 5: a signer_seq already decided in this session is a replay.
        if signed.already_decided():
            session.rejected.add(event['id'])
            self._flag(event['id'], 'replay-detected', f'sequence: signer_seq {event["signer_seq"]} already decided')
            return reject('replay-detected')
        # Persistence failure: nothing is decided, so the identical attempt may come again (§7.1).
        if self.unavailable:
            return unavailable('internal-error')
        record = self.ledger.append(event, self._next_host_ts(), self._countersigner)
        signed.decide()
        session.accepted.add(event['id'])
        # Verifiable Accept (§7.1): the host-assigned fields the tool needs to reconstruct the §8.2
        # preimage for Polluted Stop, and the countersignature triple where the host countersigns.
        response = accept(
            record.seq,
            record.record_hash,
            record.host_ts,
            record.previous_hash,
            record.host_signature,
            record.host_key_id,
            record.log_id,
        )
        self._sealed_attempts[event['id']] = (canonical, response)
        return response

    def handle_outcome(self, event: object, arrived_on: Set[str] | None = None) -> None:
        """Seal an outcome, or drop and record it; an outcome has no response (§6, §7.2).

        An outcome is validated in the order an attempt is - structure, session, signature,
        uniqueness, sequence - and only then correlated. A dropped outcome is recorded under its
        Tier-1 anomaly kind and never raised.
        """
        admitted = self._admit(event, attempt=False, arrived_on=arrived_on)
        if isinstance(admitted, str):
            return
        event, session = admitted
        # The signature is verified, and the event counted as received, even when the host then turns
        # out to be unavailable: receiving and deciding are separate (§7.4).
        signed = self._verify_signature(event, session)
        if signed.reason is not None:
            return
        # One terminal record per (session_id, id) (§7.2): a byte-identical repeat is not processed further.
        canonical = canonicalize(event)
        sealed = session.outcomes.get(event['id'])
        if sealed is not None:
            if sealed != canonical:
                signed.decide()
                self._flag(
                    event['id'],
                    'replay-detected',
                    'correlation: differs from the outcome already sealed for this operation',
                )
            return
        if signed.already_decided():
            self._flag(event['id'], 'replay-detected', f'sequence: signer_seq {event["signer_seq"]} already decided')
            return
        outcome = event['outcome']
        correlated = event['id'] in session.accepted
        # §7.2: a success or failed outcome with no accepted attempt in its session is not sealed.
        if not correlated and outcome != 'aborted':
            signed.decide()
            sub = 'after-reject' if event['id'] in session.rejected else 'never-accepted'
            self._flag(event['id'], 'orphaned-outcome', f'{sub}: outcome={outcome}')
            return
        # The switch that simulates a durability failure covers every seal, not only attempts.
        if self.unavailable:
            return
        # A correlated outcome is its operation's terminal record; an aborted outcome of an attempt
        # the host did not accept is the record of an operation the tool declined to perform (§7.2, §10.4).
        self.ledger.append(event, self._next_host_ts(), self._countersigner)
        signed.decide()
        session.outcomes[event['id']] = canonical


def _extract_id(raw: object) -> str:
    """Best-effort id extraction for anomaly logging."""
    if isinstance(raw, dict) and isinstance(raw.get('id'), str):
        return raw['id']
    return '<unknown>'
