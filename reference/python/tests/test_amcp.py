"""Tests for the AmcpSession audit-before-act discipline."""

import pytest

from auditable_mcp.amcp import AmcpAbortedError, AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2.keys import generate_tool_key
from auditable_mcp.l2.signing import KeySigner
from auditable_mcp.transport import AttemptResponse, AuditTransportError

SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


def _l2_signer() -> KeySigner:
    """Build an Ed25519 signer, whose presence marks a session as Level 2."""
    key = generate_tool_key('polluted-stop-key')
    return KeySigner(key.key_id, key.alg, key.private_key)


class _StubTransport:
    """A transport double that returns a canned attempt response and captures outcome events."""

    def __init__(self, response: AttemptResponse) -> None:
        """Store the response to return and prepare capture lists."""
        self._response = response
        self.attempts: list[dict] = []
        self.outcomes: list[dict] = []

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Capture the attempt and return the canned response."""
        self.attempts.append(event)
        return self._response

    def send_outcome(self, event: dict) -> None:
        """Capture the outcome event."""
        self.outcomes.append(event)


def _session(host: AuditHost) -> AmcpSession:
    """Build an in-process session bound to the host."""
    return AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps())


def test_emits_attempt_then_performs_then_outcome() -> None:
    """Attempt is accepted, the action runs, then a success outcome is sealed."""
    host = AuditHost('t#d')
    session = _session(host)
    calls: list[int] = []

    def perform() -> str:
        calls.append(1)
        return 'result'

    out = session.audited(
        'db.read', {'kind': 'table', 'ref': 'customers'}, perform, mutates=False, egress=False, disclose={'q': 1}
    )
    assert out == 'result'
    assert len(calls) == 1
    outcomes = [r.event['outcome'] for r in host.records()]
    assert outcomes == ['attempted', 'success']


def test_does_not_perform_when_unavailable() -> None:
    """When the host is unavailable, the action is not performed (fail-closed)."""
    host = AuditHost('t#d')
    host.unavailable = True
    session = _session(host)
    performed: list[int] = []

    with pytest.raises(AmcpAbortedError):
        session.audited(
            'db.write',
            {'kind': 'table', 'ref': 'customers'},
            lambda: performed.append(1),
            mutates=True,
            egress=False,
        )
    assert performed == []
    assert len(host.records()) == 0


def test_seals_failed_outcome_and_reraises() -> None:
    """When the action raises, a failed outcome is sealed and the error re-raised."""
    host = AuditHost('t#d')
    session = _session(host)

    def boom() -> None:
        raise RuntimeError('boom')

    with pytest.raises(RuntimeError):
        session.audited('db.write', {'kind': 'table', 'ref': 'customers'}, boom, mutates=True, egress=False)
    outcomes = [r.event['outcome'] for r in host.records()]
    assert outcomes == ['attempted', 'failed']


def test_polluted_stop_aborts_on_record_hash_mismatch_under_l2() -> None:
    """Under Level 2, a host-returned record hash that does not match makes the tool abort."""
    transport = _StubTransport(
        AttemptResponse(
            status='accept', seq=0, record_hash='d' * 64, host_ts='2026-07-15T00:00:01.000Z', previous_hash='0' * 64
        )
    )
    session = AmcpSession(transport, SESSION, DeterministicDeps(), _l2_signer())
    performed: list[int] = []
    with pytest.raises(AmcpAbortedError):
        session.audited(
            'db.write', {'kind': 'table', 'ref': 'notes'}, lambda: performed.append(1), mutates=True, egress=False
        )
    assert performed == []
    aborted = [o for o in transport.outcomes if o['outcome'] == 'aborted']
    assert len(aborted) == 1
    assert aborted[0]['reason'] == 'hash-mismatch'


def test_polluted_stop_skipped_under_l1() -> None:
    """Under Level 1 (no signer), the Polluted Stop check is optional; the action still proceeds."""
    transport = _StubTransport(
        AttemptResponse(
            status='accept', seq=0, record_hash='d' * 64, host_ts='2026-07-15T00:00:01.000Z', previous_hash='0' * 64
        )
    )
    session = AmcpSession(transport, SESSION, DeterministicDeps())
    performed: list[int] = []

    def perform() -> str:
        performed.append(1)
        return 'ok'

    result = session.audited('db.read', {'kind': 'table', 'ref': 'notes'}, perform, mutates=False, egress=False)
    assert result == 'ok'
    assert performed == [1]
    assert not any(o['outcome'] == 'aborted' for o in transport.outcomes)


def test_reject_emits_aborted_with_reason() -> None:
    """A rejected attempt yields an aborted outcome carrying reason=host-rejected."""
    transport = _StubTransport(AttemptResponse(status='reject', reason='schema-invalid'))
    session = AmcpSession(transport, SESSION, DeterministicDeps())
    with pytest.raises(AmcpAbortedError):
        session.audited('db.write', {'kind': 'table', 'ref': 'notes'}, lambda: None, mutates=True, egress=False)
    assert transport.outcomes[-1]['outcome'] == 'aborted'
    assert transport.outcomes[-1]['reason'] == 'host-rejected'


def test_unavailable_emits_aborted_with_reason() -> None:
    """An unavailable host yields an aborted outcome carrying reason=host-unavailable."""
    transport = _StubTransport(AttemptResponse(status='unavailable', reason='internal-error'))
    session = AmcpSession(transport, SESSION, DeterministicDeps())
    with pytest.raises(AmcpAbortedError):
        session.audited('db.read', {'kind': 'table', 'ref': 'notes'}, lambda: None, mutates=False, egress=False)
    assert transport.outcomes[-1]['outcome'] == 'aborted'
    assert transport.outcomes[-1]['reason'] == 'host-unavailable'


class _FailingTransport:
    """A transport whose attempt never gets an answer."""

    def __init__(self) -> None:
        """Prepare the capture list."""
        self.outcomes: list[dict] = []

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Fail as a broken connection does."""
        raise AuditTransportError('connection reset')

    def send_outcome(self, event: dict) -> None:
        """Capture the outcome event."""
        self.outcomes.append(event)


def test_a_transport_fault_is_unanswered() -> None:
    """§6: a transport fault is a failure to record: aborted/host-unavailable, action not performed."""
    transport = _FailingTransport()
    performed: list[bool] = []
    with pytest.raises(AmcpAbortedError, match='host-unavailable'):
        AmcpSession(transport, SESSION, DeterministicDeps()).audited(
            'db.write', {'kind': 'table', 'ref': 'notes'}, lambda: performed.append(True), mutates=True, egress=False
        )
    assert performed == []
    assert [o['reason'] for o in transport.outcomes] == ['host-unavailable']


def test_a_partial_countersignature_triple_is_unanswered() -> None:
    """§6: an answer outside the Attempt Response schema is not host-signature-invalid but unanswered."""
    partial = AttemptResponse(
        status='accept',
        seq=0,
        record_hash='d' * 64,
        host_ts='2026-07-15T00:00:01.000Z',
        previous_hash='0' * 64,
        host_signature='AAAA',
    )
    transport = _StubTransport(partial)
    checked: list[str] = []

    def verifier(host_key_id: str, signature: str, payload: str) -> bool:
        checked.append(host_key_id)
        return True

    session = AmcpSession(transport, SESSION, DeterministicDeps(), None, verifier, True)
    with pytest.raises(AmcpAbortedError, match='host-unavailable'):
        session.audited('db.write', {'kind': 'table', 'ref': 'notes'}, lambda: 'x', mutates=True, egress=False)
    assert checked == []
    assert [o['reason'] for o in transport.outcomes] == ['host-unavailable']


def test_a_tool_that_requires_a_countersignature_performs_polluted_stop_at_level_1() -> None:
    """§7.2: a genuine countersigned accept for another record is refused by the recomputed hash."""
    countersigned = AttemptResponse(
        status='accept',
        seq=0,
        record_hash='d' * 64,
        host_ts='2026-07-15T00:00:01.000Z',
        previous_hash='0' * 64,
        host_signature='AAAA',
        host_key_id='host',
        log_id='log',
    )
    session = AmcpSession(_StubTransport(countersigned), SESSION, DeterministicDeps(), None, lambda *_: True, True)
    performed: list[bool] = []
    with pytest.raises(AmcpAbortedError, match='hash-mismatch'):
        session.audited(
            'db.write', {'kind': 'table', 'ref': 'notes'}, lambda: performed.append(True), mutates=True, egress=False
        )
    assert performed == []


class _FlakyTransport:
    """Answers the first attempt `unavailable`, then forwards to the host."""

    def __init__(self, host: AuditHost) -> None:
        """Bind to the host."""
        self._host = host
        self._first = True

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Forward, with the host unavailable for the first attempt only."""
        self._host.unavailable = self._first
        self._first = False
        try:
            return self._host.handle_attempt(event)
        finally:
            self._host.unavailable = False

    def send_outcome(self, event: dict) -> None:
        """Forward the outcome."""
        self._host.handle_outcome(event)


def test_the_identical_attempt_is_sent_again_and_the_operation_performed_once() -> None:
    """§6, §7.1: after `unavailable` the identical attempt is accepted and the operation runs once."""
    host = AuditHost('t#d')
    session = AmcpSession(_FlakyTransport(host), host.open_session(), DeterministicDeps(), attempt_retries=1)
    performed: list[bool] = []
    session.audited(
        'db.write', {'kind': 'table', 'ref': 'notes'}, lambda: performed.append(True), mutates=True, egress=False
    )
    assert performed == [True]
    assert [r.event['outcome'] for r in host.records()] == ['attempted', 'success']


class _OutcomeFailsTransport:
    """Delivers attempts to a host, then fails to deliver the first outcome."""

    def __init__(self, host: AuditHost) -> None:
        """Wrap the host and fail once."""
        self._inner = InProcessTransport(host)
        self.failed = False

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Deliver the attempt."""
        return self._inner.send_attempt(event)

    def send_outcome(self, event: dict) -> None:
        """Fail the first outcome, deliver the rest."""
        if not self.failed:
            self.failed = True
            raise OSError('the wire went away')
        self._inner.send_outcome(event)


def test_a_performed_action_whose_outcome_is_lost_is_neither_failed_nor_raised() -> None:
    """The success outcome is emitted after the action, outside its error path (§10.8)."""
    host = AuditHost('t#d')
    transport = _OutcomeFailsTransport(host)
    session = AmcpSession(transport, host.open_session(), DeterministicDeps())
    performed: list[int] = []
    out = session.audited(
        'db.write', {'kind': 'table', 'ref': 'orders'}, lambda: performed.append(1) or 'ok', mutates=True, egress=False
    )
    assert out == 'ok'
    assert performed == [1]
    assert [r.event['outcome'] for r in host.records()] == ['attempted']
