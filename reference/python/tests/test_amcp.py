"""Tests for the AmcpSession audit-before-act discipline."""

import pytest

from auditable_mcp.amcp import AmcpAbortedError, AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2.keys import generate_tool_key
from auditable_mcp.l2.signing import Ed25519Signer
from auditable_mcp.transport import AttemptResponse


def _l2_signer() -> Ed25519Signer:
    """Build an Ed25519 signer, whose presence marks a session as Level 2."""
    key = generate_tool_key('polluted-stop-key')
    return Ed25519Signer(key.key_id, key.private_key)


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
    return AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps())


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
            status='accept', seq=0, record_hash='deadbeef', host_ts='2026-07-15T00:00:01.000Z', previous_hash='0' * 64
        )
    )
    session = AmcpSession(transport, 'call_abc', DeterministicDeps(), _l2_signer())
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
            status='accept', seq=0, record_hash='deadbeef', host_ts='2026-07-15T00:00:01.000Z', previous_hash='0' * 64
        )
    )
    session = AmcpSession(transport, 'call_abc', DeterministicDeps())
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
    session = AmcpSession(transport, 'call_abc', DeterministicDeps())
    with pytest.raises(AmcpAbortedError):
        session.audited('db.write', {'kind': 'table', 'ref': 'notes'}, lambda: None, mutates=True, egress=False)
    assert transport.outcomes[-1]['outcome'] == 'aborted'
    assert transport.outcomes[-1]['reason'] == 'host-rejected'


def test_unavailable_emits_aborted_with_reason() -> None:
    """An unavailable host yields an aborted outcome carrying reason=host-unavailable."""
    transport = _StubTransport(AttemptResponse(status='unavailable', reason='persistence-failure', retryable=True))
    session = AmcpSession(transport, 'call_abc', DeterministicDeps())
    with pytest.raises(AmcpAbortedError):
        session.audited('db.read', {'kind': 'table', 'ref': 'notes'}, lambda: None, mutates=False, egress=False)
    assert transport.outcomes[-1]['outcome'] == 'aborted'
    assert transport.outcomes[-1]['reason'] == 'host-unavailable'
