"""Tests for the AmcpSession audit-before-act discipline."""

import pytest

from auditable_mcp.amcp import AmcpBlockedError, AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport


def _session(host: AuditHost) -> AmcpSession:
    """Build an in-process session bound to the host."""
    return AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps())
    # end def


def test_emits_attempt_then_performs_then_outcome() -> None:
    """Attempt is accepted, the action runs, then a success outcome is sealed."""
    host = AuditHost('t#d')
    session = _session(host)
    calls: list[int] = []

    def perform() -> str:
        calls.append(1)
        return 'result'
        # end def

    out = session.audited(
        'db.read', {'kind': 'table', 'ref': 'customers'}, {'q': 1}, perform, mutates=False, egress=False
    )
    assert out == 'result'
    assert len(calls) == 1
    outcomes = [r.event['outcome'] for r in host.records()]
    assert outcomes == ['attempted', 'success']
    # end def


def test_does_not_perform_when_unavailable() -> None:
    """When the host is unavailable, the action is not performed (fail-closed)."""
    host = AuditHost('t#d')
    host.unavailable = True
    session = _session(host)
    performed: list[int] = []

    with pytest.raises(AmcpBlockedError):
        session.audited(
            'db.write',
            {'kind': 'table', 'ref': 'customers'},
            {},
            lambda: performed.append(1),
            mutates=True,
            egress=False,
        )
        # end with
    assert performed == []
    assert len(host.records()) == 0
    # end def


def test_seals_failed_outcome_and_reraises() -> None:
    """When the action raises, a failed outcome is sealed and the error re-raised."""
    host = AuditHost('t#d')
    session = _session(host)

    def boom() -> None:
        raise RuntimeError('boom')
        # end def

    with pytest.raises(RuntimeError):
        session.audited('db.write', {'kind': 'table', 'ref': 'customers'}, {}, boom, mutates=True, egress=False)
        # end with
    outcomes = [r.event['outcome'] for r in host.records()]
    assert outcomes == ['attempted', 'failed']
    # end def
