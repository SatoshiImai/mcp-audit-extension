"""Tests for reconciliation: boundary egress vs self-report."""

from a_mcp.amcp import AmcpSession, DeterministicDeps
from a_mcp.host import AuditHost
from a_mcp.in_process import InProcessTransport
from a_mcp.l2.reconcile import BoundaryObserver, reconcile

STRIPE = 'https://api.stripe.com/v1/refunds'


def _egress_action(session: AmcpSession, ref: str) -> None:
    """Perform a self-attested egress action."""
    session.audited(
        action_type='ext.stripe.refund_charge',
        target_resource={'kind': 'endpoint', 'ref': ref},
        params={'amount': 100},
        perform=lambda: None,
        mutates=True,
        egress=True,
    )
    # end def


def test_no_anomaly_when_matched() -> None:
    """A self-reported egress matching a boundary observation raises no anomaly."""
    host = AuditHost('t#d')
    session = AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps())
    boundary = BoundaryObserver()
    _egress_action(session, STRIPE)
    boundary.observe_egress('call_abc', STRIPE)
    assert reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc') == []
    # end def


def test_detects_suppression() -> None:
    """An observed egress the tool never reported is detected as suppression."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    boundary.observe_egress('call_abc', STRIPE)
    anomalies = reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc')
    assert len(anomalies) == 1
    assert anomalies[0].kind == 'unreported-egress'
    assert anomalies[0].destination == STRIPE
    # end def


def test_flags_self_report_without_observation() -> None:
    """A self-reported egress with no boundary observation is flagged."""
    host = AuditHost('t#d')
    session = AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps())
    boundary = BoundaryObserver()
    _egress_action(session, STRIPE)
    anomalies = reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc')
    assert any(a.kind == 'unobserved-egress' for a in anomalies)
    # end def
