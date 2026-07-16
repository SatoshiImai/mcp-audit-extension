"""Tests for reconciliation: boundary egress vs self-report.

The tool's web search is the egress under audit: it mutates nothing, but the query leaves the
trust boundary. Reconciliation compares what the tool self-reported against what the boundary
(a gateway) actually observed.
"""

from auditable_mcp.amcp import AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2.reconcile import BoundaryObserver, reconcile
from auditable_mcp.research_tool import SEARCH_ENDPOINT, ResearchTool

QUERY = 'acme corp merger due diligence'


def _new_tool(host: AuditHost) -> ResearchTool:
    """Build a research tool bound to an in-process session."""
    return ResearchTool(AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps()))
    # end def


def test_no_anomaly_when_matched() -> None:
    """A self-reported search egress matching a boundary observation raises no anomaly."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    _new_tool(host).search(QUERY)
    boundary.observe_egress('call_abc', SEARCH_ENDPOINT)
    assert reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc') == []
    # end def


def test_detects_suppression() -> None:
    """A search the boundary saw but the tool never reported is detected as suppression."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    # The query egressed and the gateway saw it, but the tool emitted no audit event. This is
    # the lie that signatures and sequence gaps cannot catch.
    boundary.observe_egress('call_abc', SEARCH_ENDPOINT)
    anomalies = reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc')
    assert len(anomalies) == 1
    assert anomalies[0].kind == 'unreported-egress'
    assert anomalies[0].destination == SEARCH_ENDPOINT
    # end def


def test_flags_self_report_without_observation() -> None:
    """A self-reported egress with no boundary observation is flagged."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    _new_tool(host).search(QUERY)
    anomalies = reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc')
    assert any(a.kind == 'unobserved-egress' for a in anomalies)
    # end def


def test_search_is_read_only_yet_egresses() -> None:
    """The point of the example: a search mutates nothing but the query still leaves."""
    host = AuditHost('t#d')
    _new_tool(host).search(QUERY)
    event = host.records()[0].event
    assert event['action_type'] == 'api.request'
    assert event['mutates'] is False
    assert event['egress'] is True
    # end def
