"""Tests for reconciliation: boundary egress vs self-report.

The tool's external geocoding call is the egress under audit: it mutates nothing, but it sends
tenant data past the governance boundary to a third party. Reconciliation compares what the tool
self-reported against what the boundary (a gateway) actually observed.
"""

from auditable_mcp.amcp import AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2.reconcile import BoundaryObserver, reconcile
from auditable_mcp.sql_analyst_tool import GEOCODER, SqlAnalystTool

QUESTION = 'What were the high-value customer trends in the Tokyo area last month?'


SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


def _new_tool(host: AuditHost) -> SqlAnalystTool:
    """Build a SQL analyst tool bound to an in-process session."""
    return SqlAnalystTool(AmcpSession(InProcessTransport(host), host.open_session(SESSION), DeterministicDeps()))


def test_no_anomaly_when_matched() -> None:
    """A self-reported egress matching a boundary observation raises no anomaly."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    _new_tool(host).analyze(QUESTION)
    boundary.observe_egress(SESSION, GEOCODER)
    assert reconcile(host.records(), boundary.for_session(SESSION), SESSION) == []


def test_detects_suppression() -> None:
    """An egress the boundary saw but the tool never reported is detected as suppression."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    # The tool called out and the gateway saw it, but the tool emitted no audit event. This is
    # the suppression that signatures and sequence gaps cannot catch.
    boundary.observe_egress(SESSION, GEOCODER)
    anomalies = reconcile(host.records(), boundary.for_session(SESSION), SESSION)
    assert len(anomalies) == 1
    assert anomalies[0].kind == 'unreported-egress'
    assert anomalies[0].destination == GEOCODER


def test_anomalies_sorted_by_destination() -> None:
    """Anomalies come back in a stable sorted order regardless of observation order (per-port determinism)."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    # Set iteration is hash-randomized (PYTHONHASHSEED). Use enough distinct destinations in a
    # deliberately unsorted order that an accidentally pre-sorted iteration (which would let a
    # missing sort pass) is negligible (~1/720 per seed); the result must always be sorted.
    for destination in ['zeta', 'mid', 'alpha', 'yankee', 'bravo', 'kilo']:
        boundary.observe_egress(SESSION, destination)
    anomalies = reconcile(host.records(), boundary.for_session(SESSION), SESSION)
    assert [a.destination for a in anomalies] == ['alpha', 'bravo', 'kilo', 'mid', 'yankee', 'zeta']


def test_self_report_without_observation_is_not_flagged() -> None:
    """A self-reported egress the boundary did not observe is not an anomaly (boundary blind spot)."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    _new_tool(host).analyze(QUESTION)
    assert reconcile(host.records(), boundary.for_session(SESSION), SESSION) == []


def test_external_call_is_read_only_yet_egresses() -> None:
    """The external geocoding lookup mutates nothing but still egresses; the internal query does not."""
    host = AuditHost('t#d')
    _new_tool(host).analyze(QUESTION)
    events = [record.event for record in host.records()]
    geocode = next(event for event in events if event['action_type'] == 'ext.geocode')
    assert geocode['mutates'] is False
    assert geocode['egress'] is True
    query = next(event for event in events if event['action_type'] == 'db.query')
    assert query['egress'] is False
