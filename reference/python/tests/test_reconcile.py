"""Tests for reconciliation: boundary egress vs self-report.

The tool's SQL query is the egress under audit: it mutates nothing, but the query leaves the
trust boundary to reach the database. Reconciliation compares what the tool self-reported
against what the boundary (a gateway) actually observed.
"""

from auditable_mcp.amcp import AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2.reconcile import BoundaryObserver, reconcile
from auditable_mcp.sql_analyst_tool import ANALYTICS_DB, SqlAnalystTool

QUESTION = 'What were the high-value customer trends in the Tokyo area last month?'


def _new_tool(host: AuditHost) -> SqlAnalystTool:
    """Build a SQL analyst tool bound to an in-process session."""
    return SqlAnalystTool(AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps()))


def test_no_anomaly_when_matched() -> None:
    """A self-reported query egress matching a boundary observation raises no anomaly."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    _new_tool(host).analyze(QUESTION)
    boundary.observe_egress('call_abc', ANALYTICS_DB)
    assert reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc') == []


def test_detects_suppression() -> None:
    """A query the boundary saw but the tool never reported is detected as suppression."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    # The query egressed and the gateway saw it, but the tool emitted no audit event. This is
    # the suppression that signatures and sequence gaps cannot catch.
    boundary.observe_egress('call_abc', ANALYTICS_DB)
    anomalies = reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc')
    assert len(anomalies) == 1
    assert anomalies[0].kind == 'unreported-egress'
    assert anomalies[0].destination == ANALYTICS_DB


def test_anomalies_sorted_by_destination() -> None:
    """Anomalies come back in a stable sorted order regardless of observation order (per-port determinism)."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    # Set iteration is hash-randomized (PYTHONHASHSEED). Use enough distinct destinations in a
    # deliberately unsorted order that an accidentally pre-sorted iteration (which would let a
    # missing sort pass) is negligible (~1/720 per seed); the result must always be sorted.
    for destination in ['zeta', 'mid', 'alpha', 'yankee', 'bravo', 'kilo']:
        boundary.observe_egress('call_abc', destination)
    anomalies = reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc')
    assert [a.destination for a in anomalies] == ['alpha', 'bravo', 'kilo', 'mid', 'yankee', 'zeta']


def test_self_report_without_observation_is_not_flagged() -> None:
    """A self-reported egress the boundary did not observe is not an anomaly (boundary blind spot)."""
    host = AuditHost('t#d')
    boundary = BoundaryObserver()
    _new_tool(host).analyze(QUESTION)
    assert reconcile(host.records(), boundary.for_call('call_abc'), 'call_abc') == []


def test_query_is_read_only_yet_egresses() -> None:
    """The point of the example: a SELECT mutates nothing but the query still leaves."""
    host = AuditHost('t#d')
    _new_tool(host).analyze(QUESTION)
    event = host.records()[0].event
    assert event['action_type'] == 'db.query'
    assert event['mutates'] is False
    assert event['egress'] is True
