"""A reproducible clean L1 scenario shared by the demo, the tests, and the chain conformance vector.

One host call drives a data-analysis tool that runs a raw SQL query the host never sees, enriches
the result via an external service, then caches it: three internal operations spanning the
(mutates, egress) axis and both confidentiality choices of §4.3.
"""

from auditable_mcp.amcp import AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.sql_analyst_tool import SqlAnalystTool

# The audit session of the clean scenario (§6.3). Fixed so the chain vector is reproducible.
SCENARIO_SESSION_ID = '0198f3a2-5c1e-7000-8000-00000000abc0'


def run_clean_scenario(partition: str = 'acme#2026-07-15') -> AuditHost:
    """Run the clean scenario and return the host holding the sealed ledger."""
    host = AuditHost(partition)
    session_id = host.open_session(SCENARIO_SESSION_ID)
    session = AmcpSession(InProcessTransport(host), session_id, DeterministicDeps())
    tool = SqlAnalystTool(session)
    tool.analyze('What were the high-value customer trends in the Tokyo area last month?')
    host.close_session(session_id)
    return host
