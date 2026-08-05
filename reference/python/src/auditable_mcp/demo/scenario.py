"""A reproducible clean L1 scenario shared by the demo, the tests, and the chain conformance vector.

One host call drives a data-analysis tool that runs a raw SQL query the host never sees, enriches
the result via an external service, then caches it: three internal operations spanning the
(mutates, egress) axis and both confidentiality choices of §4.3.
"""

from auditable_mcp.amcp import AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.sql_analyst_tool import SqlAnalystTool


def run_clean_scenario(partition: str = 'acme#2026-07-15') -> AuditHost:
    """Run the clean scenario and return the host holding the sealed ledger."""
    host = AuditHost(partition)
    session = AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps())
    tool = SqlAnalystTool(session)
    tool.analyze('What were the high-value customer trends in the Tokyo area last month?')
    return host
