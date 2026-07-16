"""A reproducible L1 scenario shared by the demo and the tests.

A first-party research tool performs three internal operations that deliberately span the
(mutates, egress) axis: a web search (read-only, yet the query egresses), a note write, and
a note read.
"""

from auditable_mcp.amcp import AmcpSession, DeterministicDeps
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.research_tool import ResearchTool


def run_clean_scenario(partition: str = 'acme#2026-07-15') -> AuditHost:
    """Run the clean scenario and return the host holding the sealed ledger."""
    host = AuditHost(partition)
    session = AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps())
    tool = ResearchTool(session)
    tool.search('acme corp merger due diligence')  # api.request -- mutates=0, egress=1
    tool.save_note('acme', 'merger rumour confirmed by two sources')  # db.write
    tool.list_notes()  # db.read
    return host
    # end def
