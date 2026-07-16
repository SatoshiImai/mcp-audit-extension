'''A reproducible L1 scenario shared by the demo and the tests.

A first-party customer DB tool performs a few internal reads/writes; every operation is
self-attested and sealed.
'''

from a_mcp.amcp import AmcpSession, DeterministicDeps
from a_mcp.customer_db_tool import CustomerDbTool
from a_mcp.host import AuditHost
from a_mcp.in_process import InProcessTransport


def run_clean_scenario(partition: str = 'acme#2026-07-15') -> AuditHost:
    '''Run the clean scenario and return the host holding the sealed ledger.'''
    host = AuditHost(partition)
    session = AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps())
    tool = CustomerDbTool(session)
    tool.get_customer('c_1')
    tool.update_email('c_1', 'new@acme.example')
    tool.get_customer('c_2')
    return host
    # end def
