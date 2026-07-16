'''In-process transport: the tool calls the host directly.

This is the only asset superseded when a later MCP-backed transport is swapped in, and it
survives as a fast test double. Everything above the transport interface is reused.
'''

from a_mcp.capability import AuditCapability
from a_mcp.host import AuditHost
from a_mcp.transport import AttemptResponse


class InProcessTransport:
    '''Direct in-process transport implementing the AuditTransport protocol.'''

    def __init__(self, host: AuditHost) -> None:
        '''Bind the transport to a host audit subsystem.'''
        self._host = host
        # end def

    def negotiate(self) -> AuditCapability:
        '''Return the host-declared audit capability.'''
        return self._host.negotiate()
        # end def

    def send_attempt(self, event: dict) -> AttemptResponse:
        '''Forward audit/attempt to the host.'''
        return self._host.handle_attempt(event)
        # end def

    def send_outcome(self, event: dict) -> None:
        '''Forward audit/outcome to the host.'''
        self._host.handle_outcome(event)
        # end def
    # end class
