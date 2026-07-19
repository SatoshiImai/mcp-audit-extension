"""In-process transport implementation.

Directly couples the tool to the host audit subsystem without network overhead.
Used primarily for testing and local demonstration.
"""

from auditable_mcp.capability import AuditCapability, NegotiationResult
from auditable_mcp.host import AuditHost
from auditable_mcp.transport import AttemptResponse


class InProcessTransport:
    """Direct in-process transport implementing the AuditTransport protocol."""

    def __init__(self, host: AuditHost) -> None:
        """Bind the transport to a host audit subsystem."""
        self._host = host

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Forward the tool's offered capability to the host and return the negotiation result."""
        return self._host.negotiate(offered)

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Forward audit/attempt to the host."""
        return self._host.handle_attempt(event)

    def send_outcome(self, event: dict) -> None:
        """Forward audit/outcome to the host."""
        self._host.handle_outcome(event)
