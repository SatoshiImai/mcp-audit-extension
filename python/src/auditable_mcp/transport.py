"""Wire-shaped audit transport interface (mirror of the TypeScript AuditTransport).

Shaped to the MCP elicitation wire: a request/response for attempt, a fire-and-forget for
outcome, plus capability negotiation. Keeping it faithful is what makes the in-process
implementation zero-waste versus a later MCP-backed transport.
"""

from dataclasses import dataclass
from typing import Protocol

from auditable_mcp.capability import AuditCapability


@dataclass(frozen=True)
class AttemptResponse:
    """Host response to audit/attempt.

    ``accept`` = record durably persisted (proceed). ``reject`` = the record is a lie into
    the ledger (do not proceed). ``unavailable`` = infra could not persist (do not proceed,
    retryable). None of these authorize the domain action; fail-closed here is about record
    completeness, not action control (design §6.1).
    """

    status: str  # 'accept' | 'reject' | 'unavailable'
    seq: int | None = None
    record_hash: str | None = None
    reason: str | None = None
    retryable: bool | None = None
    # end class


def accept(seq: int, record_hash: str) -> AttemptResponse:
    """Build an accept response (record durably persisted)."""
    return AttemptResponse(status='accept', seq=seq, record_hash=record_hash)
    # end def


def reject(reason: str) -> AttemptResponse:
    """Build a reject response (a lie into the ledger was refused)."""
    return AttemptResponse(status='reject', reason=reason)
    # end def


def unavailable(reason: str) -> AttemptResponse:
    """Build an unavailable response (infra failure, retryable)."""
    return AttemptResponse(status='unavailable', reason=reason, retryable=True)
    # end def


class AuditTransport(Protocol):
    """Transport between a tool and the host audit subsystem."""

    def negotiate(self) -> AuditCapability:
        """Return the host-declared audit capability."""
        ...
        # end def

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Send audit/attempt and block for the host response."""
        ...
        # end def

    def send_outcome(self, event: dict) -> None:
        """Send audit/outcome (not a completeness gate)."""
        ...
        # end def

    # end class
