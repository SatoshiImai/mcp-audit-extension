"""Audit transport protocol interface.

Defines the request/response pattern for attempts, outcomes, and capability negotiation.
"""

from dataclasses import asdict, dataclass
from typing import Protocol

from auditable_mcp.capability import AuditCapability, NegotiationResult


@dataclass(frozen=True)
class AttemptResponse:
    """The host's answer to an attempt (§7.1).

    - `accept`: the record is sealed.
    - `reject`: the record will not be sealed.
    - `unavailable`: nothing was decided; the identical attempt may be sent again (§7.1).
    """

    status: str  # 'accept' | 'reject' | 'unavailable'
    seq: int | None = None
    record_hash: str | None = None
    # host_ts and previous_hash let the tool recompute the record hash and self-verify the seal.
    host_ts: str | None = None
    previous_hash: str | None = None
    reason: str | None = None
    # The countersignature triple appears together or not at all (§7.1). A host declaring `none`
    # returns none of it; one declaring `host` returns all of it on every accept (§5.2).
    host_signature: str | None = None
    host_key_id: str | None = None
    log_id: str | None = None


class AuditTransportError(Exception):
    """The transport could not carry an attempt or its answer: a fault or a protocol error (§6)."""


def response_members(response: AttemptResponse) -> dict:
    """Return the members an Attempt Response carries on the wire: the fields that are set."""
    return {name: value for name, value in asdict(response).items() if value is not None}


def accept(
    seq: int,
    record_hash: str,
    host_ts: str,
    previous_hash: str,
    host_signature: str | None = None,
    host_key_id: str | None = None,
    log_id: str | None = None,
) -> AttemptResponse:
    """Build an accept carrying what the tool needs to recompute the hash, and the countersignature if any."""
    return AttemptResponse(
        status='accept',
        seq=seq,
        record_hash=record_hash,
        host_ts=host_ts,
        previous_hash=previous_hash,
        host_signature=host_signature,
        host_key_id=host_key_id,
        log_id=log_id,
    )


def reject(reason: str) -> AttemptResponse:
    """Build a reject response."""
    return AttemptResponse(status='reject', reason=reason)


def unavailable(reason: str) -> AttemptResponse:
    """Build an unavailable response."""
    return AttemptResponse(status='unavailable', reason=reason)


class AuditTransport(Protocol):
    """Transport between a tool and the host audit subsystem."""

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Exchange capabilities: present the tool's offer, receive the host requirement and fit."""
        ...

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Send an attempt and block for the host's answer (§6).

        Raises:
            AuditTransportError: No answer came: a transport fault or a protocol error.
            OSError: The transport's I/O failed.
            TimeoutError: The bound on the wait elapsed.
        """
        ...

    def send_outcome(self, event: dict) -> None:
        """Send an outcome, which has no answer (§6)."""
        ...
