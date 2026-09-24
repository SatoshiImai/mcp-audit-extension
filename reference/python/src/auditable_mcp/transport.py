"""Audit transport protocol interface.

Defines the request/response pattern for attempts, outcomes, and capability negotiation.
"""

from dataclasses import dataclass
from typing import Protocol

from auditable_mcp.capability import AuditCapability, NegotiationResult


@dataclass(frozen=True)
class AttemptResponse:
    """Host response to audit/attempt.

    - `accept`: Record durably persisted.
    - `reject`: Invalid record.
    - `unavailable`: Transient persistence failure.
    """

    status: str  # 'accept' | 'reject' | 'unavailable'
    seq: int | None = None
    record_hash: str | None = None
    # host_ts and previous_hash let the tool recompute the record hash and self-verify the seal.
    host_ts: str | None = None
    previous_hash: str | None = None
    reason: str | None = None
    retryable: bool | None = None
    # The witness pair appears together or not at all (§7.1). A host declaring `none` returns
    # neither; one declaring `host` returns both on every accept (§5.2).
    host_signature: str | None = None
    host_key_id: str | None = None


def accept(
    seq: int,
    record_hash: str,
    host_ts: str,
    previous_hash: str,
    host_signature: str | None = None,
    host_key_id: str | None = None,
) -> AttemptResponse:
    """Build an accept carrying what the tool needs to recompute the hash, and the witness if signed."""
    return AttemptResponse(
        status='accept',
        seq=seq,
        record_hash=record_hash,
        host_ts=host_ts,
        previous_hash=previous_hash,
        host_signature=host_signature,
        host_key_id=host_key_id,
    )


def reject(reason: str) -> AttemptResponse:
    """Build a reject response."""
    return AttemptResponse(status='reject', reason=reason)


def unavailable(reason: str) -> AttemptResponse:
    """Build an unavailable response."""
    return AttemptResponse(status='unavailable', reason=reason, retryable=True)


class AuditTransport(Protocol):
    """Transport between a tool and the host audit subsystem."""

    def negotiate(self, offered: AuditCapability) -> NegotiationResult:
        """Exchange capabilities: present the tool's offer, receive the host requirement and fit."""
        ...

    def send_attempt(self, event: dict) -> AttemptResponse:
        """Send audit/attempt and block for the host response."""
        ...

    def send_outcome(self, event: dict) -> None:
        """Send audit/outcome (not a completeness gate)."""
        ...
