"""Host-declared audit capability requirements.

Declarations flow strictly from host to tool. Tools must comply with the declared
level and disposition parameters, or fail observably.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AuditCapability:
    """The audit requirements a host declares."""

    level: str = 'L1'  # 'L1' | 'L2'
    attempt: str = 'request'  # attempt is always a blocking request (fail-closed)
    attempt_ack_deadline_ms: int = 500
    block_disposition: tuple[str, ...] = ('abort',)  # 'abort' is the safe floor; 'partial' is opt-in
    outcome_mode: str = 'batched'  # 'batched' | 'request'
    outcome_batch_window_ms: int = 200


DEFAULT_L1_CAPABILITY = AuditCapability()
