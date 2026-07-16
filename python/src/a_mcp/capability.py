"""Host-declared audit capability (design §3.3).

The host owns the guarantee level; the tool complies or fails observably. Declaration flows
host->tool only, so an untrusted tool cannot weaken record integrity via what it declares.
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
    # end class


DEFAULT_L1_CAPABILITY = AuditCapability()
