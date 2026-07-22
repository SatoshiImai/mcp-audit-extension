"""Verify non-tampering and completeness over a sealed ledger.

Recomputes the hash chain from the record bytes, detects seq gaps, checks the anchored
digest, and correlates attempts with outcomes. The chain is recomputed rather than read from
the stored hashes, so any mutation of an event body propagates to the tail digest.
"""

from dataclasses import dataclass

from auditable_mcp.ledger import GENESIS_HASH, SealedRecord, compute_record_hash
from auditable_mcp.schema import validate_event


@dataclass
class VerifyIssue:
    """A single verification failure."""

    seq: int | None
    kind: str
    detail: str


@dataclass
class VerifyReport:
    """The result of verifying a ledger."""

    ok: bool
    count: int
    computed_digest: str
    issues: list[VerifyIssue]


def verify_ledger(records: list[SealedRecord], anchored_digest: str | None = None) -> VerifyReport:
    """Verify a sealed ledger for non-tampering and completeness.

    Args:
        records: The sealed records in order.
        anchored_digest: An out-of-band anchored digest to compare against, if available.

    Returns:
        A report; ``ok`` is True only when there are no issues.
    """
    issues: list[VerifyIssue] = []
    attempted_ids: set[str] = set()
    prev_recomputed = GENESIS_HASH

    for i, rec in enumerate(records):
        error = validate_event(rec.event)
        if error is not None:
            issues.append(VerifyIssue(seq=rec.seq, kind='schema-invalid', detail=error))
        if rec.seq != i:
            # Tier-1 seq-gap (§7.6); the sub-kind (gap vs out-of-order) goes in detail.
            sub = 'gap' if rec.seq > i else 'out-of-order'
            issues.append(VerifyIssue(seq=rec.seq, kind='seq-gap', detail=f'{sub}: expected seq {i}, got {rec.seq}'))
        recomputed = compute_record_hash(rec.event, rec.seq, rec.host_ts, prev_recomputed)
        if rec.previous_hash != prev_recomputed:
            issues.append(
                VerifyIssue(
                    seq=rec.seq,
                    kind='record-hash-mismatch',
                    detail='prev-hash: previous_hash does not link to previous record',
                )
            )
        if rec.record_hash != recomputed:
            issues.append(
                VerifyIssue(seq=rec.seq, kind='record-hash-mismatch', detail='stored record_hash != recomputed')
            )
        outcome = rec.event['outcome']
        if outcome == 'attempted':
            attempted_ids.add(rec.event['id'])
        elif rec.event['id'] not in attempted_ids:
            issues.append(
                VerifyIssue(
                    seq=rec.seq,
                    kind='orphaned-outcome',
                    detail=f'never-accepted: outcome={outcome} id={rec.event["id"]}',
                )
            )
        prev_recomputed = recomputed

    computed_digest = prev_recomputed
    if anchored_digest is not None and anchored_digest != computed_digest:
        issues.append(
            VerifyIssue(
                seq=None, kind='digest-mismatch', detail=f'anchored {anchored_digest} != computed {computed_digest}'
            )
        )
    return VerifyReport(ok=len(issues) == 0, count=len(records), computed_digest=computed_digest, issues=issues)
