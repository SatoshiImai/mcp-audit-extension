"""Verifier: prove non-tampering + completeness over a sealed ledger (the evidence artifact).

Recomputes the hash chain from the record bytes, detects sequence gaps (loss), checks the
anchored digest, and correlates attempts with outcomes. It trusts nothing but the bytes.
Chaining on the RECOMPUTED hash means any mutation of an event body propagates to the tail,
so a single tampered field breaks the anchored digest -- that is the tamper proof.
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
    # end class


@dataclass
class VerifyReport:
    """The result of verifying a ledger."""

    ok: bool
    count: int
    computed_digest: str
    issues: list[VerifyIssue]
    # end class


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
            # end if
        if rec.seq != i:
            kind = 'seq-gap' if rec.seq > i else 'seq-out-of-order'
            issues.append(VerifyIssue(seq=rec.seq, kind=kind, detail=f'expected seq {i}, got {rec.seq}'))
            # end if
        recomputed = compute_record_hash(rec.event, rec.seq, rec.host_ts, prev_recomputed)
        if rec.prev_hash != prev_recomputed:
            issues.append(
                VerifyIssue(seq=rec.seq, kind='prev-hash-mismatch', detail='prev_hash does not link to previous record')
            )
            # end if
        if rec.record_hash != recomputed:
            issues.append(
                VerifyIssue(seq=rec.seq, kind='record-hash-mismatch', detail='stored record_hash != recomputed')
            )
            # end if
        outcome = rec.event['outcome']
        if outcome == 'attempted':
            attempted_ids.add(rec.event['id'])
        elif rec.event['id'] not in attempted_ids:
            issues.append(
                VerifyIssue(
                    seq=rec.seq, kind='outcome-without-attempt', detail=f'outcome={outcome} id={rec.event["id"]}'
                )
            )
            # end if
        prev_recomputed = recomputed
        # end for

    computed_digest = prev_recomputed
    if anchored_digest is not None and anchored_digest != computed_digest:
        issues.append(
            VerifyIssue(
                seq=None, kind='digest-mismatch', detail=f'anchored {anchored_digest} != computed {computed_digest}'
            )
        )
        # end if
    return VerifyReport(ok=len(issues) == 0, count=len(records), computed_digest=computed_digest, issues=issues)
    # end def
