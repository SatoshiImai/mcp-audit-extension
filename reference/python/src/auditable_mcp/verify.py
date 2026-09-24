"""Verify non-tampering and completeness over a sealed ledger (§11.4).

Recomputes the hash chain from the record bytes, detects seq gaps, checks the anchored digest, and
correlates attempts with outcomes. The chain is recomputed rather than read from the stored hashes,
so any mutation of an event body propagates to the tail digest.

Witness determination (§5.2) is part of the verifier's job and needs the out-of-band registry that
binds `host_key_id` to a host's key. §11.4 requires a verifier without it to report that the check
did not run, rather than return a result in which its anomalies are simply absent: an unchecked
signature and a valid one are not the same finding.

§11.4's Identity Matching is conditional - "where the deployment binds identity (§10.10)" - and this
demonstration seals a bare a-MCP event for one principal, so nothing binds one. §10.10 says a
single-principal deployment needs neither construction; a deployment that stores records for more
than one principal in a shared medium wraps them (SEP-3004) or binds the identity inside the sealed
record, and its verifier compares that against an expectation supplied out-of-band.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from auditable_mcp.ledger import GENESIS_HASH, SealedRecord, compute_record_hash, witness_payload
from auditable_mcp.schema import validate_event

# Resolves a `host_key_id` and verifies a witness signature over the canonical host-assigned fields.
WitnessChecker = Callable[[str, str, str], bool]


@dataclass
class VerifyIssue:
    """A single verification failure."""

    seq: int | None
    kind: str
    detail: str


@dataclass
class VerifyReport:
    """The result of verifying a ledger.

    `ok` is True when the checks that ran found nothing. It is not the same as having checked
    everything: `unchecked` names every check that was applicable and did not run (§11.4), and
    `complete` is the answer a caller wants when it means "verified".
    """

    ok: bool
    count: int
    computed_digest: str
    issues: list[VerifyIssue]
    unchecked: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True when nothing was found and nothing applicable was skipped (§11.4)."""
        return self.ok and not self.unchecked


def verify_ledger(
    records: list[SealedRecord],
    anchored_digest: str | None = None,
    witness_checker: WitnessChecker | None = None,
) -> VerifyReport:
    """Verify a sealed ledger for non-tampering and completeness.

    Args:
        records: The sealed records in order.
        anchored_digest: An out-of-band anchored digest to compare against, if available.
        witness_checker: Resolves a `host_key_id` and verifies a witness signature over the
            canonical host-assigned fields (§7.1). A record carrying no signature is unwitnessed,
            which is a state and not an anomaly (§5.2); one whose signature fails verification is
            reported `host-signature-invalid`. Without a checker, records that do carry a signature
            are counted in `unchecked` rather than treated as verified (§11.4).

    Returns:
        A report; ``ok`` is True only when there are no issues.
    """
    issues: list[VerifyIssue] = []
    attempted_ids: set[str] = set()
    prev_recomputed = GENESIS_HASH
    witness_unchecked = False

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
        # §11.4 Witness Determination: established from the record's own signature, never inferred
        # from any other field. A half-present pair is not a conforming record (§7.1).
        if (rec.host_signature is None) != (rec.host_key_id is None):
            issues.append(
                VerifyIssue(
                    seq=rec.seq,
                    kind='host-signature-invalid',
                    detail='half-pair: host_signature and host_key_id appear together or not at all',
                )
            )
        elif rec.host_signature is not None and rec.host_key_id is not None:
            if witness_checker is None:
                witness_unchecked = True
            else:
                payload = witness_payload(rec.seq, rec.host_ts, rec.previous_hash, rec.record_hash)
                if not witness_checker(rec.host_key_id, rec.host_signature, payload):
                    issues.append(
                        VerifyIssue(
                            seq=rec.seq,
                            kind='host-signature-invalid',
                            detail=f'witness signature does not verify against {rec.host_key_id}',
                        )
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
    return VerifyReport(
        ok=len(issues) == 0,
        count=len(records),
        computed_digest=computed_digest,
        issues=issues,
        unchecked=['witness'] if witness_unchecked else [],
    )
