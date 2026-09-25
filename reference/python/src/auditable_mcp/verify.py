"""Verify non-tampering and completeness over a sealed ledger (§11.4).

Recomputes the hash chain from the record bytes, detects seq gaps, checks the anchored digest,
correlates attempts with outcomes, and accounts for every Level-2 signer_seq. The chain is
recomputed rather than read from the stored hashes, so any mutation of an event body propagates to
the tail digest. A malformed record is a finding, never an exception: it is reported, and the chain
is checked on either side of it.

Level-2 verification and countersignature determination need the out-of-band registries (§5.1,
§7.1). §11.4 requires a verifier without one to report that the check did not run, rather than
return a result in which its anomalies are simply absent: an unchecked signature and a valid one
are not the same finding.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from auditable_mcp.canonical import canonical_domain_error
from auditable_mcp.capability import SPEC_VERSION
from auditable_mcp.encoding import b64_decode, b64url_decode
from auditable_mcp.l2.keys import KeyRegistry, assert_disjoint_registries
from auditable_mcp.l2.signing import countersignature_check, verify_event_signature
from auditable_mcp.ledger import GENESIS_HASH, SealedRecord, compute_record_hash, countersignature_payload
from auditable_mcp.schema import EARLIER_VERSIONS, check_sealed_event, is_earlier_version

# Resolves a `host_key_id` and verifies a countersignature over the canonical host-assigned fields.
CountersignatureChecker = Callable[[str, str, str], bool]

_REFUSAL_REASONS = frozenset({'host-rejected', 'host-unavailable'})

# Published versions in order; a chain's versions do not go backwards (§11.4).
_VERSION_RANK = {
    version: rank for rank, version in enumerate([*(f'auditable-mcp/{v}' for v in EARLIER_VERSIONS), SPEC_VERSION])
}


@dataclass(frozen=True)
class ExpectedIdentity:
    """The identity a partition is expected to hold, supplied out-of-band (§10.10 construction 1).

    A log_id is distinct only among one host's chains, so the identity is the log_id together with
    the keys that host countersigns under.
    """

    log_id: str
    host_key_ids: frozenset[str]


def _as_event(value: object) -> dict:
    """Return the event as a dict, or an empty one for a value that is not an object."""
    return value if isinstance(value, dict) else {}


def _session_of(event: dict) -> str:
    """Return the audit session of an event: `session_id`, or `call_id` for versions before 0.3."""
    session = event.get('session_id', event.get('call_id'))
    return session if isinstance(session, str) else ''


def _correlation_key(event: dict) -> tuple[str, str]:
    """Return the key an attempt and its outcome share: (session, id) (§7.2)."""
    return _session_of(event), str(event.get('id'))


def _numbered(records: list[SealedRecord]) -> list[tuple[dict, bool]]:
    """Return the current-version events that carry a Level-2 number.

    Each is paired with whether an attempt with the same session_id and id was sealed before it
    (§7.2). Earlier versions numbered per key across calls, not per session, so the per-session
    procedures do not apply to them.
    """
    out: list[tuple[dict, bool]] = []
    attempted: set[tuple[str, str]] = set()
    for rec in records:
        event = _as_event(rec.event)
        correlated = _correlation_key(event) in attempted
        if event.get('outcome') == 'attempted':
            attempted.add(_correlation_key(event))
        signer_seq = event.get('signer_seq')
        if is_earlier_version(event) or not isinstance(event.get('key_id'), str):
            continue
        if not isinstance(event.get('session_id'), str):
            continue
        if isinstance(signer_seq, bool) or not isinstance(signer_seq, int) or signer_seq < 0:
            continue
        out.append((event, correlated))
    return out


def _missing_runs(present: set[int]) -> list[list[int]]:
    """Values from 0 to the largest in ``present`` that are not in it, as maximal ``[first, last]`` runs.

    Computed from the gaps between present values, so a value near 2^53 costs one run, not 2^53 entries.
    """
    runs: list[list[int]] = []
    following = 0
    for value in sorted(present):
        if value > following:
            runs.append([following, value - 1])
        following = value + 1
    return runs


def unaccounted_signer_seq(records: list[SealedRecord]) -> list[dict]:
    """Return the signer_seq runs §11.4's procedure leaves unaccounted, per key and session.

    A verifier does not see the events a host rejected, so a rejected attempt leaves a value missing
    from the sealed sequence; the sealed refusal of that attempt (§7.2) accounts for it. A refusal
    correlates only with an attempt of its own session sealed before it.

    Args:
        records: The sealed records of one partition.

    Returns:
        One ``{key_id, session_id, first, last}`` per maximal run of unaccounted values, in the order of
        first appearance of each key and session and ascending within it.
    """
    groups: dict[tuple[str, str], list[tuple[dict, bool]]] = {}
    for event, correlated in _numbered(records):
        groups.setdefault((event['key_id'], event['session_id']), []).append((event, correlated))
    unaccounted: list[dict] = []
    for (key_id, session_id), events in groups.items():
        missing = _missing_runs({event['signer_seq'] for event, _ in events})
        refusals = sorted(
            event['signer_seq']
            for event, correlated in events
            if event.get('outcome') == 'aborted' and event.get('reason') in _REFUSAL_REASONS and not correlated
        )
        # Each refusal accounts for the smallest value still missing below its own, which is always the
        # first value of the first run.
        for refusal in refusals:
            if not missing or missing[0][0] >= refusal:
                continue
            missing[0][0] += 1
            if missing[0][0] > missing[0][1]:
                missing.pop(0)
        unaccounted.extend(
            {'key_id': key_id, 'session_id': session_id, 'first': first, 'last': last} for first, last in missing
        )
    return unaccounted


def _shared_signer_seq(records: list[SealedRecord]) -> list[dict]:
    """Return one entry for each sealed record after the first sharing a signer_seq in one key and session."""
    seen: set[tuple[str, str, int]] = set()
    shared: list[dict] = []
    for event, _ in _numbered(records):
        slot = (event['key_id'], event['session_id'], event['signer_seq'])
        if slot in seen:
            shared.append({'key_id': slot[0], 'session_id': slot[1], 'signer_seq': slot[2]})
        seen.add(slot)
    return shared


def _identity_mismatch(rec: SealedRecord, present: int, expected: ExpectedIdentity) -> str | None:
    """Return why a record's bound identity does not match the expectation, or None (§10.10)."""
    if present != 3:
        return 'uncountersigned: no countersignature binds the record'
    if rec.log_id != expected.log_id:
        return f'log_id {rec.log_id}'
    if not isinstance(rec.host_key_id, str) or rec.host_key_id not in expected.host_key_ids:
        return f'host_key_id {rec.host_key_id}'
    return None


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
    countersignature_checker: CountersignatureChecker | None = None,
    *,
    key_registry: KeyRegistry | None = None,
    host_key_registry: KeyRegistry | None = None,
    expected_identity: ExpectedIdentity | None = None,
    countersignature_required: bool = False,
) -> VerifyReport:
    """Verify a sealed ledger for non-tampering and completeness.

    Args:
        records: The sealed records in order.
        anchored_digest: An out-of-band anchored digest to compare against, if available.
        countersignature_checker: Resolves a `host_key_id` and verifies a countersignature over the
            canonical host-assigned fields and log_id (§7.1). A record carrying none of the triple is
            uncountersigned, which is a state and not an anomaly (§5.2); one whose signature fails
            verification is reported `host-signature-invalid`.
        key_registry: The registry binding tool key_ids to keys, for Level-2 signatures (§5.1). A
            revoked entry still verifies the records sealed under it (§10.9).
        host_key_registry: The registry binding host_key_ids to keys, in place of a
            `countersignature_checker`.
        expected_identity: The identity the partition is expected to hold, supplied out-of-band
            (§10.10 construction 1). A record naming another log_id, countersigned under a
            host_key_id outside the set, or carrying no countersignature, is `principal-mismatch`.
        countersignature_required: The chain must be countersigned, supplied out-of-band (§11.4). An
            uncountersigned record is then `host-signature-invalid`, since a countersignature can be
            stripped though not forged (§10.1).

    Returns:
        A report; ``ok`` is True only when there are no issues. Without a registry, a check that
        applied is named in ``unchecked`` (`countersignature`, `level-2-signature`).

    Raises:
        ValueError: The tool and host registries share a key (§10.9).
    """
    if key_registry is not None and host_key_registry is not None:
        assert_disjoint_registries(key_registry, host_key_registry)
    check_countersignature = countersignature_checker
    if check_countersignature is None and host_key_registry is not None:
        check_countersignature = countersignature_check(host_key_registry, 'verifier')
    issues: list[VerifyIssue] = []
    attempted: set[tuple[str, str]] = set()
    prev_recomputed = GENESIS_HASH
    countersignature_unchecked = False
    level2_unchecked = False
    latest_version = -1

    for i, rec in enumerate(records):
        seq = rec.seq if isinstance(rec.seq, int) else None
        event = _as_event(rec.event)
        error = check_sealed_event(rec.event)
        if error is not None:
            issues.append(VerifyIssue(seq=seq, kind='schema-invalid', detail=error))
        version = event.get('spec_version')
        rank = _VERSION_RANK.get(version) if isinstance(version, str) else None
        if rank is not None:
            if rank < latest_version:
                issues.append(
                    VerifyIssue(
                        seq=seq,
                        kind='schema-invalid',
                        detail=f'version-regression: {version} sealed after a later version',
                    )
                )
            latest_version = max(latest_version, rank)
        if rec.seq != i:
            # Tier-1 seq-gap (§7.6); the sub-kind (gap vs out-of-order) goes in detail.
            sub = 'gap' if seq is not None and seq > i else 'out-of-order'
            issues.append(VerifyIssue(seq=seq, kind='seq-gap', detail=f'{sub}: expected seq {i}, got {rec.seq}'))
        # A record outside the canonicalization domain has no record hash to recompute; it is reported
        # above, and the chain continues from the hash it stores.
        hashable = canonical_domain_error([rec.event, rec.seq, rec.host_ts, rec.previous_hash]) is None
        if hashable:
            recomputed = compute_record_hash(rec.event, rec.seq, rec.host_ts, prev_recomputed)
            if rec.previous_hash != prev_recomputed:
                issues.append(
                    VerifyIssue(
                        seq=seq,
                        kind='record-hash-mismatch',
                        detail='prev-hash: previous_hash does not link to previous record',
                    )
                )
            if rec.record_hash != recomputed:
                issues.append(
                    VerifyIssue(seq=seq, kind='record-hash-mismatch', detail='stored record_hash != recomputed')
                )
        else:
            recomputed = rec.record_hash if isinstance(rec.record_hash, str) else prev_recomputed
        # Level-2 Validation: the signature against the tool-key registry, decoded as the record's own
        # version encoded it.
        key_id = event.get('key_id')
        if isinstance(event.get('signature'), str) and isinstance(key_id, str):
            if key_registry is None:
                level2_unchecked = True
            else:
                registered = key_registry.get(key_id)
                decode = b64_decode if is_earlier_version(event) else b64url_decode
                if registered is None or not verify_event_signature(event, registered, decode):
                    issues.append(
                        VerifyIssue(
                            seq=seq, kind='signature-invalid', detail=f'signature does not verify against {key_id}'
                        )
                    )
        # §11.4 Countersignature Determination: established from the record's own signature, never
        # inferred from any other field. A partial triple is not a conforming record (§7.1).
        present = sum(value is not None for value in (rec.host_signature, rec.host_key_id, rec.log_id))
        if present == 0 and countersignature_required:
            issues.append(
                VerifyIssue(
                    seq=seq,
                    kind='host-signature-invalid',
                    detail='uncountersigned: the chain must be countersigned',
                )
            )
        elif present not in (0, 3):
            issues.append(
                VerifyIssue(
                    seq=seq,
                    kind='host-signature-invalid',
                    detail='partial: host_signature, host_key_id, and log_id appear together or not at all',
                )
            )
        elif present == 3 and hashable:
            if check_countersignature is None:
                countersignature_unchecked = True
            else:
                payload = countersignature_payload(rec.seq, rec.host_ts, rec.log_id, rec.previous_hash, rec.record_hash)
                if not check_countersignature(rec.host_key_id, rec.host_signature, payload):
                    issues.append(
                        VerifyIssue(
                            seq=seq,
                            kind='host-signature-invalid',
                            detail=f'countersignature does not verify against {rec.host_key_id}',
                        )
                    )
        # Identity Matching (§10.10 construction 1): the expectation is an input, never read from the
        # ledger, and a record without the full triple carries no binding. Compared as strings, so it
        # runs for a record that fails every other check (§11.4).
        if expected_identity is not None:
            mismatch = _identity_mismatch(rec, present, expected_identity)
            if mismatch is not None:
                expected = f'{expected_identity.log_id} under {", ".join(sorted(expected_identity.host_key_ids))}'
                issues.append(
                    VerifyIssue(seq=seq, kind='principal-mismatch', detail=f'{mismatch}; expected {expected}')
                )
        # Correlation by (session_id, id) with an attempt sealed before the outcome (§7.2): a success or
        # failed outcome with none is an inconsistency; an aborted one with none is a sealed refusal.
        outcome = event.get('outcome')
        if outcome == 'attempted':
            attempted.add(_correlation_key(event))
        elif outcome in ('success', 'failed') and _correlation_key(event) not in attempted:
            issues.append(
                VerifyIssue(
                    seq=seq,
                    kind='orphaned-outcome',
                    detail=f'never-accepted: outcome={outcome} id={event.get("id")}',
                )
            )
        prev_recomputed = recomputed

    for dup in _shared_signer_seq(records):
        issues.append(
            VerifyIssue(
                seq=None,
                kind='replay-detected',
                detail=f'{dup["key_id"]} in session {dup["session_id"]}: signer_seq {dup["signer_seq"]} sealed twice',
            )
        )
    for gap in unaccounted_signer_seq(records):
        issues.append(
            VerifyIssue(
                seq=None,
                kind='signer-seq-gap',
                detail=(
                    f'{gap["key_id"]} in session {gap["session_id"]}: '
                    f'signer_seq {gap["first"]}..{gap["last"]} is missing'
                ),
            )
        )

    computed_digest = prev_recomputed
    if anchored_digest is not None and anchored_digest != computed_digest:
        issues.append(
            VerifyIssue(
                seq=None, kind='digest-mismatch', detail=f'anchored {anchored_digest} != computed {computed_digest}'
            )
        )
    unchecked = ['countersignature'] if countersignature_unchecked else []
    if level2_unchecked:
        unchecked.append('level-2-signature')
    return VerifyReport(
        ok=len(issues) == 0,
        count=len(records),
        computed_digest=computed_digest,
        issues=issues,
        unchecked=unchecked,
    )
