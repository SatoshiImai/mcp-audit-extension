"""Tests for the verifier: proof of non-tampering + completeness."""

import base64

import pytest

from auditable_mcp.canonical import canonicalize
from auditable_mcp.demo.scenario import run_clean_scenario
from auditable_mcp.l2.keys import KeyRegistry, ToolKey, generate_tool_key
from auditable_mcp.l2.signing import sign_event
from auditable_mcp.ledger import GENESIS_HASH, SealedRecord, compute_record_hash
from auditable_mcp.verify import ExpectedIdentity, VerifyReport, verify_ledger


def test_clean_ledger_verifies() -> None:
    """A clean ledger verifies with zero issues and matches the anchored digest."""
    host = run_clean_scenario()
    anchored = host.ledger.digest()
    report = verify_ledger(host.records(), anchored)
    assert report.ok
    assert report.issues == []
    assert report.computed_digest == anchored


def test_detects_tampering() -> None:
    """Tampering a sealed field breaks the record hash and the anchored digest."""
    host = run_clean_scenario()
    anchored = host.ledger.digest()
    host.records()[1].event['target_resource']['ref'] = 'https://evil.example/exfil'
    report = verify_ledger(host.records(), anchored)
    assert not report.ok
    assert any(i.kind == 'record-hash-mismatch' for i in report.issues)
    assert any(i.kind == 'digest-mismatch' for i in report.issues)


def test_detects_dropped_record() -> None:
    """Dropping a record is caught by a sequence gap (completeness)."""
    host = run_clean_scenario()
    records = host.records()
    del records[2]
    report = verify_ledger(records)
    assert not report.ok
    assert any(i.kind in ('seq-gap', 'record-hash-mismatch') for i in report.issues)


SESSION_A = '0198f3a2-5c1e-7000-8000-00000000abc0'
SESSION_B = '0198f3a2-5c1e-7000-8000-00000000abc1'


def _event(n: int, outcome: str, **extra: object) -> dict:
    """Build a current-version event."""
    return {
        'id': f'00000000-0000-4000-8000-{n:012x}',
        'spec_version': 'auditable-mcp/0.3',
        'ts': '2026-07-15T00:00:01.000Z',
        'session_id': SESSION_A,
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': outcome,
        **extra,
    }


def _chain(events: list[dict]) -> list[SealedRecord]:
    """Seal events into a chain without the host's validation, as another implementation's ledger."""
    records: list[SealedRecord] = []
    prev = GENESIS_HASH
    for seq, event in enumerate(events):
        host_ts = f'2026-07-15T00:00:{10 + seq:02d}.000Z'
        record_hash = compute_record_hash(event, seq, host_ts, prev)
        records.append(SealedRecord(event=event, seq=seq, host_ts=host_ts, previous_hash=prev, record_hash=record_hash))
        prev = record_hash
    return records


def _kinds(report: VerifyReport) -> list[str]:
    """Return the issue kinds in order."""
    return [issue.kind for issue in report.issues]


def _signed() -> tuple[KeyRegistry, ToolKey]:
    """A registry with one Ed25519 tool key."""
    key = generate_tool_key('tool')
    registry = KeyRegistry()
    registry.register('tool', key.public_key, 'Ed25519')
    return registry, key


def test_an_out_of_domain_record_is_reported_and_the_chain_checked_around_it() -> None:
    """§11.4: 1e300 in action_context is schema-invalid, not an exception."""
    first = _chain([_event(1, 'attempted')])[0]
    bad = SealedRecord(
        event=_event(2, 'attempted', action_context={'rows': 1e300}),
        seq=1,
        host_ts='2026-07-15T00:00:11.000Z',
        previous_hash=first.record_hash,
        record_hash='f' * 64,
    )
    last_event = _event(3, 'attempted')
    last_hash = compute_record_hash(last_event, 2, '2026-07-15T00:00:12.000Z', bad.record_hash)
    last = SealedRecord(
        event=last_event,
        seq=2,
        host_ts='2026-07-15T00:00:12.000Z',
        previous_hash=bad.record_hash,
        record_hash=last_hash,
    )
    report = verify_ledger([first, bad, last])
    assert _kinds(report) == ['schema-invalid']
    assert report.computed_digest == last_hash


def test_an_aborted_record_without_a_reason_is_schema_invalid() -> None:
    """§7.2, §11.4."""
    assert _kinds(verify_ledger(_chain([_event(1, 'aborted')]))) == ['schema-invalid']


def test_a_record_of_an_earlier_version_is_read_under_its_own_schema() -> None:
    """§11.4: a 0.2 record with call_id and a padded base64 signature is valid and verifies."""
    registry, key = _signed()
    unsigned = {name: value for name, value in _event(1, 'attempted').items() if name != 'session_id'}
    unsigned.update({'spec_version': 'auditable-mcp/0.2', 'call_id': 'call-1', 'key_id': 'tool', 'signer_seq': 7})
    signature = base64.b64encode(key.private_key.sign(canonicalize(unsigned).encode('utf-8'))).decode('ascii')
    records = _chain([{**unsigned, 'signature': signature}])
    report = verify_ledger(records, key_registry=registry)
    assert report.issues == []
    assert report.complete


def test_level_2_signatures_are_verified_or_reported_unchecked() -> None:
    """§11.4: with a registry signatures are verified; without one the check is named unchecked."""
    registry, key = _signed()
    records = _chain(
        [
            sign_event(_event(1, 'attempted'), 'tool', 0, 'Ed25519', key.private_key),
            sign_event(_event(1, 'success'), 'tool', 1, 'Ed25519', key.private_key),
        ]
    )
    assert verify_ledger(records, key_registry=registry).complete
    unchecked = verify_ledger(records)
    assert unchecked.ok
    assert unchecked.unchecked == ['level-2-signature']


def test_a_signature_that_does_not_verify_is_reported() -> None:
    """§11.4: a forged signature, and one under an unregistered key, are signature-invalid."""
    registry, key = _signed()
    forged = {**sign_event(_event(1, 'attempted'), 'tool', 0, 'Ed25519', key.private_key), 'mutates': False}
    stranger = sign_event(_event(2, 'attempted'), 'stranger', 0, 'Ed25519', generate_tool_key('s').private_key)
    assert _kinds(verify_ledger(_chain([forged, stranger]), key_registry=registry)) == [
        'signature-invalid',
        'signature-invalid',
    ]


def test_a_record_under_a_key_revoked_since_verifies() -> None:
    """§10.9."""
    registry, key = _signed()
    records = _chain([sign_event(_event(1, 'attempted'), 'tool', 0, 'Ed25519', key.private_key)])
    registry.revoke('tool')
    assert verify_ledger(records, key_registry=registry).issues == []


def test_two_sealed_records_sharing_a_signer_seq_are_a_replay() -> None:
    """§7.4, §11.4: per key and session."""
    registry, key = _signed()
    records = _chain(
        [
            sign_event(_event(1, 'attempted'), 'tool', 0, 'Ed25519', key.private_key),
            sign_event(_event(2, 'attempted'), 'tool', 0, 'Ed25519', key.private_key),
            sign_event(_event(3, 'attempted', session_id=SESSION_B), 'tool', 0, 'Ed25519', key.private_key),
        ]
    )
    assert _kinds(verify_ledger(records, key_registry=registry)) == ['replay-detected']


def test_correlation_is_by_session_and_id() -> None:
    """§7.2: an attempt of another session does not resolve an outcome."""
    records = _chain([_event(1, 'attempted'), _event(1, 'success', session_id=SESSION_B)])
    assert _kinds(verify_ledger(records)) == ['orphaned-outcome']


def test_tool_and_host_registries_must_not_share_a_key() -> None:
    """§10.9."""
    registry, _ = _signed()
    with pytest.raises(ValueError, match='share a key'):
        verify_ledger([], key_registry=registry, host_key_registry=registry)


_IDENTITY = ExpectedIdentity(log_id='tenant-a', host_key_ids=frozenset({'h'}))


def _countersigned(record: SealedRecord, log_id: str = 'tenant-a', host_key_id: str = 'h') -> SealedRecord:
    """Attach a countersignature triple the test's checker accepts."""
    record.host_signature, record.host_key_id, record.log_id = 'AA', host_key_id, log_id
    return record


def test_identity_matching_against_an_expected_identity() -> None:
    """§10.10 construction 1: another log_id, another host key, or no countersignature is principal-mismatch."""
    a, b, c, d = _chain([_event(1, 'attempted'), _event(1, 'success'), _event(2, 'attempted'), _event(2, 'success')])
    records = [_countersigned(a), _countersigned(b, log_id='tenant-b'), _countersigned(c, host_key_id='other'), d]
    report = verify_ledger(records, None, lambda *_: True, expected_identity=_IDENTITY)
    assert [(issue.seq, issue.kind) for issue in report.issues] == [
        (1, 'principal-mismatch'),
        (2, 'principal-mismatch'),
        (3, 'principal-mismatch'),
    ]


def test_identity_is_checked_for_a_record_that_cannot_be_canonicalized() -> None:
    """§11.4 Identity Matching: the comparison runs for a record the verifier cannot otherwise validate."""
    (record,) = _chain([_event(1, 'attempted')])
    record.event = _event(1, 'attempted', action_context={'note': 'a\ud800b'})
    report = verify_ledger(
        [_countersigned(record, log_id='tenant-b')], None, lambda *_: True, expected_identity=_IDENTITY
    )
    assert _kinds(report) == ['schema-invalid', 'principal-mismatch']


def test_an_uncountersigned_record_where_the_chain_must_be_countersigned() -> None:
    """§11.4: host-signature-invalid only when the requirement is supplied."""
    a, b = _chain([_event(1, 'attempted'), _event(1, 'success')])
    records = [_countersigned(a), b]
    assert _kinds(verify_ledger(records, None, lambda *_: True)) == []
    report = verify_ledger(records, None, lambda *_: True, countersignature_required=True)
    assert [(issue.seq, issue.kind) for issue in report.issues] == [(1, 'host-signature-invalid')]


def test_an_outcome_does_not_correlate_with_an_attempt_sealed_after_it() -> None:
    """§7.2: correlation is with an attempt sealed before the outcome."""
    assert _kinds(verify_ledger(_chain([_event(1, 'success'), _event(1, 'attempted')]))) == ['orphaned-outcome']


def test_an_earlier_version_sealed_after_a_later_one_is_schema_invalid() -> None:
    """§11.4: a chain's versions do not go backwards."""
    earlier = {
        'id': '00000000-0000-4000-8000-000000000009',
        'spec_version': 'auditable-mcp/0.2',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': '7',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 't'},
        'outcome': 'attempted',
    }
    assert _kinds(verify_ledger(_chain([earlier, _event(1, 'attempted')]))) == []
    assert _kinds(verify_ledger(_chain([_event(1, 'attempted'), earlier]))) == ['schema-invalid']
