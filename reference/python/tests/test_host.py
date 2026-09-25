"""Tests for the L1 audit host: accept / reject / unavailable."""

import json

import pytest

from auditable_mcp.host import AuditHost
from auditable_mcp.ledger import GENESIS_HASH, compute_record_hash
from auditable_mcp.paths import SPEC_VECTORS_DIR

_ERROR_CASES = json.loads((SPEC_VECTORS_DIR / 'error-cases.json').read_text(encoding='utf-8'))
SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'
OTHER = '0198f3a2-5c1e-7000-8000-00000000abc1'


def _attempt(overrides: dict | None = None) -> dict:
    """Build a valid attempt event, optionally overriding fields."""
    event = {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': 'auditable-mcp/0.3',
        'ts': '2026-07-15T00:00:01.000Z',
        'session_id': SESSION,
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers', 'scope_hint': 'row:id=c_1'},
        'outcome': 'attempted',
        'action_context_hash': f'sha256:{"0" * 64}',
    }
    if overrides:
        event.update(overrides)
    return event


def _open_host() -> AuditHost:
    """A host with the test's audit session open."""
    host = AuditHost('t#d')
    host.open_session(SESSION)
    return host


def test_accepts_valid_attempt() -> None:
    """A valid attempt is accepted and sealed."""
    host = _open_host()
    assert host.handle_attempt(_attempt()).status == 'accept'
    assert len(host.records()) == 1


def test_rejects_schema_invalid_without_sealing() -> None:
    """A schema-invalid record (a forged/invalid record) is rejected and never sealed."""
    host = _open_host()
    res = host.handle_attempt(_attempt({'action_context_hash': 'not-a-hash'}))
    assert res.status == 'reject'
    assert len(host.records()) == 0
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())


def test_rejects_non_canonicalizable_number_without_raising() -> None:
    """§8.1: a non-canonicalizable number (out-of-range or non-finite) is rejected gracefully, not raised."""
    host = _open_host()
    assert host.handle_attempt(_attempt({'action_context': {'rows': 9007199254740992}})).reason == 'schema-invalid'
    assert host.handle_attempt(_attempt({'action_context': {'x': float('inf')}})).reason == 'schema-invalid'
    assert host.handle_attempt(_attempt({'action_context': {'x': float('nan')}})).reason == 'schema-invalid'
    assert host.records() == []


def test_byte_identical_repeat_is_answered_from_the_ledger() -> None:
    """§7.1: a byte-identical repeat of a sealed attempt gets the original accept and seals nothing."""
    host = _open_host()
    first = host.handle_attempt(_attempt())
    assert first.status == 'accept'
    assert host.handle_attempt(_attempt()) == first
    assert len(host.records()) == 1
    assert host.anomalies() == []


def test_rejects_an_id_sealed_with_a_different_event() -> None:
    """An attempt id already sealed with different bytes is a replay; the ledger stays clean."""
    host = _open_host()
    assert host.handle_attempt(_attempt()).status == 'accept'
    res = host.handle_attempt(_attempt({'target_resource': {'kind': 'table', 'ref': 'salaries'}}))
    assert (res.status, res.reason) == ('reject', 'replay-detected')
    assert len(host.records()) == 1


def test_rejects_an_event_outside_an_open_session() -> None:
    """§6.3: an event whose session_id is not an open audit session is rejected."""
    host = _open_host()
    res = host.handle_attempt(_attempt({'session_id': '0198f3a2-5c1e-7000-8000-00000000ffff'}))
    assert (res.status, res.reason) == ('reject', 'replay-detected')
    host.close_session(SESSION)
    assert host.handle_attempt(_attempt()).reason == 'replay-detected'
    assert host.records() == []


def test_unavailable_decides_nothing_and_the_identical_attempt_is_accepted() -> None:
    """§7.1: unavailable seals nothing, and the identical attempt sent again is accepted."""
    host = _open_host()
    host.unavailable = True
    res = host.handle_attempt(_attempt())
    assert (res.status, res.reason) == ('unavailable', 'internal-error')
    assert len(host.records()) == 0
    host.unavailable = False
    assert host.handle_attempt(_attempt()).status == 'accept'
    assert len(host.records()) == 1


def test_seals_the_refusal_of_an_attempt_it_did_not_accept() -> None:
    """§7.2, §10.4: an aborted outcome for an attempt the host did not accept is sealed as a refusal."""
    host = _open_host()
    host.handle_outcome(_attempt({'outcome': 'aborted', 'reason': 'host-rejected'}))
    assert host.anomalies() == []
    assert len(host.records()) == 1
    host.handle_outcome(_attempt({'id': '00000000-0000-4000-8000-000000000002', 'outcome': 'success'}))
    assert any(a.kind == 'orphaned-outcome' for a in host.anomalies())


def test_rejects_an_attempt_whose_operation_has_a_sealed_outcome() -> None:
    """§7.1 rule 4: no attempt is sealed after its own terminal record."""
    host = _open_host()
    host.unavailable = True
    assert host.handle_attempt(_attempt()).status == 'unavailable'
    host.unavailable = False
    host.handle_outcome(_attempt({'outcome': 'aborted', 'reason': 'host-unavailable'}))
    assert len(host.records()) == 1
    response = host.handle_attempt(_attempt())
    assert (response.status, response.reason) == ('reject', 'replay-detected')
    assert len(host.records()) == 1
    assert [a.kind for a in host.anomalies()] == ['replay-detected']


def test_records_an_unresolved_attempt_when_the_call_ends() -> None:
    """§6.3: a call that ends with an accepted attempt and no outcome leaves `unresolved-attempt`."""
    host = _open_host()
    host.handle_attempt(_attempt())
    host.close_session(SESSION)
    assert [a.kind for a in host.anomalies()] == ['unresolved-attempt']


def test_records_nothing_when_every_attempt_was_resolved() -> None:
    """A call whose attempts all have outcomes ends cleanly."""
    host = _open_host()
    host.handle_attempt(_attempt())
    host.handle_outcome(_attempt({'outcome': 'success'}))
    host.close_session(SESSION)
    assert host.anomalies() == []


def test_reason_less_aborted_is_schema_invalid() -> None:
    """§7.2: an aborted outcome MUST carry a Tier-1 abort code; a reason-less one is schema-invalid."""
    host = _open_host()
    host.handle_outcome(_attempt({'outcome': 'aborted'}))  # no reason
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())
    assert host.records() == []


def test_attempted_on_outcome_channel_is_dropped_not_sealed() -> None:
    """§6: an `attempted` outcome on the audit/outcome channel is invalid — flagged schema-invalid, never sealed."""
    host = _open_host()
    host.handle_attempt(_attempt())
    host.handle_outcome(_attempt({'outcome': 'attempted'}))
    assert len(host.records()) == 1
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())


def test_one_terminal_outcome_per_operation() -> None:
    """§7.2: a byte-identical repeat outcome is ignored; a differing one is not sealed and is a replay."""
    host = _open_host()
    host.handle_attempt(_attempt())
    host.handle_outcome(_attempt({'outcome': 'success'}))
    host.handle_outcome(_attempt({'outcome': 'success'}))
    assert len(host.records()) == 2
    assert host.anomalies() == []
    host.handle_outcome(_attempt({'outcome': 'failed'}))
    assert len(host.records()) == 2
    assert [a.kind for a in host.anomalies()] == ['replay-detected']


def test_an_outcome_for_another_session_is_recorded_not_raised() -> None:
    """§6: an outcome whose session is not the call's is dropped and recorded as replay-detected."""
    host = _open_host()
    host.handle_outcome(_attempt({'outcome': 'aborted', 'reason': 'host-rejected', 'session_id': OTHER}))
    assert host.records() == []
    assert [a.kind for a in host.anomalies()] == ['replay-detected']


def test_structure_is_checked_before_the_session() -> None:
    """§7.1: a malformed event on a foreign session is schema-invalid, not replay-detected."""
    host = _open_host()
    response = host.handle_attempt(_attempt({'session_id': OTHER, 'action_context_hash': 'not-a-hash'}))
    assert response.reason == 'schema-invalid'


def test_only_a_session_of_a_call_in_flight_on_the_connection_is_accepted() -> None:
    """§6.5: an open session that is not one of the connection's calls in flight is not the call's."""
    host = _open_host()
    host.open_session(OTHER)
    assert host.handle_attempt(_attempt(), arrived_on={OTHER}).reason == 'replay-detected'
    assert host.handle_attempt(_attempt(), arrived_on={SESSION}).status == 'accept'


def test_a_session_id_is_never_issued_twice() -> None:
    """§6.3: a session id is not issued again, even after its session ended."""
    host = _open_host()
    host.close_session(SESSION)
    with pytest.raises(ValueError, match='already issued'):
        host.open_session(SESSION)


def test_a_lone_surrogate_is_schema_invalid() -> None:
    """§8.1: a string that is not a sequence of Unicode scalar values is refused, member names included."""
    host = _open_host()
    assert host.handle_attempt(_attempt({'action_context': {'note': 'a\ud800b'}})).reason == 'schema-invalid'
    assert host.handle_attempt(_attempt({'action_context': {'k\udc00': 1}})).reason == 'schema-invalid'
    assert host.handle_attempt(_attempt({'action_context': {'note': '\U0001f512'}})).status == 'accept'


def test_patterns_anchor_the_whole_string() -> None:
    """§4: `$` does not match before a trailing newline, and `\\d` is ASCII only, as in ECMA-262."""
    host = _open_host()
    assert host.handle_attempt(_attempt({'id': '00000000-0000-4000-8000-000000000001\n'})).reason == 'schema-invalid'
    assert host.handle_attempt(_attempt({'ts': '\u0662026-07-15T00:00:01.000Z'})).reason == 'schema-invalid'


def test_hashes_the_received_structure() -> None:
    """§8: a `__proto__` member of action_context is sealed as received."""
    host = _open_host()
    received = json.loads(json.dumps(_attempt({'action_context': {'__proto__': {'a': 1}, 'b': 2}})))
    response = host.handle_attempt(received)
    assert response.record_hash == compute_record_hash(received, 0, host.records()[0].host_ts, GENESIS_HASH)


@pytest.mark.parametrize('case', _ERROR_CASES, ids=[c['name'] for c in _ERROR_CASES])
def test_negative_cases_match_pinned_code(case: dict) -> None:
    """Each error-cases.json event is refused with the pinned Tier-1 code (§7.6, §8.4)."""
    host = _open_host()
    if case['channel'] == 'attempt':
        response = host.handle_attempt(case['event'])
        assert response.status == case['expect']['status']
        assert response.reason == case['expect']['reason']
    else:
        host.handle_outcome(case['event'])
        assert host.records() == []
        assert any(a.kind == case['expect']['anomaly_kind'] for a in host.anomalies())
