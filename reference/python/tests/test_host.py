"""Tests for the L1 audit host: accept / reject / unavailable."""

import json

import pytest

from auditable_mcp.host import AuditHost
from auditable_mcp.paths import SPEC_VECTORS_DIR

_ERROR_CASES = json.loads((SPEC_VECTORS_DIR / 'error-cases.json').read_text(encoding='utf-8'))


def _attempt(overrides: dict | None = None) -> dict:
    """Build a valid attempt event, optionally overriding fields."""
    event = {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': 'auditable-mcp/0.1.1',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
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


def test_accepts_valid_attempt() -> None:
    """A valid attempt is accepted and sealed."""
    host = AuditHost('t#d')
    assert host.handle_attempt(_attempt()).status == 'accept'
    assert len(host.records()) == 1


def test_rejects_schema_invalid_without_sealing() -> None:
    """A schema-invalid record (a forged/invalid record) is rejected and never sealed."""
    host = AuditHost('t#d')
    res = host.handle_attempt(_attempt({'action_context_hash': 'not-a-hash'}))
    assert res.status == 'reject'
    assert len(host.records()) == 0
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())


def test_rejects_non_canonicalizable_number_without_raising() -> None:
    """§8.1: a non-canonicalizable number (out-of-range or non-finite) is rejected gracefully, not raised."""
    host = AuditHost('t#d')
    assert host.handle_attempt(_attempt({'action_context': {'rows': 9007199254740992}})).reason == 'schema-invalid'
    assert host.handle_attempt(_attempt({'action_context': {'x': float('inf')}})).reason == 'schema-invalid'
    assert host.handle_attempt(_attempt({'action_context': {'x': float('nan')}})).reason == 'schema-invalid'
    assert host.records() == []


def test_rejects_replayed_attempt() -> None:
    """A replayed attempt id is rejected and the ledger stays clean."""
    host = AuditHost('t#d')
    assert host.handle_attempt(_attempt()).status == 'accept'
    res = host.handle_attempt(_attempt())
    assert res.status == 'reject'
    assert len(host.records()) == 1
    assert any(a.kind == 'replay-detected' for a in host.anomalies())


def test_unavailable_fail_closed() -> None:
    """An unavailable host fails closed: the record is not sealed."""
    host = AuditHost('t#d')
    host.unavailable = True
    res = host.handle_attempt(_attempt())
    assert res.status == 'unavailable'
    assert len(host.records()) == 0


def test_aborted_outcome_for_never_accepted_attempt_not_flagged() -> None:
    """§10.4: a fail-closed aborted outcome for a never-accepted attempt is not a tampering anomaly."""
    host = AuditHost('t#d')
    host.handle_outcome(_attempt({'outcome': 'aborted', 'reason': 'host-rejected'}))
    assert host.anomalies() == []
    assert host.records() == []
    host.handle_outcome(_attempt({'outcome': 'success'}))
    assert any(a.kind == 'orphaned-outcome' for a in host.anomalies())


def test_reason_less_aborted_is_schema_invalid() -> None:
    """§7.2: an aborted outcome MUST carry a Tier-1 abort code; a reason-less one is schema-invalid."""
    host = AuditHost('t#d')
    host.handle_outcome(_attempt({'outcome': 'aborted'}))  # no reason
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())
    assert host.records() == []


def test_outcomes_are_not_de_duplicated() -> None:
    """§8.3: each correlated outcome is sealed, not de-duplicated."""
    host = AuditHost('t#d')
    host.handle_attempt(_attempt())
    host.handle_outcome(_attempt({'outcome': 'success'}))
    host.handle_outcome(_attempt({'outcome': 'success'}))
    assert len(host.records()) == 3
    assert host.anomalies() == []


@pytest.mark.parametrize('case', _ERROR_CASES, ids=[c['name'] for c in _ERROR_CASES])
def test_negative_cases_match_pinned_code(case: dict) -> None:
    """Each error-cases.json event is refused with the pinned Tier-1 code (§7.6, §8.4)."""
    host = AuditHost('t#d')
    if case['channel'] == 'attempt':
        response = host.handle_attempt(case['event'])
        assert response.status == case['expect']['status']
        assert response.reason == case['expect']['reason']
    else:
        host.handle_outcome(case['event'])
        assert host.records() == []
        assert any(a.kind == case['expect']['anomaly_kind'] for a in host.anomalies())
