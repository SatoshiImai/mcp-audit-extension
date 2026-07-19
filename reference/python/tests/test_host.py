"""Tests for the L1 audit host: accept / reject / unavailable."""

from auditable_mcp.host import AuditHost


def _attempt(overrides: dict | None = None) -> dict:
    """Build a valid attempt event, optionally overriding fields."""
    event = {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': 'auditable-mcp/0.1',
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
    """A schema-invalid record (a lie) is rejected and never sealed."""
    host = AuditHost('t#d')
    res = host.handle_attempt(_attempt({'action_context_hash': 'not-a-hash'}))
    assert res.status == 'reject'
    assert len(host.records()) == 0
    assert any(a.kind == 'schema-invalid' for a in host.anomalies())


def test_rejects_replayed_attempt() -> None:
    """A replayed attempt id is rejected and the ledger stays clean."""
    host = AuditHost('t#d')
    assert host.handle_attempt(_attempt()).status == 'accept'
    res = host.handle_attempt(_attempt())
    assert res.status == 'reject'
    assert len(host.records()) == 1
    assert any(a.kind == 'attempt-replay' for a in host.anomalies())


def test_unavailable_fail_closed() -> None:
    """An unavailable host fails closed: the record is not sealed."""
    host = AuditHost('t#d')
    host.unavailable = True
    res = host.handle_attempt(_attempt())
    assert res.status == 'unavailable'
    assert len(host.records()) == 0
