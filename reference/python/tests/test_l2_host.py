"""Tests for the L2 audit host policy."""

from auditable_mcp.capability import AuditCapability
from auditable_mcp.host import AuditHost
from auditable_mcp.l2.keys import KeyRegistry, ToolKey, generate_tool_key
from auditable_mcp.l2.signing import sign_event

L2_CAP = AuditCapability(level='L2')


def _attempt(n: int) -> dict:
    """Build a valid attempt event with a distinct id for sequence ``n`` scenarios."""
    return {
        'id': f'00000000-0000-4000-8000-{n:012x}',
        'spec_version': 'auditable-mcp/0.2',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
        'action_context_hash': f'sha256:{"0" * 64}',
    }


def _new_host() -> tuple[AuditHost, ToolKey]:
    """Build an L2 host with one registered tool key."""
    key = generate_tool_key('tool-key-1')
    registry = KeyRegistry()
    registry.register(key.key_id, key.public_key, key.alg)
    host = AuditHost('t#d', L2_CAP, registry)
    return host, key


def test_accepts_valid_signed_attempt() -> None:
    """A valid signed attempt is accepted and sealed."""
    host, key = _new_host()
    signed = sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key)
    assert host.handle_attempt(signed).status == 'accept'
    assert len(host.records()) == 1


def test_rejects_unsigned_under_l2() -> None:
    """An unsigned event under L2 is rejected (needs escalation)."""
    host, _ = _new_host()
    res = host.handle_attempt(_attempt(1))
    assert res.status == 'reject'
    assert res.reason == 'l2-unsigned'
    assert len(host.records()) == 0


def test_rejects_unregistered_key() -> None:
    """A signature from an unregistered key is rejected."""
    host, _ = _new_host()
    stranger = generate_tool_key('stranger')
    signed = sign_event(_attempt(1), stranger.key_id, 0, stranger.alg, stranger.private_key)
    assert host.handle_attempt(signed).reason == 'unknown-key'


def test_rejects_forged_record() -> None:
    """A record altered after signing is rejected as signature-invalid."""
    host, key = _new_host()
    signed = sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key)
    forged = {**signed, 'target_resource': {'kind': 'table', 'ref': 'salaries'}}
    assert host.handle_attempt(forged).reason == 'signature-invalid'
    assert len(host.records()) == 0


def test_rejects_replayed_sequence() -> None:
    """A replayed sequence is rejected."""
    host, key = _new_host()
    host.handle_attempt(sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key))
    replay = sign_event(_attempt(2), key.key_id, 0, key.alg, key.private_key)
    assert host.handle_attempt(replay).reason == 'replay-detected'


def test_first_observation_above_zero_is_baseline_not_a_gap() -> None:
    """A first observation with signer_seq > 0 is the baseline, accepted without flagging a gap (§7.4)."""
    host, key = _new_host()
    # A key whose counter starts above 0 (persisted across restart, or reused across partitions).
    res = host.handle_attempt(sign_event(_attempt(1), key.key_id, 5, key.alg, key.private_key))
    assert res.status == 'accept'
    assert host.anomalies() == []


def test_flags_sequence_gap_but_accepts() -> None:
    """A forward sequence gap (suppressed prior event) is flagged but the record is accepted."""
    host, key = _new_host()
    host.handle_attempt(sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key))
    res = host.handle_attempt(sign_event(_attempt(2), key.key_id, 2, key.alg, key.private_key))
    assert res.status == 'accept'
    assert any(a.kind == 'signer-seq-gap' for a in host.anomalies())


def test_sealed_outcome_counts_in_signer_seq_contiguous() -> None:
    """A sealed outcome consumes signer_seq: attempt(0) -> outcome(1) -> attempt(2) is contiguous (§7.4)."""
    host, key = _new_host()
    host.handle_attempt(sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key))
    # The correlated signed success outcome consumes signer_seq 1 and is sealed.
    host.handle_outcome(sign_event({**_attempt(1), 'outcome': 'success'}, key.key_id, 1, key.alg, key.private_key))
    # The next attempt at signer_seq 2 is contiguous with the outcome's 1 - not a gap.
    res = host.handle_attempt(sign_event(_attempt(2), key.key_id, 2, key.alg, key.private_key))
    assert res.status == 'accept'
    assert not any(a.kind == 'signer-seq-gap' for a in host.anomalies())
    assert len(host.records()) == 3


def test_sequence_advances_only_on_seal_retry_after_unavailable() -> None:
    """§7.4: the tracker follows the last accepted sequence, so a retry after unavailable seals."""
    host, key = _new_host()
    host.unavailable = True
    signed = sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key)
    assert host.handle_attempt(signed).status == 'unavailable'
    host.unavailable = False
    assert host.handle_attempt(signed).status == 'accept'
    assert len(host.records()) == 1


def test_fail_closed_aborted_not_flagged_as_sequence_gap() -> None:
    """§10.4: a signed fail-closed aborted outcome whose signer sequence outran the unsealed attempt is not a gap."""
    host, key = _new_host()
    host.unavailable = True
    assert host.handle_attempt(sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key)).status == 'unavailable'
    host.unavailable = False
    event = {**_attempt(1), 'outcome': 'aborted', 'reason': 'host-unavailable'}
    host.handle_outcome(sign_event(event, key.key_id, 1, key.alg, key.private_key))
    assert host.anomalies() == []
    assert host.records() == []
