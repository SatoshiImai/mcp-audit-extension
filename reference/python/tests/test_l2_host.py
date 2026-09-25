"""Tests for the L2 audit host policy."""

from auditable_mcp.capability import AuditCapability
from auditable_mcp.host import AuditHost
from auditable_mcp.l2.keys import KeyRegistry, ToolKey, generate_tool_key
from auditable_mcp.l2.signing import sign_event

L2_CAP = AuditCapability(level='L2')
SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'
OTHER_SESSION = '0198f3a2-5c1e-7000-8000-00000000abc1'


def _attempt(n: int) -> dict:
    """Build a valid attempt event with a distinct id for sequence ``n`` scenarios."""
    return {
        'id': f'00000000-0000-4000-8000-{n:012x}',
        'spec_version': 'auditable-mcp/0.3',
        'ts': '2026-07-15T00:00:01.000Z',
        'session_id': SESSION,
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
        'action_context_hash': f'sha256:{"0" * 64}',
    }


def _new_host() -> tuple[AuditHost, ToolKey]:
    """Build an L2 host with one registered tool key."""
    host, key, _ = _new_host_with_registry()
    return host, key


def _new_host_with_registry() -> tuple[AuditHost, ToolKey, KeyRegistry]:
    """Build an L2 host with one registered tool key, and return its registry."""
    key = generate_tool_key('tool-key-1')
    registry = KeyRegistry()
    registry.register(key.key_id, key.public_key, key.alg)
    host = AuditHost('t#d', L2_CAP, registry)
    host.open_session(SESSION)
    return host, key, registry


def _sign(event: dict, key: ToolKey, signer_seq: int) -> dict:
    """Sign an event under the key at the given signer_seq."""
    return sign_event(event, key.key_id, signer_seq, key.alg, key.private_key)


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


def test_first_value_other_than_zero_is_a_gap() -> None:
    """§7.4: a session starts at 0, so a first signer_seq of 5 is flagged, and accepted."""
    host, key = _new_host()
    assert host.handle_attempt(sign_event(_attempt(1), key.key_id, 5, key.alg, key.private_key)).status == 'accept'
    assert [a.kind for a in host.anomalies()] == ['signer-seq-gap']


def test_each_session_numbers_from_zero() -> None:
    """§7.4: one key serves concurrent calls, each numbered from 0, without a gap."""
    host, key = _new_host()
    host.open_session(OTHER_SESSION)
    assert host.handle_attempt(sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key)).status == 'accept'
    other = {**_attempt(2), 'session_id': OTHER_SESSION}
    assert host.handle_attempt(sign_event(other, key.key_id, 0, key.alg, key.private_key)).status == 'accept'
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


def test_unavailable_does_not_move_the_replay_bound() -> None:
    """§7.1, §7.4: the identical attempt sent again after unavailable is accepted."""
    host, key = _new_host()
    host.unavailable = True
    signed = sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key)
    assert host.handle_attempt(signed).status == 'unavailable'
    host.unavailable = False
    assert host.handle_attempt(signed).status == 'accept'
    assert len(host.records()) == 1
    assert host.anomalies() == []


def test_the_refusal_of_an_unavailable_attempt_is_sealed_without_a_gap() -> None:
    """§7.2, §7.4: the host received 0, so the refusal at 1 is no gap, and it is sealed."""
    host, key = _new_host()
    host.unavailable = True
    assert host.handle_attempt(sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key)).status == 'unavailable'
    host.unavailable = False
    aborted = {**_attempt(1), 'outcome': 'aborted', 'reason': 'host-unavailable'}
    host.handle_outcome(sign_event(aborted, key.key_id, 1, key.alg, key.private_key))
    assert host.anomalies() == []
    assert len(host.records()) == 1


def test_the_sequence_continues_after_a_rejected_attempt() -> None:
    """§7.4: a reject after the signature verified is a decision, so the next value is no gap."""
    host, key = _new_host()
    host.handle_attempt(sign_event(_attempt(1), key.key_id, 0, key.alg, key.private_key))
    duplicate = sign_event({**_attempt(1), 'ts': '2026-07-15T00:00:09.000Z'}, key.key_id, 1, key.alg, key.private_key)
    res = host.handle_attempt(duplicate)
    assert (res.status, res.reason) == ('reject', 'replay-detected')
    assert host.handle_attempt(sign_event(_attempt(3), key.key_id, 2, key.alg, key.private_key)).status == 'accept'
    assert not any(a.kind == 'signer-seq-gap' for a in host.anomalies())


def test_the_decided_set_accepts_a_value_sent_again_below_a_decided_one() -> None:
    """§7.4: after unavailable, the identical attempt is accepted even below a decided value."""
    host, key = _new_host()
    first = _sign(_attempt(1), key, 0)
    host.unavailable = True
    assert host.handle_attempt(first).status == 'unavailable'
    host.unavailable = False
    assert host.handle_attempt(_sign(_attempt(2), key, 1)).status == 'accept'
    assert host.handle_attempt(first).status == 'accept'
    assert host.handle_attempt(_sign(_attempt(3), key, 1)).reason == 'replay-detected'
    assert [a.kind for a in host.anomalies()] == ['replay-detected']
    assert len(host.records()) == 2


def test_an_outcome_is_received_while_the_host_is_unavailable() -> None:
    """§7.4: the signature of an outcome is verified and counted even when it cannot be sealed."""
    host, key = _new_host()
    host.handle_attempt(_sign(_attempt(1), key, 0))
    host.unavailable = True
    host.handle_outcome(_sign({**_attempt(1), 'outcome': 'success'}, key, 1))
    host.unavailable = False
    assert host.handle_attempt(_sign(_attempt(2), key, 2)).status == 'accept'
    assert not any(a.kind == 'signer-seq-gap' for a in host.anomalies())


def test_dropped_outcomes_are_recorded_under_their_tier_1_kinds() -> None:
    """§6: missing signature, unknown key, bad signature, a decided value, and a partial trio."""
    host, key = _new_host()
    stranger = generate_tool_key('stranger')
    host.handle_attempt(_sign(_attempt(1), key, 0))
    success = {**_attempt(1), 'outcome': 'success'}
    host.handle_outcome(success)
    host.handle_outcome(sign_event(success, stranger.key_id, 1, stranger.alg, stranger.private_key))
    host.handle_outcome({**_sign(success, key, 1), 'mutates': False})
    host.handle_outcome(_sign({**_attempt(9), 'outcome': 'aborted', 'reason': 'host-rejected'}, key, 0))
    host.handle_outcome({**success, 'signature': 'AAAA'})
    assert [a.kind for a in host.anomalies()] == [
        'signature-invalid',
        'signature-invalid',
        'signature-invalid',
        'replay-detected',
        'schema-invalid',
    ]
    assert len(host.records()) == 1


def test_the_outcome_signature_is_checked_before_correlation() -> None:
    """§7.2: a forged orphan is signature-invalid, not orphaned-outcome."""
    host, key = _new_host()
    host.handle_outcome({**_sign({**_attempt(5), 'outcome': 'success'}, key, 0), 'mutates': False})
    assert [a.kind for a in host.anomalies()] == ['signature-invalid']


def test_an_event_under_a_revoked_key_is_unknown_key() -> None:
    """§10.9: after revocation, new events under the key are rejected as unknown-key."""
    host, key, registry = _new_host_with_registry()
    registry.revoke(key.key_id)
    assert host.handle_attempt(_sign(_attempt(1), key, 0)).reason == 'unknown-key'
