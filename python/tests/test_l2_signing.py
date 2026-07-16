"""Tests for L2 signing and the L1 ⊆ L2 schema invariant."""

from auditable_mcp.l2.keys import generate_tool_key
from auditable_mcp.l2.signing import Ed25519Signer, sign_event, verify_event_signature
from auditable_mcp.schema import validate_event


def _base_event() -> dict:
    """Build a minimal valid (unsigned) event."""
    return {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': 'auditable-mcp/0.1',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
        'params_hash': f'sha256:{"0" * 64}',
    }
    # end def


def test_signed_event_verifies() -> None:
    """A signed event verifies against the registered public key."""
    key = generate_tool_key('k1')
    signed = sign_event(_base_event(), key.key_id, 0, key.private_key)
    assert signed['signature']
    assert verify_event_signature(signed, key.public_key)
    # end def


def test_tampering_invalidates_signature() -> None:
    """Tampering any signed field invalidates the signature (forgery blocked)."""
    key = generate_tool_key('k1')
    signed = sign_event(_base_event(), key.key_id, 0, key.private_key)
    forged = {**signed, 'target_resource': {'kind': 'table', 'ref': 'salaries'}}
    assert not verify_event_signature(forged, key.public_key)
    # end def


def test_different_key_does_not_verify() -> None:
    """A signature from a different key does not verify."""
    key = generate_tool_key('k1')
    other = generate_tool_key('k2')
    signed = sign_event(_base_event(), key.key_id, 0, key.private_key)
    assert not verify_event_signature(signed, other.public_key)
    # end def


def test_l1_subset_of_l2_schema() -> None:
    """An unsigned (L1) event and a signed (L2) event both validate against the one schema."""
    l1 = _base_event()
    assert validate_event(l1) is None
    assert 'signature' not in l1

    key = generate_tool_key('k1')
    l2 = sign_event(l1, key.key_id, 7, key.private_key)
    assert validate_event(l2) is None
    assert l2['key_id'] == 'k1'
    assert l2['sequence'] == 7
    # end def


def test_signer_stamps_monotonic_sequence() -> None:
    """The signer stamps a monotonic per-tool sequence."""
    key = generate_tool_key('k1')
    signer = Ed25519Signer(key.key_id, key.private_key)
    a = signer.sign(_base_event())
    b = signer.sign({**_base_event(), 'id': '00000000-0000-4000-8000-000000000002'})
    assert a['sequence'] == 0
    assert b['sequence'] == 1
    assert verify_event_signature(a, key.public_key)
    assert verify_event_signature(b, key.public_key)
    # end def
