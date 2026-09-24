"""Tests for L2 signing and the shared-schema invariant."""

import base64

from auditable_mcp.l2.keys import generate_tool_key
from auditable_mcp.l2.signing import KeySigner, sign_event, verify_event_signature
from auditable_mcp.schema import validate_event


def _base_event() -> dict:
    """Build a minimal valid (unsigned) event."""
    return {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': 'auditable-mcp/0.3',
        'ts': '2026-07-15T00:00:01.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': 'attempted',
        'action_context_hash': f'sha256:{"0" * 64}',
    }


def test_signed_event_verifies() -> None:
    """A signed event verifies against the registered public key."""
    key = generate_tool_key('k1')
    signed = sign_event(_base_event(), key.key_id, 0, key.alg, key.private_key)
    assert signed['signature']
    assert verify_event_signature(signed, key)


def test_tampering_invalidates_signature() -> None:
    """Tampering any signed field invalidates the signature (forgery blocked)."""
    key = generate_tool_key('k1')
    signed = sign_event(_base_event(), key.key_id, 0, key.alg, key.private_key)
    forged = {**signed, 'target_resource': {'kind': 'table', 'ref': 'salaries'}}
    assert not verify_event_signature(forged, key)


def test_different_key_does_not_verify() -> None:
    """A signature from a different key does not verify."""
    key = generate_tool_key('k1')
    other = generate_tool_key('k2')
    signed = sign_event(_base_event(), key.key_id, 0, key.alg, key.private_key)
    assert not verify_event_signature(signed, other)


def test_shared_schema_covers_both_levels() -> None:
    """An unsigned (L1) event and a signed (L2) event both validate against the one schema."""
    l1 = _base_event()
    assert validate_event(l1) is None
    assert 'signature' not in l1

    key = generate_tool_key('k1')
    l2 = sign_event(l1, key.key_id, 7, key.alg, key.private_key)
    assert validate_event(l2) is None
    assert l2['key_id'] == 'k1'
    assert l2['signer_seq'] == 7


def test_signer_stamps_monotonic_sequence() -> None:
    """The signer stamps a monotonic per-key signer_seq."""
    key = generate_tool_key('k1')
    signer = KeySigner(key.key_id, key.alg, key.private_key)
    a = signer.sign(_base_event())
    b = signer.sign({**_base_event(), 'id': '00000000-0000-4000-8000-000000000002'})
    assert a['signer_seq'] == 0
    assert b['signer_seq'] == 1
    assert verify_event_signature(a, key)
    assert verify_event_signature(b, key)


def test_ecdsa_p256_signs_and_verifies_fixed_length() -> None:
    """ECDSA P-256 (KMS/PKI profile) signs and verifies as fixed-length r||s (§5.1)."""
    key = generate_tool_key('kms-key', 'ECDSA_P256_SHA256')
    assert key.alg == 'ECDSA_P256_SHA256'
    signed = sign_event(_base_event(), key.key_id, 0, key.alg, key.private_key)
    # IEEE P1363 r||s: 64 raw bytes, not DER, so a foreign verifier decodes it unambiguously.
    assert len(base64.b64decode(signed['signature'])) == 64
    assert verify_event_signature(signed, key)
    forged = {**signed, 'target_resource': {'kind': 'table', 'ref': 'salaries'}}
    assert not verify_event_signature(forged, key)


def test_verifier_dispatches_on_key_bound_algorithm() -> None:
    """A mixed Ed25519 + ECDSA fleet verifies: the algorithm comes from the key, not the payload."""
    ed_key = generate_tool_key('ed', 'Ed25519')
    ec_key = generate_tool_key('ec', 'ECDSA_P256_SHA256')
    ed_signed = sign_event(_base_event(), ed_key.key_id, 0, ed_key.alg, ed_key.private_key)
    ec_signed = sign_event(_base_event(), ec_key.key_id, 0, ec_key.alg, ec_key.private_key)
    assert verify_event_signature(ed_signed, ed_key)
    assert verify_event_signature(ec_signed, ec_key)
    # Verifying under the other algorithm's key fails.
    assert not verify_event_signature(ed_signed, ec_key)
    assert not verify_event_signature(ec_signed, ed_key)
