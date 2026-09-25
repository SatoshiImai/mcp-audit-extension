"""Tests for key registry entries (§5.1, §10.9) and the raw signature encoding."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from auditable_mcp.canonical import canonicalize
from auditable_mcp.encoding import b64url_decode, b64url_encode
from auditable_mcp.l2.keys import KeyRegistry, RegisteredKey, ToolKey, assert_disjoint_registries, generate_tool_key
from auditable_mcp.l2.signing import countersignature_check, sign_event, verify_detached, verify_event_signature

EVENT = {
    'id': '00000000-0000-4000-8000-000000000001',
    'spec_version': 'auditable-mcp/0.3',
    'ts': '2026-07-15T00:00:01.000Z',
    'session_id': '0198f3a2-5c1e-7000-8000-00000000abc0',
    'action_type': 'db.write',
    'mutates': True,
    'egress': False,
    'target_resource': {'kind': 'table', 'ref': 'customers'},
    'outcome': 'attempted',
}


def _jwk(key_id: str, alg: str) -> dict:
    """Return the public JWK of a fresh key."""
    public_key = generate_tool_key(key_id, alg).public_key
    if alg == 'Ed25519':
        return {'kty': 'OKP', 'crv': 'Ed25519', 'x': b64url_encode(public_key.public_bytes_raw())}
    numbers = public_key.public_numbers()
    return {
        'kty': 'EC',
        'crv': 'P-256',
        'x': b64url_encode(numbers.x.to_bytes(32, 'big')),
        'y': b64url_encode(numbers.y.to_bytes(32, 'big')),
    }


def test_refuses_a_key_whose_algorithm_disagrees() -> None:
    """§5.1: a P-384 key under ES256, an Ed25519 key under ES256, and the reverse are refused."""
    registry = KeyRegistry()
    with pytest.raises(ValueError, match='not a ES256'):
        registry.register('k', ec.generate_private_key(ec.SECP384R1()).public_key(), 'ES256')
    with pytest.raises(ValueError, match='not a ES256'):
        registry.register('k', generate_tool_key('k').public_key, 'ES256')
    with pytest.raises(ValueError, match='not a Ed25519'):
        registry.register('k', generate_tool_key('k', 'ES256').public_key, 'Ed25519')


def test_refuses_an_empty_key_id() -> None:
    """§5.1: a key_id is non-empty."""
    with pytest.raises(ValueError, match='non-empty'):
        KeyRegistry().register('', generate_tool_key('k').public_key, 'Ed25519')


def test_refuses_jwk_material_that_is_not_a_key_of_the_algorithm() -> None:
    """§5.1: wrong length, off the curve, another curve, or a private half is refused."""
    registry = KeyRegistry()
    ed = _jwk('ed', 'Ed25519')
    p256 = _jwk('ec', 'ES256')
    with pytest.raises(ValueError, match='not 32'):
        registry.register_jwk('a', {**ed, 'x': b64url_encode(b64url_decode(ed['x'])[:-3])}, 'Ed25519')
    with pytest.raises(ValueError):
        registry.register_jwk('b', {**p256, 'y': p256['x']}, 'ES256')
    with pytest.raises(ValueError, match='not a P-256'):
        registry.register_jwk('c', {**p256, 'crv': 'P-384'}, 'ES256')
    with pytest.raises(ValueError, match='private key'):
        registry.register_jwk('d', {**ed, 'd': ed['x']}, 'Ed25519')
    registry.register_jwk('e', p256, 'ES256')
    assert registry.get('e').alg == 'ES256'


def test_a_key_id_binds_one_key() -> None:
    """§10.9: re-registering the same key is harmless; binding another key is refused."""
    registry = KeyRegistry()
    key = generate_tool_key('k')
    registry.register('k', key.public_key, 'Ed25519')
    registry.register('k', key.public_key, 'Ed25519')
    with pytest.raises(ValueError, match='already bound'):
        registry.register('k', generate_tool_key('k').public_key, 'Ed25519')


def test_a_revoked_entry_still_verifies_historical_records() -> None:
    """§10.9: a revoked entry is kept for the verifier and offered for nothing new."""
    registry = KeyRegistry()
    key = generate_tool_key('k')
    registry.register('k', key.public_key, 'Ed25519')
    signed = sign_event(EVENT, 'k', 0, 'Ed25519', key.private_key)
    registry.revoke('k')
    assert registry.current('k') is None
    assert verify_event_signature(signed, registry.get('k'))


def test_a_tool_refuses_a_countersignature_under_a_revoked_host_key() -> None:
    """§10.9: the tool aborts on it; a verifier still checks it."""
    host = generate_tool_key('host')
    registry = KeyRegistry()
    registry.register('host', host.public_key, 'Ed25519')
    payload = '{"seq":0}'
    signature = b64url_encode(host.private_key.sign(payload.encode('utf-8')))
    assert countersignature_check(registry, 'tool')('host', signature, payload)
    registry.revoke('host')
    assert not countersignature_check(registry, 'tool')('host', signature, payload)
    assert countersignature_check(registry, 'verifier')('host', signature, payload)


def test_tool_and_host_registries_share_no_key() -> None:
    """§10.9: a key registered for a tool is not also registered for a host."""
    key = generate_tool_key('k')
    tools = KeyRegistry()
    hosts = KeyRegistry()
    tools.register('tool', key.public_key, 'Ed25519')
    hosts.register('host', generate_tool_key('h').public_key, 'Ed25519')
    assert_disjoint_registries(tools, hosts)
    hosts.register('host-2', key.public_key, 'Ed25519')
    with pytest.raises(ValueError, match='share a key'):
        assert_disjoint_registries(tools, hosts)


def test_a_der_encoded_es256_signature_is_rejected() -> None:
    """§5.1: ES256 is the 64-byte r||s form; a DER signature over the same bytes does not verify."""
    key = generate_tool_key('ec', 'ES256')
    signed = sign_event(EVENT, 'ec', 0, 'ES256', key.private_key)
    unsigned = {name: value for name, value in signed.items() if name != 'signature'}
    data = canonicalize(unsigned).encode('utf-8')
    der = key.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    assert len(der) != 64
    assert not verify_detached('ES256', key.public_key, data, der)
    assert not verify_event_signature({**signed, 'signature': b64url_encode(der)}, registered_of(key))


def test_an_ed25519_signature_of_the_wrong_length_is_rejected() -> None:
    """§5.1: an Ed25519 signature is exactly 64 bytes."""
    key = generate_tool_key('ed')
    good = key.private_key.sign(b'payload')
    assert verify_detached('Ed25519', key.public_key, b'payload', good)
    assert not verify_detached('Ed25519', key.public_key, b'payload', good + b'\x00')


def registered_of(key: ToolKey) -> RegisteredKey:
    """Register a tool key and return its entry."""
    registry = KeyRegistry()
    registry.register(key.key_id, key.public_key, key.alg)
    entry = registry.get(key.key_id)
    assert entry is not None
    return entry
