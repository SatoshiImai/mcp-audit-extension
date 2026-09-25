"""L2 key material: tool signing keys and the host key registry.

A tool holds a private key and stamps its self-attestations with a signature; the host verifies
against a public key registered out-of-band at onboarding (the trust anchor). The signature then
gives non-repudiation, not real-time control.

The algorithm is bound to the key_id by the registry (§5.1), not carried in the event, so one host
verifies a mixed Ed25519 + ES256 fleet without an in-band algorithm. The identifiers are the
fully-specified JOSE names (RFC 9864).
"""

from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from auditable_mcp.encoding import b64url_decode

SignatureAlg = Literal['Ed25519', 'ES256']

PrivateKey = Ed25519PrivateKey | ec.EllipticCurvePrivateKey
PublicKey = Ed25519PublicKey | ec.EllipticCurvePublicKey

_COORDINATE_BYTES = 32


@dataclass
class ToolKey:
    """A tool's key pair, its identity, and the algorithm bound to it."""

    key_id: str
    alg: SignatureAlg
    public_key: PublicKey
    private_key: PrivateKey


def generate_tool_key(key_id: str, alg: SignatureAlg = 'Ed25519') -> ToolKey:
    """Generate a fresh tool key for the given algorithm under the given key_id."""
    private_key: PrivateKey = (
        Ed25519PrivateKey.generate() if alg == 'Ed25519' else ec.generate_private_key(ec.SECP256R1())
    )
    return ToolKey(key_id=key_id, alg=alg, public_key=private_key.public_key(), private_key=private_key)


@dataclass
class RegisteredKey:
    """A registered public key bound to its algorithm (§5.1).

    A revoked entry stays in the registry: records sealed while the key was valid still verify
    against it, and nothing new is accepted under it (§10.9).
    """

    public_key: PublicKey
    alg: SignatureAlg
    revoked: bool = False


def _raw(public_key: PublicKey) -> bytes:
    """Return the public key's SubjectPublicKeyInfo bytes, to compare two keys."""
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _is_key_of(public_key: object, alg: SignatureAlg) -> bool:
    """Return True if the public key is a key of the algorithm (§5.1)."""
    if alg == 'Ed25519':
        return isinstance(public_key, Ed25519PublicKey)
    return isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1)


def _coordinate(jwk: dict, member: str, key_id: str) -> bytes:
    """Decode one 32-byte JWK key member (RFC 8037, RFC 7518)."""
    value = jwk.get(member)
    if not isinstance(value, str):
        raise ValueError(f'the JWK registered as {key_id} has no {member} (§5.1)')
    raw = b64url_decode(value)
    if len(raw) != _COORDINATE_BYTES:
        raise ValueError(f'the JWK registered as {key_id} has a {member} of {len(raw)} bytes, not 32 (§5.1)')
    return raw


def public_key_from_jwk(key_id: str, jwk: dict, alg: SignatureAlg) -> PublicKey:
    """Build the public key a JWK (RFC 7517) holds, refusing material that is not a key of `alg`.

    Raises:
        ValueError: The JWK carries a private half, names another key type or curve, has key material
            of the wrong length, or holds a point that is not on the curve.
    """
    if 'd' in jwk:
        raise ValueError(f'the JWK registered as {key_id} carries a private key')
    if alg == 'Ed25519':
        if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519':
            raise ValueError(f'the JWK registered as {key_id} is not an Ed25519 key (§5.1)')
        return Ed25519PublicKey.from_public_bytes(_coordinate(jwk, 'x', key_id))
    if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
        raise ValueError(f'the JWK registered as {key_id} is not a P-256 key (§5.1)')
    x = int.from_bytes(_coordinate(jwk, 'x', key_id), 'big')
    y = int.from_bytes(_coordinate(jwk, 'y', key_id), 'big')
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


class KeyRegistry:
    """Maps key_id -> registered key (public key + algorithm), established out-of-band at onboarding.

    A key_id the host has never onboarded is untrusted; its events are rejected as unverifiable.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._keys: dict[str, RegisteredKey] = {}

    def register(self, key_id: str, public_key: PublicKey, alg: SignatureAlg) -> None:
        """Register a public key and its algorithm under key_id.

        §5.1 requires a non-empty key_id and a public key of the entry's algorithm. An entry whose
        key and algorithm disagree is refused here rather than carried to verification time, where
        every event bound to it would be rejected `signature-invalid` - a forged signature, which is
        a different fact from a misprovisioned registry. §10.9: a key_id binds one key for its lifetime.

        Raises:
            ValueError: The key_id is empty, the key is not a key of `alg`, or the key_id is already
                bound to another key.
        """
        if not key_id:
            raise ValueError('a registry entry binds a non-empty key_id (§5.1)')
        if not _is_key_of(public_key, alg):
            raise ValueError(f'the key registered as {key_id} is not a {alg} public key (§5.1)')
        existing = self._keys.get(key_id)
        if existing is None:
            self._keys[key_id] = RegisteredKey(public_key=public_key, alg=alg)
        elif existing.alg != alg or _raw(existing.public_key) != _raw(public_key):
            raise ValueError(f'{key_id} is already bound to another key (§10.9)')

    def register_jwk(self, key_id: str, jwk: dict, alg: SignatureAlg) -> None:
        """Register the public key a JWK holds, the form a registry is commonly provisioned from (§5.1).

        Raises:
            ValueError: The JWK is not a public key of `alg` (see `public_key_from_jwk`), or `register`
                refuses the entry.
        """
        self.register(key_id, public_key_from_jwk(key_id, jwk, alg), alg)

    def revoke(self, key_id: str) -> None:
        """Mark an entry revoked; it stays registered for the records sealed before (§10.9).

        Raises:
            KeyError: The key_id is not registered.
        """
        self._keys[key_id].revoked = True

    def get(self, key_id: str) -> RegisteredKey | None:
        """Return the entry, revoked or not: a verifier checks a sealed record against it (§10.9)."""
        return self._keys.get(key_id)

    def current(self, key_id: str) -> RegisteredKey | None:
        """Return the entry an event arriving now may be accepted under: a revoked key confirms nothing new."""
        entry = self._keys.get(key_id)
        return None if entry is None or entry.revoked else entry

    def shares_key_with(self, other: 'KeyRegistry') -> bool:
        """Return True if any key registered here is also registered in `other`."""
        mine = {_raw(entry.public_key) for entry in self._keys.values()}
        return any(_raw(entry.public_key) in mine for entry in other._keys.values())


def assert_disjoint_registries(tool: KeyRegistry, host: KeyRegistry) -> None:
    """Refuse a tool registry and a host registry that share a key (§10.9).

    A tool holding a key the countersignature registry binds to a host would manufacture the
    countersigned state (§5.2).

    Raises:
        ValueError: The two registries share a key.
    """
    if tool.shares_key_with(host):
        raise ValueError('the tool and host registries share a key (§10.9)')
