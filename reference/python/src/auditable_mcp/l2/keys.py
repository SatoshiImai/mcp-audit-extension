"""L2 key material: tool signing keys and the host key registry.

A tool holds a private key and stamps its self-attestations with a signature; the host verifies
against a public key registered out-of-band at onboarding (the trust anchor). The signature then
gives non-repudiation, not real-time control.

The algorithm is bound to the key_id by the registry (§5.1), not carried in the event, so one host
verifies a mixed Ed25519 + ECDSA P-256 fleet without an in-band algorithm.
"""

from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SignatureAlg = Literal['Ed25519', 'ECDSA_P256_SHA256']

PrivateKey = Ed25519PrivateKey | ec.EllipticCurvePrivateKey
PublicKey = Ed25519PublicKey | ec.EllipticCurvePublicKey

# §5.1: an entry's public key must be a key of the entry's algorithm.
_KEY_TYPES: dict[str, type] = {'Ed25519': Ed25519PublicKey, 'ECDSA_P256_SHA256': ec.EllipticCurvePublicKey}


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
    """A registered public key bound to its algorithm (§5.1)."""

    public_key: PublicKey
    alg: SignatureAlg


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
        a different fact from a misprovisioned registry.

        Raises:
            ValueError: The key_id is empty, or the key is not a key of `alg`.
        """
        if not key_id:
            raise ValueError('a registry entry binds a non-empty key_id (§5.1)')
        expected = _KEY_TYPES[alg]
        if not isinstance(public_key, expected):
            raise ValueError(f'a {alg} entry binds a {expected.__name__}, not a {type(public_key).__name__} (§5.1)')
        self._keys[key_id] = RegisteredKey(public_key=public_key, alg=alg)

    def get(self, key_id: str) -> RegisteredKey | None:
        """Return the registered key for key_id, or None if unknown."""
        return self._keys.get(key_id)
