"""L2 key material: Ed25519 tool keys and the host key registry.

A tool holds a private key and stamps its self-attestations with a signature; the host
verifies against a public key registered out-of-band at onboarding (the trust anchor). The
signature then gives non-repudiation, not real-time control.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass
class ToolKey:
    """A tool's Ed25519 key pair and its identity."""

    key_id: str
    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey
    # end class


def generate_tool_key(key_id: str) -> ToolKey:
    """Generate a fresh Ed25519 tool key under the given key_id."""
    private_key = Ed25519PrivateKey.generate()
    return ToolKey(key_id=key_id, public_key=private_key.public_key(), private_key=private_key)
    # end def


class KeyRegistry:
    """Maps key_id -> registered public key (established out-of-band at onboarding).

    A key_id the host has never onboarded is untrusted: its events are rejected as
    unverifiable (a lie into the ledger), never silently accepted.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._keys: dict[str, Ed25519PublicKey] = {}
        # end def

    def register(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        """Register a public key under its key_id."""
        self._keys[key_id] = public_key
        # end def

    def get(self, key_id: str) -> Ed25519PublicKey | None:
        """Return the registered public key for key_id, or None if unknown."""
        return self._keys.get(key_id)
        # end def

    # end class
