"""L2 signing over canonical(event minus signature).

The signature covers ``canonical(event minus signature)`` -- so key_id and sequence are
inside the signed bytes, and tampering any field (including sequence) invalidates it. This is
what lets the host reject a forged/altered record: the "block a lie into the camera"
primitive (design §6.1), which is detection of tampering, not control of actions.
"""

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from auditable_mcp.canonical import canonicalize


def _signature_input(event: dict) -> bytes:
    """Return the bytes to sign: canonical(event without the signature field), UTF-8."""
    rest = {key: value for key, value in event.items() if key != 'signature'}
    return canonicalize(rest).encode('utf-8')
    # end def


def sign_event(event: dict, key_id: str, sequence: int, private_key: Ed25519PrivateKey) -> dict:
    """Return the event stamped with key_id, sequence, and a detached signature."""
    signed = {**event, 'key_id': key_id, 'sequence': sequence}
    signature = base64.b64encode(private_key.sign(_signature_input(signed))).decode('ascii')
    return {**signed, 'signature': signature}
    # end def


def verify_event_signature(event: dict, public_key: Ed25519PublicKey) -> bool:
    """Return True if the event's signature verifies against the public key."""
    signature = event.get('signature')
    if not signature:
        return False
        # end if
    try:
        public_key.verify(base64.b64decode(signature), _signature_input(event))
        return True
    except (InvalidSignature, ValueError):
        return False
        # end try
    # end def


class Ed25519Signer:
    """Tool-side signer holding the private key and a monotonic per-tool sequence counter.

    The same counter advances across every emitted event (attempt and outcome), so a
    suppressed event leaves a gap the host detects (design §3.2 L2).
    """

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        """Bind the signer to a key and start the sequence at zero."""
        self._key_id = key_id
        self._private_key = private_key
        self._seq = 0
        # end def

    def sign(self, event: dict) -> dict:
        """Sign the event with the next sequence number."""
        signed = sign_event(event, self._key_id, self._seq, self._private_key)
        self._seq += 1
        return signed
        # end def

    # end class
