"""L2 signing over canonical(event minus signature).

key_id and signer_seq are part of the signed payload, so tampering with any field invalidates the
signature. Signing dispatches on the key's algorithm (§5.1): Ed25519 produces a 64-byte raw
signature; ECDSA P-256 is encoded as the fixed-length IEEE P1363 r||s form (64 bytes), not DER, so
the wire signature is one unambiguous encoding a foreign verifier decodes without guessing. Both are
carried as standard base64.
"""

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from auditable_mcp.canonical import canonicalize
from auditable_mcp.l2.keys import PrivateKey, RegisteredKey, SignatureAlg

_P256_COORD_BYTES = 32


def _signature_input(event: dict) -> bytes:
    """Return the bytes to sign: canonical(event without the signature field), UTF-8."""
    rest = {key: value for key, value in event.items() if key != 'signature'}
    return canonicalize(rest).encode('utf-8')


def _sign_bytes(alg: SignatureAlg, data: bytes, private_key: PrivateKey) -> bytes:
    """Produce the raw detached signature for the algorithm bound to the key."""
    if alg == 'Ed25519':
        assert isinstance(private_key, Ed25519PrivateKey)
        return private_key.sign(data)
    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(_P256_COORD_BYTES, 'big') + s.to_bytes(_P256_COORD_BYTES, 'big')


def _verify_bytes(registered: RegisteredKey, data: bytes, signature: bytes) -> bool:
    """Verify a raw detached signature against the registered key and its algorithm."""
    public_key = registered.public_key
    if registered.alg == 'Ed25519':
        public_key.verify(signature, data)
        return True
    if len(signature) != _P256_COORD_BYTES * 2:
        return False
    r = int.from_bytes(signature[:_P256_COORD_BYTES], 'big')
    s = int.from_bytes(signature[_P256_COORD_BYTES:], 'big')
    public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    return True


def sign_event(event: dict, key_id: str, signer_seq: int, alg: SignatureAlg, private_key: PrivateKey) -> dict:
    """Return the event stamped with key_id, signer_seq, and a detached signature."""
    signed = {**event, 'key_id': key_id, 'signer_seq': signer_seq}
    signature = base64.b64encode(_sign_bytes(alg, _signature_input(signed), private_key)).decode('ascii')
    return {**signed, 'signature': signature}


def verify_event_signature(event: dict, registered: RegisteredKey) -> bool:
    """Return True if the event's signature verifies against the registered key (§7.4)."""
    signature = event.get('signature')
    if not signature:
        return False
    try:
        return _verify_bytes(registered, _signature_input(event), base64.b64decode(signature))
    except (InvalidSignature, ValueError):
        return False


class KeySigner:
    """Tool-side signer holding the private key, its algorithm, and a monotonic per-key signer_seq.

    The counter advances across every emitted event, so a suppressed event leaves a gap.
    """

    def __init__(self, key_id: str, alg: SignatureAlg, private_key: PrivateKey) -> None:
        """Bind the signer to a key and algorithm and start signer_seq at zero."""
        self._key_id = key_id
        self._alg = alg
        self._private_key = private_key
        self._seq = 0

    def sign(self, event: dict) -> dict:
        """Sign the event with the next signer_seq."""
        signed = sign_event(event, self._key_id, self._seq, self._alg, self._private_key)
        self._seq += 1
        return signed
