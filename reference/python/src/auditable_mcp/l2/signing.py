"""L2 signing over canonical(event minus signature).

key_id and signer_seq are part of the signed payload, so tampering with any field invalidates the
signature. Signing dispatches on the key's algorithm (§5.1): Ed25519 produces a 64-byte raw
signature; ES256 is encoded as the fixed-length r||s form (64 bytes), not DER, so the wire signature
is one unambiguous encoding a foreign verifier decodes without guessing. Both are carried as base64url
without padding, as JWS writes a signature.
"""

from collections.abc import Callable
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from auditable_mcp.canonical import canonicalize
from auditable_mcp.encoding import b64url_decode, b64url_encode
from auditable_mcp.l2.keys import KeyRegistry, PrivateKey, PublicKey, RegisteredKey, SignatureAlg

__all__ = [
    'KeySigner',
    'b64url_decode',
    'b64url_encode',
    'countersignature_check',
    'sign_event',
    'verify_detached',
    'verify_event_signature',
]

_P256_COORD_BYTES = 32
# Both algorithms produce exactly 64 raw bytes (§5.1); anything else - a DER-encoded ECDSA signature
# among them - fails verification rather than being reinterpreted.
_RAW_SIGNATURE_BYTES = 64


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


def verify_detached(alg: SignatureAlg, public_key: PublicKey, data: bytes, signature: bytes) -> bool:
    """Verify a raw detached signature under the algorithm bound to the key (§5.1)."""
    if len(signature) != _RAW_SIGNATURE_BYTES:
        return False
    try:
        if alg == 'Ed25519':
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(signature, data)
            return True
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        r = int.from_bytes(signature[:_P256_COORD_BYTES], 'big')
        s = int.from_bytes(signature[_P256_COORD_BYTES:], 'big')
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def sign_event(event: dict, key_id: str, signer_seq: int, alg: SignatureAlg, private_key: PrivateKey) -> dict:
    """Return the event stamped with key_id, signer_seq, and a detached signature."""
    signed = {**event, 'key_id': key_id, 'signer_seq': signer_seq}
    signature = b64url_encode(_sign_bytes(alg, _signature_input(signed), private_key))
    return {**signed, 'signature': signature}


def verify_event_signature(
    event: dict, registered: RegisteredKey, decode: Callable[[str], bytes] = b64url_decode
) -> bool:
    """Return True if the event's signature verifies against the registered key (§7.4).

    `decode` reads the signature field; records of versions before 0.3 encoded it as padded standard
    base64 (§11.4).
    """
    signature = event.get('signature')
    if not isinstance(signature, str) or not signature:
        return False
    try:
        return verify_detached(registered.alg, registered.public_key, _signature_input(event), decode(signature))
    except ValueError:
        return False


def countersignature_check(
    host_registry: KeyRegistry, purpose: Literal['tool', 'verifier']
) -> Callable[[str, str, str], bool]:
    """Return a countersignature check over a host-key registry (§7.2, §11.4).

    A tool accepts only a key that is registered and not revoked, since a revoked key confirms nothing
    new; a verifier checks a sealed record against a revoked entry as before (§10.9).
    """

    def check(host_key_id: str, signature: str, payload: str) -> bool:
        entry = host_registry.current(host_key_id) if purpose == 'tool' else host_registry.get(host_key_id)
        if entry is None:
            return False
        try:
            raw = b64url_decode(signature)
        except ValueError:
            return False
        return verify_detached(entry.alg, entry.public_key, payload.encode('utf-8'), raw)

    return check


class KeySigner:
    """Tool-side signer holding the private key, its algorithm, and a signer_seq per audit session.

    Each session is numbered from 0 (§7.4), so a suppressed event leaves a gap in its session.
    Nothing here awaits, so numbering and emission are one step and §7.4's atomic numbering holds by
    construction; a signer that awaits (a KMS call) holds a per-session lock across the same span.
    """

    def __init__(self, key_id: str, alg: SignatureAlg, private_key: PrivateKey) -> None:
        """Bind the signer to a key and algorithm."""
        self._key_id = key_id
        self._alg = alg
        self._private_key = private_key
        self._next: dict[str, int] = {}

    def sign(self, event: dict) -> dict:
        """Sign the event with the next signer_seq of its session."""
        signer_seq = self._next.get(event['session_id'], 0)
        signed = sign_event(event, self._key_id, signer_seq, self._alg, self._private_key)
        self._next[event['session_id']] = signer_seq + 1
        return signed
