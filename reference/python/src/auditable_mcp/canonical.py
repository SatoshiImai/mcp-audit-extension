"""Deterministic canonical JSON serialization and hashing.

Serialization follows the JSON Canonicalization Scheme (JCS), RFC 8785, delegated to the
``rfc8785`` package rather than a hand-rolled serializer. The TypeScript port uses the
``canonicalize`` package; both implement RFC 8785 and produce byte-identical output (verified
against the shared conformance vectors under spec/vectors).
"""

from hashlib import sha256

import rfc8785


def canonicalize(value: object) -> str:
    """Serialize a JSON-compatible value to its RFC 8785 (JCS) canonical string form.

    Args:
        value: Any JSON-compatible value (dict, list, str, int, bool, None).

    Returns:
        The RFC 8785 canonical JSON string.
    """
    return rfc8785.dumps(value).decode('utf-8')


def sha256_hex(data: str) -> str:
    """Return the hex-encoded SHA-256 of ``data`` encoded as UTF-8."""
    return sha256(data.encode('utf-8')).hexdigest()


def hash_canonical(value: object) -> str:
    """Return the `sha256:<hex>` hash of the canonical form of `value` (an action_context_hash)."""
    return f'sha256:{sha256_hex(canonicalize(value))}'
