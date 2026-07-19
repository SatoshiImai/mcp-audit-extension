"""Deterministic canonical JSON serialization and hashing.

Serialization follows the JSON Canonicalization Scheme (JCS), RFC 8785, delegated to the
``rfc8785`` package rather than a hand-rolled serializer. The TypeScript port uses the
``canonicalize`` package; both implement RFC 8785 and produce byte-identical output (verified
against the shared conformance vectors under spec/vectors).
"""

import math
from hashlib import sha256

import rfc8785

_MAX_SAFE_INT = 2**53 - 1


def has_unsafe_number(value: object) -> bool:
    """Return True if any number is outside the §8.1 canonicalization domain.

    Rejected: non-finite values (no JCS form) and integer-valued numbers beyond +/-(2^53-1). A
    runtime cannot tell an exact integer (which would not round-trip as an IEEE-754 double, diverging
    from the TypeScript port which rounds silently) from an integer-valued float, so all are
    conservatively rejected for cross-language identity. A host uses this to reject such an event
    gracefully (§7.1) rather than let canonicalize() raise at seal time.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) > _MAX_SAFE_INT
    if isinstance(value, float):
        return not math.isfinite(value) or (value.is_integer() and abs(value) > _MAX_SAFE_INT)
    if isinstance(value, dict):
        return any(has_unsafe_number(item) for item in value.values())
    if isinstance(value, list):
        return any(has_unsafe_number(item) for item in value)
    return False


def _assert_safe_numbers(value: object) -> None:
    """Raise if any number is not canonicalizable (non-finite or outside +/-(2^53-1)) (§8.1)."""
    if has_unsafe_number(value):
        raise ValueError('a numeric value is not canonicalizable (non-finite or outside +/-(2^53-1)) (§8.1)')


def canonicalize(value: object) -> str:
    """Serialize a JSON-compatible value to its RFC 8785 (JCS) canonical string form.

    Args:
        value: Any JSON-compatible value (dict, list, str, int, bool, None).

    Returns:
        The RFC 8785 canonical JSON string.
    """
    _assert_safe_numbers(value)
    return rfc8785.dumps(value).decode('utf-8')


def sha256_hex(data: str) -> str:
    """Return the hex-encoded SHA-256 of ``data`` encoded as UTF-8."""
    return sha256(data.encode('utf-8')).hexdigest()


def hash_canonical(value: object) -> str:
    """Return the `sha256:<hex>` hash of the canonical form of `value` (an action_context_hash)."""
    return f'sha256:{sha256_hex(canonicalize(value))}'
