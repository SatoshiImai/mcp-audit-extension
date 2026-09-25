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


def _is_lone_surrogate(text: str) -> bool:
    """Return True if the string holds a surrogate code point, which only a lone surrogate leaves."""
    return any('\ud800' <= char <= '\udfff' for char in text)


def has_lone_surrogate(value: object) -> bool:
    """Return True if any string, member names included, is not a sequence of Unicode scalar values.

    A lone surrogate has no UTF-8 encoding, so JCS cannot serialize it and ports diverge on it (§8.1).
    ``json.loads`` joins a valid surrogate pair into one code point, so only a lone one remains.
    """
    if isinstance(value, str):
        return _is_lone_surrogate(value)
    if isinstance(value, dict):
        return any(
            (isinstance(key, str) and _is_lone_surrogate(key)) or has_lone_surrogate(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(has_lone_surrogate(item) for item in value)
    return False


def canonical_domain_error(value: object) -> str | None:
    """Return why a value lies outside the §8.1 canonicalization domain, or None when it lies inside it."""
    if has_unsafe_number(value):
        return 'numeric-domain: a number is non-finite or outside +/-(2^53-1) (§8.1)'
    if has_lone_surrogate(value):
        return 'lone-surrogate: a string is not a sequence of Unicode scalar values (§8.1)'
    return None


def _assert_canonicalizable(value: object) -> None:
    """Raise if the value lies outside the canonicalization domain (§8.1)."""
    error = canonical_domain_error(value)
    if error is not None:
        raise ValueError(f'not canonicalizable: {error}')


def canonicalize(value: object) -> str:
    """Serialize a JSON-compatible value to its RFC 8785 (JCS) canonical string form.

    Args:
        value: Any JSON-compatible value (dict, list, str, int, bool, None).

    Returns:
        The RFC 8785 canonical JSON string.
    """
    _assert_canonicalizable(value)
    return rfc8785.dumps(value).decode('utf-8')


def sha256_hex(data: str) -> str:
    """Return the hex-encoded SHA-256 of ``data`` encoded as UTF-8."""
    return sha256(data.encode('utf-8')).hexdigest()


def hash_canonical(value: object) -> str:
    """Return the `sha256:<hex>` hash of the canonical form of `value` (an action_context_hash)."""
    return f'sha256:{sha256_hex(canonicalize(value))}'
