'''Deterministic canonical JSON serialization and hashing.

The canonical form must match the TypeScript reference byte-for-byte so both share one set
of conformance vectors: object keys sorted recursively, no insignificant whitespace,
non-ASCII preserved, ``null`` kept. Absent optional fields are omitted by the caller (event
serialization), never here.
'''

import json
from hashlib import sha256

# JSON separators with no insignificant whitespace (matches JSON.stringify output).
_SEPARATORS = (',', ':')


def canonicalize(value: object) -> str:
    '''Serialize a JSON-compatible value to its canonical string form.

    Args:
        value: Any JSON-compatible value (dict, list, str, int, bool, None).

    Returns:
        The canonical JSON string: keys sorted recursively, no whitespace, non-ASCII kept.
    '''
    return json.dumps(value, sort_keys=True, separators=_SEPARATORS, ensure_ascii=False)
    # end def


def sha256_hex(data: str) -> str:
    '''Return the hex-encoded SHA-256 of ``data`` encoded as UTF-8.'''
    return sha256(data.encode('utf-8')).hexdigest()
    # end def


def hash_params(params: object) -> str:
    '''Return the ``sha256:<hex>`` hash of the canonical form of ``params``.

    Tools hash their (masked) params rather than storing raw values.
    '''
    return f'sha256:{sha256_hex(canonicalize(params))}'
    # end def
