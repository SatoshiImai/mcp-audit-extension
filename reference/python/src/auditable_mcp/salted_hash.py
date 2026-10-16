"""The salted hash of an internal context (§4.3).

The construction of SD-JWT [RFC-9901] §4.2.2 and §4.2.3, applied to the whole context as one
array-element Disclosure: the Disclosure is base64url(UTF-8(JSON [salt, context])) and the salted
hash is base64url(SHA-256(ASCII(Disclosure))). The digest is taken over the Disclosure string as the
tool encoded it, so its JSON need not be canonical: whoever opens the hash is handed that exact string.
"""

import json
import re
import secrets
from hashlib import sha256

from auditable_mcp.encoding import b64url_decode, b64url_encode

SALTED_HASH_PATTERN = re.compile(r'[A-Za-z0-9_-]{43}')

# RFC 9901 §4.2.1 recommends at least 128 bits of salt.
_SALT_BYTES = 16


def new_salt() -> str:
    """Return a fresh base64url salt of 128 bits."""
    return b64url_encode(secrets.token_bytes(_SALT_BYTES))


def disclosure_of(salt: str, context: dict[str, object]) -> str:
    """Return the Disclosure of `context` under `salt`."""
    return b64url_encode(json.dumps([salt, context], ensure_ascii=False, separators=(',', ':')).encode('utf-8'))


def salted_hash_of(disclosure: str) -> str:
    """Return the salted hash of a Disclosure: base64url of the SHA-256 of its ASCII bytes."""
    return b64url_encode(sha256(disclosure.encode('ascii')).digest())


def open_salted_hash(disclosure: str, salted_hash: str) -> dict[str, object] | None:
    """Return the context `disclosure` opens if it is the one `salted_hash` commits to, else None."""
    try:
        if salted_hash_of(disclosure) != salted_hash:
            return None
        decoded = json.loads(b64url_decode(disclosure).decode('utf-8'))
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(decoded, list) or len(decoded) != 2 or not isinstance(decoded[0], str):
        return None
    context = decoded[1]
    if not isinstance(context, dict):
        return None
    return context
