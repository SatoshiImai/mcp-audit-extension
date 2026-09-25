"""The byte encodings of signatures and key material.

A signature of this version is base64url without padding, as JWS writes one (§5.1); records of
versions before 0.3 encoded it as padded standard base64 (§11.4). Both decoders are strict: they
refuse any input that does not re-encode to itself.
"""

import base64
import binascii
import re

_BASE64URL = re.compile(r'[A-Za-z0-9_-]*')
_BASE64 = re.compile(r'[A-Za-z0-9+/]*={0,2}')


def b64url_encode(raw: bytes) -> str:
    """Encode base64url without padding (§5.1)."""
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def b64url_decode(value: str) -> bytes:
    """Decode strict base64url without padding; raise ValueError on anything else (§5.1)."""
    if not _BASE64URL.fullmatch(value):
        raise ValueError('not base64url')
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except binascii.Error as error:
        raise ValueError('not base64url') from error
    if b64url_encode(raw) != value:
        raise ValueError('not canonical base64url')
    return raw


def b64_decode(value: str) -> bytes:
    """Decode strict padded standard base64, the signature encoding before 0.3; raise ValueError otherwise."""
    if not _BASE64.fullmatch(value):
        raise ValueError('not base64')
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as error:
        raise ValueError('not base64') from error
    if base64.b64encode(raw).decode('ascii') != value:
        raise ValueError('not canonical base64')
    return raw
