"""The salted hash (§4.3), against the shared vectors and RFC 9901's own example."""

import json

from auditable_mcp.paths import SPEC_VECTORS_DIR
from auditable_mcp.salted_hash import (
    SALTED_HASH_PATTERN,
    disclosure_of,
    new_salt,
    open_salted_hash,
    salted_hash_of,
)


def test_salted_hash_vectors() -> None:
    cases = json.loads((SPEC_VECTORS_DIR / 'salted-hash.json').read_text(encoding='utf-8'))
    for case in cases:
        assert salted_hash_of(case['disclosure']) == case['salted_hash'], case['name']
        salt, value = case['decoded']
        if isinstance(value, dict):
            assert disclosure_of(salt, value) == case['disclosure'], case['name']
            assert open_salted_hash(case['disclosure'], case['salted_hash']) == value, case['name']


def test_rfc9901_example() -> None:
    assert salted_hash_of('WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0') == 'pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo'


def test_opens_only_with_its_own_disclosure() -> None:
    context: dict[str, object] = {'table': 'customers', 'rows': 3}
    disclosure = disclosure_of(new_salt(), context)
    digest = salted_hash_of(disclosure)
    assert SALTED_HASH_PATTERN.fullmatch(digest)
    assert open_salted_hash(disclosure, digest) == context
    assert open_salted_hash(disclosure_of(new_salt(), context), digest) is None
