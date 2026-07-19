"""Conformance: reproduce the shared golden vectors byte-for-byte.

These are the same vectors the TypeScript reference generates and checks. Passing them proves
the two implementations produce identical canonical bytes, hashes, and sealed chains - the
cross-language contract that makes the Python mirror verifiable.
"""

import json

from auditable_mcp.canonical import canonicalize, sha256_hex
from auditable_mcp.ledger import GENESIS_HASH, compute_record_hash
from auditable_mcp.paths import SPEC_VECTORS_DIR


def _load(name: str) -> object:
    """Load a golden vector file from the shared spec directory."""
    return json.loads((SPEC_VECTORS_DIR / name).read_text(encoding='utf-8'))


def test_canonicalization_vectors() -> None:
    """Canonical serialization and its hash match the golden for every primitive case."""
    cases = _load('canonicalization.json')
    assert len(cases) > 0
    for case in cases:
        assert canonicalize(case['value']) == case['canonical']
        assert sha256_hex(case['canonical']) == case['sha256']


def test_event_vectors() -> None:
    """Canonical serialization and its hash match the golden for every event case."""
    cases = _load('events.json')
    assert len(cases) > 0
    for case in cases:
        assert canonicalize(case['event']) == case['canonical']
        assert sha256_hex(case['canonical']) == case['sha256']


def test_chain_vector() -> None:
    """Recompute every record hash and the final digest from the chain inputs."""
    chain = _load('chain.json')
    prev = GENESIS_HASH
    for i, record in enumerate(chain['records']):
        assert record['seq'] == i
        assert record['previous_hash'] == prev
        recomputed = compute_record_hash(record['event'], record['seq'], record['host_ts'], prev)
        assert recomputed == record['record_hash']
        prev = recomputed
    assert prev == chain['digest']
