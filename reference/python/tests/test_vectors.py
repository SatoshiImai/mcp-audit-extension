"""Conformance: reproduce the shared golden vectors byte-for-byte.

These are the same vectors the TypeScript reference generates and checks. Passing them proves
the two implementations produce identical canonical bytes, hashes, and sealed chains - the
cross-language contract that makes the Python mirror verifiable.
"""

import json

from auditable_mcp.canonical import canonicalize, sha256_hex
from auditable_mcp.ledger import GENESIS_HASH, compute_record_hash, witness_payload
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


def _recompute_chain(name: str) -> None:
    """Recompute every record hash and the final digest from a chain vector's inputs."""
    chain = _load(name)
    prev = GENESIS_HASH
    for i, record in enumerate(chain['records']):
        assert record['seq'] == i
        assert record['previous_hash'] == prev
        recomputed = compute_record_hash(record['event'], record['seq'], record['host_ts'], prev)
        assert recomputed == record['record_hash']
        prev = recomputed
    assert prev == chain['digest']


def test_chain_vector() -> None:
    """Recompute every record hash and the final digest from the L1 chain inputs."""
    _recompute_chain('chain.json')


def test_signed_chain_vector() -> None:
    """Reproduce the Level-2 signed chain: record_hash is computed over the full event incl. signature (§8.2)."""
    chain = _load('chain-signed.json')
    assert all('signature' in record['event'] for record in chain['records'])
    _recompute_chain('chain-signed.json')


def test_witnessed_chain_vector() -> None:
    """Reproduce the witnessed chain: the same records, plus the pair a signing host adds (§5.2, §7.1).

    The witness signature is not part of the §8.2 preimage, so this chain's record hashes and digest
    are the unwitnessed chain's. What the vector pins is the preimage the host signs over and where
    the pair sits on the record.
    """
    chain = _load('chain-witnessed.json')
    _recompute_chain('chain-witnessed.json')
    assert chain['digest'] == _load('chain.json')['digest']
    for record in chain['records']:
        assert record['host_key_id'] and record['host_signature']
        preimage = record['witness_preimage']
        assert (
            witness_payload(record['seq'], record['host_ts'], record['previous_hash'], record['record_hash'])
            == preimage['canonical']
        )
        assert sha256_hex(preimage['canonical']) == preimage['sha256']
