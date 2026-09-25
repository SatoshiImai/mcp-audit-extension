"""Conformance: reproduce the shared golden vectors byte-for-byte.

These are the same vectors the TypeScript reference generates and checks. Passing them proves
the two implementations produce identical canonical bytes, hashes, and sealed chains - the
cross-language contract that makes the Python mirror verifiable.
"""

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from auditable_mcp.canonical import canonicalize, sha256_hex
from auditable_mcp.capability import AuditCapability
from auditable_mcp.host import AuditHost
from auditable_mcp.l2.keys import KeyRegistry, RegisteredKey
from auditable_mcp.l2.signing import b64url_decode, verify_event_signature
from auditable_mcp.ledger import GENESIS_HASH, SealedRecord, compute_record_hash, countersignature_payload
from auditable_mcp.paths import SPEC_VECTORS_DIR
from auditable_mcp.verify import ExpectedIdentity, unaccounted_signer_seq, verify_ledger


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


def _public_key(chain: dict, key_id: str) -> Ed25519PublicKey:
    """Return the Ed25519 public key a chain vector publishes, as a JWK, under `key_id`."""
    jwk = chain['keys'][key_id]['jwk']
    assert jwk['kty'] == 'OKP' and jwk['crv'] == 'Ed25519'
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk['x']))


def test_signed_chain_signatures_verify() -> None:
    """Every Level-2 signature verifies against the published key, numbered from 0 in its session (§5.1, §7.4)."""
    chain = _load('chain-signed.json')
    for i, record in enumerate(chain['records']):
        event = record['event']
        assert event['signer_seq'] == i
        registered = RegisteredKey(public_key=_public_key(chain, event['key_id']), alg='Ed25519')
        assert verify_event_signature(event, registered)


def test_countersigned_chain_vector() -> None:
    """Reproduce the countersigned chain: the same records, plus the triple a countersigning host adds (§5.2, §7.1).

    The countersignature is not part of the §8.2 preimage, so this chain's record hashes and digest
    are the uncountersigned chain's. The vector pins the preimage the host signs over, where the
    triple sits on the record, and a signature that verifies against the published key.
    """
    chain = _load('chain-countersigned.json')
    _recompute_chain('chain-countersigned.json')
    assert chain['digest'] == _load('chain.json')['digest']
    for record in chain['records']:
        preimage = record['countersignature_preimage']
        canonical = countersignature_payload(
            record['seq'], record['host_ts'], record['log_id'], record['previous_hash'], record['record_hash']
        )
        assert canonical == preimage['canonical']
        assert sha256_hex(preimage['canonical']) == preimage['sha256']
        public_key = _public_key(chain, record['host_key_id'])
        public_key.verify(b64url_decode(record['host_signature']), canonical.encode('utf-8'))


def test_signer_seq_accounting_vector() -> None:
    """§11.4's accounting reports exactly the pinned values for every case."""
    for case in _load('signer-seq-accounting.json'):
        records = [
            SealedRecord(event=event, seq=0, host_ts='', previous_hash='', record_hash='') for event in case['records']
        ]
        assert unaccounted_signer_seq(records) == case['unaccounted'], case['name']


def test_signer_seq_replay_vector() -> None:
    """§7.4: the replay window, step by step against one Level-2 host."""
    vector = _load('signer-seq-replay.json')
    registry = KeyRegistry()
    for key_id, entry in vector['keys'].items():
        registry.register_jwk(key_id, entry['jwk'], entry['alg'])
    host = AuditHost('replay', AuditCapability(level='L2'), registry)
    host.open_session(vector['steps'][0]['event']['session_id'])
    for step in vector['steps']:
        host.unavailable = not step['host_available']
        anomalies_before = len(host.anomalies())
        records_before = len(host.records())
        expect = step['expect']
        if step['channel'] == 'attempt':
            response = host.handle_attempt(step['event'])
            assert response.status == expect['status'], step['name']
            if 'reason' in expect:
                assert response.reason == expect['reason'], step['name']
            if 'seq' in expect:
                assert response.seq == expect['seq'], step['name']
        else:
            host.handle_outcome(step['event'])
            assert len(host.records()) - records_before == (1 if expect['sealed'] else 0), step['name']
        assert [a.kind for a in host.anomalies()[anomalies_before:]] == expect['anomalies'], step['name']


def test_verifier_cases_vector() -> None:
    """§11.4: the verifier reports exactly the pinned kinds for each ledger and its out-of-band inputs."""
    vector = _load('verifier-cases.json')
    host_key_registry = KeyRegistry()
    for key_id, entry in vector['keys'].items():
        host_key_registry.register_jwk(key_id, entry['jwk'], entry['alg'])
    for case in vector['cases']:
        options = case['options']
        identity = options.get('expected_identity')
        report = verify_ledger(
            [SealedRecord(**record) for record in case['records']],
            host_key_registry=host_key_registry,
            countersignature_required=options.get('countersignature_required', False),
            expected_identity=(
                None
                if identity is None
                else ExpectedIdentity(log_id=identity['log_id'], host_key_ids=frozenset(identity['host_key_ids']))
            ),
        )
        assert sorted(issue.kind for issue in report.issues) == case['expect_kinds'], case['name']
        assert report.unchecked == [], case['name']
