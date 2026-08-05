"""Tests for the ledger sequence and hash chain."""

import pytest

from auditable_mcp.canonical import canonicalize
from auditable_mcp.ledger import GENESIS_HASH, Ledger


def _event(event_id: str, outcome: str) -> dict:
    """Build a minimal valid event dict for ledger tests."""
    return {
        'id': event_id,
        'spec_version': 'auditable-mcp/0.2',
        'ts': '2026-07-15T00:00:00.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.read',
        'mutates': False,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers'},
        'outcome': outcome,
        'action_context_hash': f'sha256:{"0" * 64}',
    }


def test_assigns_sequence_and_links_chain() -> None:
    """Sequence starts at 0, previous_hash links, and the digest is the tail hash."""
    ledger = Ledger('t#d')
    a = ledger.append(_event('00000000-0000-4000-8000-000000000001', 'attempted'), 'host-ts:1')
    b = ledger.append(_event('00000000-0000-4000-8000-000000000001', 'success'), 'host-ts:2')
    assert a.seq == 0
    assert b.seq == 1
    assert a.previous_hash == GENESIS_HASH
    assert b.previous_hash == a.record_hash
    assert ledger.digest() == b.record_hash


def test_record_hash_is_deterministic() -> None:
    """Identical inputs produce an identical record hash across ledgers."""
    r1 = Ledger('t#d').append(_event('00000000-0000-4000-8000-000000000001', 'attempted'), 'host-ts:1')
    r2 = Ledger('t#d').append(_event('00000000-0000-4000-8000-000000000001', 'attempted'), 'host-ts:1')
    assert r1.record_hash == r2.record_hash


def test_canonicalize_is_key_order_independent() -> None:
    """Canonicalization does not depend on key insertion order."""
    assert canonicalize({'b': 1, 'a': 2}) == canonicalize({'a': 2, 'b': 1})


def test_canonicalize_rejects_integers_beyond_json_safe_range() -> None:
    """§8.1: the max JSON-safe integer canonicalizes, but a larger int or integer-valued float is rejected."""
    canonicalize({'n': 9007199254740991})
    with pytest.raises(ValueError):
        canonicalize({'n': 9007199254740992})
    with pytest.raises(ValueError):
        canonicalize({'ctx': {'rows': 1e21}})
