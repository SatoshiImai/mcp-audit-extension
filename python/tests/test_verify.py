"""Tests for the verifier: proof of non-tampering + completeness."""

from auditable_mcp.demo.scenario import run_clean_scenario
from auditable_mcp.verify import verify_ledger


def test_clean_ledger_verifies() -> None:
    """A clean ledger verifies with zero issues and matches the anchored digest."""
    host = run_clean_scenario()
    anchored = host.ledger.digest()
    report = verify_ledger(host.records(), anchored)
    assert report.ok
    assert report.issues == []
    assert report.computed_digest == anchored
    # end def


def test_detects_tampering() -> None:
    """Tampering a sealed field breaks the record hash and the anchored digest."""
    host = run_clean_scenario()
    anchored = host.ledger.digest()
    host.records()[1].event['target_resource']['ref'] = 'https://evil.example/exfil'
    report = verify_ledger(host.records(), anchored)
    assert not report.ok
    assert any(i.kind == 'record-hash-mismatch' for i in report.issues)
    assert any(i.kind == 'digest-mismatch' for i in report.issues)
    # end def


def test_detects_dropped_record() -> None:
    """Dropping a record is caught by a sequence gap (completeness)."""
    host = run_clean_scenario()
    records = host.records()
    del records[2]
    report = verify_ledger(records)
    assert not report.ok
    assert any(i.kind in ('seq-gap', 'prev-hash-mismatch') for i in report.issues)
    # end def
