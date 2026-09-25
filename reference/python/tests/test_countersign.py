"""The countersignature axis (§5.2): what a record carries, and what the tool does about it (§7.1, §7.2)."""

import base64
import json
from dataclasses import replace

import pytest

from auditable_mcp.amcp import AmcpAbortedError, AmcpSession, DeterministicDeps
from auditable_mcp.capability import AuditCapability
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.ledger import countersignature_payload
from auditable_mcp.verify import verify_ledger

_COUNTERSIGNING = AuditCapability(countersign='host')
_TARGET = {'kind': 'table', 'ref': 'customers'}
SESSION = '0198f3a2-5c1e-7000-8000-00000000abc0'


class _Signer:
    """A stand-in countersigner: these tests are about where the countersignature is required and
    checked, not about the algorithm, which the vectors exercise with a real key."""

    key_id = 'host-key-2026'

    def sign(self, payload: str) -> str:
        """Return a deterministic stand-in signature over `payload`."""
        return base64.urlsafe_b64encode(f'countersigned:{payload}'.encode()).rstrip(b'=').decode('ascii')


def _verifier(host_key_id: str, signature: str, payload: str) -> bool:
    """Accept only the signature this host's key produces over these exact bytes."""
    return host_key_id == 'host-key-2026' and signature == _Signer().sign(payload)


def _run(session: AmcpSession) -> None:
    """Run one audited action."""
    session.audited('db.read', _TARGET, lambda: None, mutates=False, egress=False)


def test_a_countersigning_host_signs_every_record_it_seals() -> None:
    """§7.1: attempts and outcomes alike, and both are persisted with the triple."""
    host = AuditHost('t#w', _COUNTERSIGNING, countersigner=_Signer())
    _run(AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps()))
    records = host.records()
    assert records
    assert all(
        record.host_signature is not None and record.host_key_id == 'host-key-2026' and record.log_id == 't#w'
        for record in records
    )


def test_a_host_declaring_none_returns_no_countersignature() -> None:
    """§7.1: a host declaring `none` MUST NOT return the triple, and cannot hold a signer to do it."""
    host = AuditHost('t#d')
    _run(AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps()))
    assert all(
        record.host_signature is None and record.host_key_id is None and record.log_id is None
        for record in host.records()
    )


def test_a_host_cannot_declare_a_countersignature_it_cannot_produce() -> None:
    """A declaration the host cannot honour is refused at construction, not at seal time."""
    with pytest.raises(ValueError, match='requires a Countersigner'):
        AuditHost('t#w', _COUNTERSIGNING)
    with pytest.raises(ValueError, match='must not hold'):
        AuditHost('t#d', countersigner=_Signer())


def test_a_tool_that_requires_a_countersignature_aborts_on_an_uncountersigned_accept() -> None:
    """§7.2: the tool must not act on a record no distinct party confirmed."""
    plain = AuditHost('t#d')
    session = AmcpSession(
        InProcessTransport(plain),
        plain.open_session(),
        DeterministicDeps(),
        countersignature_verifier=_verifier,
        require_countersign=True,
    )
    with pytest.raises(AmcpAbortedError) as aborted:
        _run(session)
    assert aborted.value.reason == 'host-uncountersigned'


def test_a_tool_aborts_on_a_countersignature_that_does_not_verify() -> None:
    """§7.2: a signature that is present and fails is `host-signature-invalid`, not uncountersigned."""

    class _Forger(_Signer):
        def sign(self, payload: str) -> str:
            return base64.urlsafe_b64encode(b'not-the-host').rstrip(b'=').decode('ascii')

    host = AuditHost('t#w', _COUNTERSIGNING, countersigner=_Forger())
    session = AmcpSession(
        InProcessTransport(host),
        host.open_session(),
        DeterministicDeps(),
        countersignature_verifier=_verifier,
        require_countersign=True,
    )
    with pytest.raises(AmcpAbortedError) as aborted:
        _run(session)
    assert aborted.value.reason == 'host-signature-invalid'


def test_requiring_a_countersignature_without_a_verifier_is_refused() -> None:
    """Every action would abort on a host that is signing correctly, so the pairing is enforced."""
    with pytest.raises(ValueError, match='CountersignatureVerifier'):
        AmcpSession(InProcessTransport(AuditHost('t#d')), SESSION, DeterministicDeps(), require_countersign=True)


def test_the_countersignature_preimage_is_the_host_assigned_fields_and_the_ledger_name() -> None:
    """§7.1: no signature field in the preimage, so there is no self-reference; `log_id` names the ledger."""
    payload = countersignature_payload(0, '2026-07-15T00:00:01.000Z', 't#w', '0' * 64, 'a' * 64)
    assert list(json.loads(payload)) == ['host_ts', 'log_id', 'previous_hash', 'record_hash', 'seq']
    assert 'signature' not in payload


def test_a_countersignature_does_not_verify_for_another_ledger() -> None:
    """§7.1: a record moved to another ledger carries a countersignature over the wrong name."""
    host = AuditHost('t#w', _COUNTERSIGNING, countersigner=_Signer())
    _run(AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps()))
    moved = [replace(record, log_id='t#other') for record in host.records()]
    assert 'host-signature-invalid' in [issue.kind for issue in verify_ledger(moved, None, _verifier).issues]


def test_a_verifier_without_the_registry_says_the_countersignature_was_not_checked() -> None:
    """§11.4: an unchecked signature and a valid one are not the same finding."""
    host = AuditHost('t#w', _COUNTERSIGNING, countersigner=_Signer())
    _run(AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps()))
    report = verify_ledger(host.records())
    assert report.ok
    assert report.unchecked == ['countersignature']
    assert report.complete is False


def test_a_verifier_with_the_registry_determines_the_countersignature() -> None:
    """§11.4: the countersignature is established from the record's own signature, never inferred."""
    host = AuditHost('t#w', _COUNTERSIGNING, countersigner=_Signer())
    _run(AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps()))
    report = verify_ledger(host.records(), None, _verifier)
    assert report.complete is True


def test_an_uncountersigned_chain_is_complete_without_a_checker() -> None:
    """A record carrying no signature is uncountersigned, which is a state and not an anomaly (§5.2)."""
    host = AuditHost('t#d')
    _run(AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps()))
    assert verify_ledger(host.records()).complete is True


def test_a_countersignature_that_does_not_verify_is_reported() -> None:
    """§11.4: present and failing is `host-signature-invalid`, distinct from uncountersigned."""

    class _Forger(_Signer):
        def sign(self, payload: str) -> str:
            return base64.urlsafe_b64encode(b'not-the-host').rstrip(b'=').decode('ascii')

    host = AuditHost('t#w', _COUNTERSIGNING, countersigner=_Forger())
    _run(AmcpSession(InProcessTransport(host), host.open_session(), DeterministicDeps()))
    report = verify_ledger(host.records(), None, _verifier)
    assert not report.ok
    assert all(issue.kind == 'host-signature-invalid' for issue in report.issues)
