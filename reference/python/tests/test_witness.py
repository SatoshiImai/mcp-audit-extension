"""The witness axis (§5.2): what a record carries, and what the tool does about it (§7.1, §7.2)."""

import base64

import pytest

from auditable_mcp.amcp import AmcpAbortedError, AmcpSession, DeterministicDeps
from auditable_mcp.capability import AuditCapability
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.ledger import witness_payload

_WITNESSING = AuditCapability(witness='host')
_TARGET = {'kind': 'table', 'ref': 'customers'}


class _Signer:
    """A host witness signer. The vectors pin the preimage and the field placement, not the scheme."""

    key_id = 'host-key-2026'

    def sign(self, payload: str) -> str:
        """Return a deterministic stand-in signature over `payload`."""
        return base64.b64encode(b'fake-witness-signature').decode('ascii')


def _verifier(host_key_id: str, signature: str, payload: str) -> bool:
    """Accept only the signature this host's key produces over these exact bytes."""
    return host_key_id == 'host-key-2026' and signature == _Signer().sign(payload)


def _run(session: AmcpSession) -> None:
    """Run one audited action."""
    session.audited('db.read', _TARGET, lambda: None, mutates=False, egress=False)


def test_a_witnessing_host_signs_every_record_it_seals() -> None:
    """§7.1: attempts and outcomes alike, and both are persisted with the pair."""
    host = AuditHost('t#w', _WITNESSING, witness_signer=_Signer())
    _run(AmcpSession(InProcessTransport(host), 'call-1', DeterministicDeps()))
    records = host.records()
    assert records
    assert all(record.host_signature is not None and record.host_key_id == 'host-key-2026' for record in records)


def test_a_host_declaring_none_returns_no_witness() -> None:
    """§7.1: a host declaring `none` MUST NOT return the pair, and cannot hold a signer to do it."""
    host = AuditHost('t#d')
    _run(AmcpSession(InProcessTransport(host), 'call-1', DeterministicDeps()))
    assert all(record.host_signature is None and record.host_key_id is None for record in host.records())


def test_a_host_cannot_declare_a_witness_it_cannot_produce() -> None:
    """A declaration the host cannot honour is refused at construction, not at seal time."""
    with pytest.raises(ValueError, match='requires a WitnessSigner'):
        AuditHost('t#w', _WITNESSING)
    with pytest.raises(ValueError, match='must not hold'):
        AuditHost('t#d', witness_signer=_Signer())


def test_a_tool_that_requires_a_witness_aborts_on_an_unwitnessed_accept() -> None:
    """§7.2: the tool must not act on a record no distinct party confirmed."""
    session = AmcpSession(
        InProcessTransport(AuditHost('t#d')),
        'call-1',
        DeterministicDeps(),
        witness_verifier=_verifier,
        require_witness=True,
    )
    with pytest.raises(AmcpAbortedError) as aborted:
        _run(session)
    assert aborted.value.reason == 'host-unwitnessed'


def test_a_tool_aborts_on_a_witness_signature_that_does_not_verify() -> None:
    """§7.2: a signature that is present and fails is `host-signature-invalid`, not unwitnessed."""

    class _Forger(_Signer):
        def sign(self, payload: str) -> str:
            return base64.b64encode(b'not-the-host').decode('ascii')

    host = AuditHost('t#w', _WITNESSING, witness_signer=_Forger())
    session = AmcpSession(
        InProcessTransport(host), 'call-1', DeterministicDeps(), witness_verifier=_verifier, require_witness=True
    )
    with pytest.raises(AmcpAbortedError) as aborted:
        _run(session)
    assert aborted.value.reason == 'host-signature-invalid'


def test_requiring_a_witness_without_a_verifier_is_refused() -> None:
    """Every action would abort on a host that is signing correctly, so the pairing is enforced."""
    with pytest.raises(ValueError, match='WitnessVerifier'):
        AmcpSession(InProcessTransport(AuditHost('t#d')), 'call-1', DeterministicDeps(), require_witness=True)


def test_the_witness_preimage_is_the_host_assigned_fields_alone() -> None:
    """§7.1: no signature field in the preimage, so there is no self-reference."""
    payload = witness_payload(0, '2026-07-15T00:00:01.000Z', '0' * 64, 'a' * 64)
    assert payload.startswith('{"host_ts":')
    assert 'signature' not in payload
