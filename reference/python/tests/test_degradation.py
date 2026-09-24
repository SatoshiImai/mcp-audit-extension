"""The §6.2 postures: what a tool does with a session that was not audit-negotiated."""

import pytest

from auditable_mcp.capability import AuditCapability, negotiate_capability
from auditable_mcp.degradation import MANDATORY, UnnegotiatedSessionError, transport_for
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport

_TOOL = AuditCapability()
_REQUIRES_WITNESS = AuditCapability(witness='host')


def _wire() -> InProcessTransport:
    """A stand-in for the transport to a host that did negotiate."""
    return InProcessTransport(AuditHost('tenant-a'))


def _self_hosted() -> InProcessTransport:
    """A transport over an audit host the tool provides for itself (the degraded posture)."""
    return InProcessTransport(AuditHost('tool-local'))


def test_a_negotiated_session_uses_the_host() -> None:
    """Nothing degrades when the comparison succeeded (§6.1)."""
    wire = _wire()
    assert transport_for(negotiate_capability(_TOOL, _TOOL), wire, _self_hosted()) is wire


def test_an_undeclared_host_degrades_to_the_tools_own() -> None:
    """The common case, and the tool stays usable by it (§6.2)."""
    fallback = _self_hosted()
    assert transport_for(negotiate_capability(None, _TOOL), _wire(), fallback) is fallback


def test_a_mismatched_host_degrades_the_same_way() -> None:
    """A declaration that does not fit leaves the session unnegotiated, like an absent one."""
    older = AuditCapability(spec_version='auditable-mcp/0.1')
    fallback = _self_hosted()
    assert transport_for(negotiate_capability(older, _TOOL), _wire(), fallback) is fallback


def test_the_mandatory_posture_declines_to_serve() -> None:
    """[SEP-2133] permits refusing where an unwitnessed record has no value (§6.2)."""
    with pytest.raises(UnnegotiatedSessionError):
        transport_for(negotiate_capability(None, _TOOL), _wire(), _self_hosted(), MANDATORY)


def test_the_third_posture_is_not_available() -> None:
    """Serving while neither recording nor reporting is not conformant, so it cannot be chosen."""
    with pytest.raises(ValueError, match='fallback'):
        transport_for(negotiate_capability(None, _TOOL), _wire())


def test_a_tool_that_requires_a_witness_cannot_degrade() -> None:
    """Its own host holds no key a registry binds to a host, so every action would abort (§5.2)."""
    with pytest.raises(ValueError, match='MANDATORY'):
        transport_for(negotiate_capability(None, _REQUIRES_WITNESS), _wire(), _self_hosted())
