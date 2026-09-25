"""Capability negotiation on both axes (§6.1) and the absent declaration §6.2 governs."""

from auditable_mcp.capability import MISMATCH, NEGOTIATED, UNDECLARED, AuditCapability, negotiate_capability
from auditable_mcp.host import AuditHost

_TOOL_L1 = AuditCapability(level='L1')
_TOOL_L2 = AuditCapability(level='L2')
_L2_REQUIRED = AuditCapability(level='L2')
_COUNTERSIGNING = AuditCapability(countersign='host')


def test_l1_host_is_satisfied_by_an_l1_tool() -> None:
    """The ordinary case: the tool offers what the host requires."""
    result = AuditHost('t#d').negotiate(_TOOL_L1)
    assert result.negotiated is True
    assert result.outcome == NEGOTIATED


def test_l1_host_is_satisfied_by_an_l2_tool() -> None:
    """A safe downgrade: L2 obligations are a superset of L1's."""
    assert AuditHost('t#d').negotiate(_TOOL_L2).negotiated is True


def test_l2_host_is_not_satisfied_by_an_l1_tool() -> None:
    """The orchestrator decides what to do; until a comparison succeeds, §6.2 governs the tool."""
    result = AuditHost('t#l2', _L2_REQUIRED).negotiate(_TOOL_L1)
    assert result.negotiated is False
    assert result.outcome == MISMATCH
    assert result.level_fit is False


def test_l2_host_is_satisfied_by_an_l2_tool() -> None:
    """The level axis fits exactly."""
    assert AuditHost('t#l2', _L2_REQUIRED).negotiate(_TOOL_L2).negotiated is True


def test_a_spec_version_mismatch_is_unsatisfiable() -> None:
    """A 0.x draft has no compatibility window: the versions match or nothing is negotiated (§6.1)."""
    older = AuditCapability(spec_version='auditable-mcp/0.1')
    result = AuditHost('t#d').negotiate(older)
    assert result.negotiated is False
    assert result.version_match is False


def test_a_signing_host_satisfies_a_tool_that_requires_a_countersign() -> None:
    """The countersign axis runs the other way: the host offers, the tool requires (§5.2)."""
    assert negotiate_capability(_COUNTERSIGNING, _COUNTERSIGNING).negotiated is True


def test_a_non_signing_host_cannot_satisfy_a_tool_that_requires_a_countersign() -> None:
    """A host declaring `none` cannot sign, and that is knowable at initialize (§6.1)."""
    result = negotiate_capability(_TOOL_L1, _COUNTERSIGNING)
    assert result.outcome == MISMATCH
    assert result.countersign_fit is False
    assert result.level_fit is True


def test_the_axes_run_in_opposite_directions() -> None:
    """A tool surplus is safe on `level`; a host surplus is safe on `countersign`."""
    assert negotiate_capability(_TOOL_L1, _TOOL_L2).negotiated is True
    assert negotiate_capability(_L2_REQUIRED, _TOOL_L1).negotiated is False
    assert negotiate_capability(_COUNTERSIGNING, _TOOL_L1).negotiated is True
    assert negotiate_capability(_TOOL_L1, _COUNTERSIGNING).negotiated is False


def test_a_host_that_declared_nothing_is_not_a_mismatch() -> None:
    """§6.2: an absent declaration is the ordinary MCP host, and the tool must stay usable by it."""
    result = negotiate_capability(None, _TOOL_L1)
    assert result.outcome == UNDECLARED
    assert result.negotiated is False
    assert result.host is None
