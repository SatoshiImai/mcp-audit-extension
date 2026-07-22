"""Tests for bidirectional capability negotiation (§6.1).

The tool offers a supported capability and the host returns its requirement plus whether the
offer satisfies it. Mismatch handling is left to the orchestrator; the host never blocks the
exchange itself.
"""

from dataclasses import replace

from auditable_mcp.capability import DEFAULT_L1_CAPABILITY
from auditable_mcp.host import AuditHost

_L2_REQUIRED = replace(DEFAULT_L1_CAPABILITY, level='L2')
_TOOL_L1 = replace(DEFAULT_L1_CAPABILITY, level='L1')
_TOOL_L2 = replace(DEFAULT_L1_CAPABILITY, level='L2')


def test_l1_host_satisfied_by_l1_tool() -> None:
    """An L1-requiring host is satisfied by an L1 tool."""
    result = AuditHost('t#d').negotiate(_TOOL_L1)
    assert result.satisfied is True
    assert result.required.level == 'L1'


def test_l1_host_satisfied_by_l2_tool_downgrade() -> None:
    """An L1-requiring host is satisfied by an L2 tool (safe downgrade; L2 obligations superset L1)."""
    assert AuditHost('t#d').negotiate(_TOOL_L2).satisfied is True


def test_l2_host_not_satisfied_by_l1_tool() -> None:
    """An L2-requiring host is not satisfied by an L1 tool (the orchestrator decides)."""
    result = AuditHost('t#l2', _L2_REQUIRED).negotiate(_TOOL_L1)
    assert result.satisfied is False
    assert result.required.level == 'L2'


def test_l2_host_satisfied_by_l2_tool() -> None:
    """An L2-requiring host is satisfied by an L2 tool."""
    assert AuditHost('t#l2', _L2_REQUIRED).negotiate(_TOOL_L2).satisfied is True


def test_spec_version_mismatch_is_unsatisfiable() -> None:
    """A spec_version mismatch is unsatisfiable even at the same level (§6.1)."""
    older_tool = replace(DEFAULT_L1_CAPABILITY, spec_version='auditable-mcp/0.1')
    assert AuditHost('t#d').negotiate(older_tool).satisfied is False
