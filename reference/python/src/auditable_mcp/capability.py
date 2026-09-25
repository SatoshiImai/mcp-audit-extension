"""Audit capability object and the two axes negotiation compares (§6.1).

Read as a requirement when the host declares it and as a supported capability when the tool declares
it; both directions are exchanged during the MCP initialize phase.

The two axes run in opposite directions. On `level` the tool produces and the host requires, so a
tool offering L2 satisfies an L1 host. On `countersign` (§5.2) the host produces and the tool requires,
so a host offering `host` satisfies a tool that requires `none`. Each party enforces the axis on
which it is the one requiring.

A peer that declared nothing is not a failed negotiation but an absent one, which §6.2 governs
differently: the tool sends no audit message at all and serves the call as an ordinary MCP tool.
"""

from dataclasses import dataclass

SPEC_VERSION = 'auditable-mcp/0.3'


@dataclass(frozen=True)
class AuditCapability:
    """An audit capability: a requirement when host-declared, a supported level when tool-declared.

    spec_version carries the supported Auditable MCP version so a common version is established
    before events (which carry spec_version) are exchanged (§6.1). All four fields are REQUIRED.
    """

    spec_version: str = SPEC_VERSION  # supported version, e.g. auditable-mcp/0.3
    level: str = 'L1'  # 'L1' | 'L2'
    attempt: str = 'request'  # attempt is always a blocking request (fail-closed)
    countersign: str = 'none'  # 'none' | 'host' - the host offers it, the tool requires it (§5.2)


DEFAULT_L1_CAPABILITY = AuditCapability()

# L2 obligations are a superset of L1, so an L2-capable tool satisfies an L1 requirement (a safe
# downgrade), while an L1-only tool does not satisfy an L2 requirement.
_LEVEL_RANK = {'L1': 1, 'L2': 2}

# A host that signs satisfies a tool that requires a signature and one that does not; a host that
# does not sign satisfies only the latter.
_COUNTERSIGN_RANK = {'none': 1, 'host': 2}

# Why a session is or is not audit-negotiated (§6.2). UNDECLARED is not a mismatch: nothing was
# offered to compare, and collapsing the two would brick the tool against ordinary MCP hosts.
NEGOTIATED = 'negotiated'
UNDECLARED = 'undeclared'
MISMATCH = 'mismatch'


@dataclass(frozen=True)
class NegotiationResult:
    """The outcome of a capability exchange, and which axis decided it."""

    tool: AuditCapability
    host: AuditCapability | None
    outcome: str  # NEGOTIATED | UNDECLARED | MISMATCH
    version_match: bool
    level_fit: bool
    countersign_fit: bool

    @property
    def negotiated(self) -> bool:
        """True only for an audit-negotiated session; §6.2 governs every other case."""
        return self.outcome == NEGOTIATED


def level_satisfies(tool: AuditCapability, host: AuditCapability) -> bool:
    """Return True if the tool offers at least the level the host requires (§6.1)."""
    return _LEVEL_RANK.get(tool.level, 0) >= _LEVEL_RANK.get(host.level, 0)


def countersign_satisfies(host: AuditCapability, tool: AuditCapability) -> bool:
    """Return True if the host provides at least the countersign the tool requires (§5.2, §6.1)."""
    return _COUNTERSIGN_RANK.get(host.countersign, 0) >= _COUNTERSIGN_RANK.get(tool.countersign, 0)


def negotiate_capability(host: AuditCapability | None, tool: AuditCapability) -> NegotiationResult:
    """Compare a host and a tool declaration (§6.1).

    A 0.x draft has no on-the-wire compatibility window, so a fit requires an exact spec_version
    match as well as both axes; the per-axis flags surface which one failed. Truthfulness is not
    verified here; runtime validation (§7) enforces the required level.

    Args:
        host: The capability the host declared, or None if it declared no auditable-mcp extension.
        tool: The capability the tool declares.

    Returns:
        A result carrying both declarations, the outcome, and the per-axis fit.
    """
    if host is None:
        return NegotiationResult(
            tool=tool, host=None, outcome=UNDECLARED, version_match=False, level_fit=False, countersign_fit=False
        )
    version_match = tool.spec_version == host.spec_version
    level_fit = level_satisfies(tool, host)
    countersign_fit = countersign_satisfies(host, tool)
    fits = version_match and level_fit and countersign_fit
    return NegotiationResult(
        tool=tool,
        host=host,
        outcome=NEGOTIATED if fits else MISMATCH,
        version_match=version_match,
        level_fit=level_fit,
        countersign_fit=countersign_fit,
    )
