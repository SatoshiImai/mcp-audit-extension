"""Audit capability object.

Read as a requirement when the host declares it and as a supported capability when the tool
declares it; both directions are exchanged during the MCP initialize phase (§6.1).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AuditCapability:
    """An audit capability: a requirement when host-declared, a supported level when tool-declared."""

    level: str = 'L1'  # 'L1' | 'L2'
    attempt: str = 'request'  # attempt is always a blocking request (fail-closed)


DEFAULT_L1_CAPABILITY = AuditCapability()

# L2 obligations are a superset of L1, so an L2-capable tool satisfies an L1 requirement (a safe
# downgrade), while an L1-only tool does not satisfy an L2 requirement.
_LEVEL_RANK = {'L1': 1, 'L2': 2}


@dataclass(frozen=True)
class NegotiationResult:
    """Outcome of a capability exchange: the host requirement plus whether the offer meets it."""

    required: AuditCapability
    satisfied: bool


def capability_satisfies(offered: AuditCapability, required: AuditCapability) -> bool:
    """Return True if `offered` supports at least the `required` level.

    Truthfulness is not verified here; runtime validation (§7) enforces the required level.

    Args:
        offered: The capability the tool declares it supports.
        required: The capability the host requires.

    Returns:
        True if the offered level is at least the required level.
    """
    return _LEVEL_RANK.get(offered.level, 0) >= _LEVEL_RANK.get(required.level, 0)


def negotiate_capability(required: AuditCapability, offered: AuditCapability) -> NegotiationResult:
    """Compare a tool's offered capability against a host requirement (§6.1).

    Args:
        required: The capability the host requires.
        offered: The capability the tool declares it supports.

    Returns:
        A NegotiationResult carrying the host requirement and whether the offer satisfies it.
    """
    return NegotiationResult(required=required, satisfied=capability_satisfies(offered, required))
