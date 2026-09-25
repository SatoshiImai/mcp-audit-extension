"""What a tool does with a call that is not audit-negotiated (§6.2).

A tool that speaks this extension has to stay usable by hosts that do not, which is nearly every MCP
host today. For an unnegotiated call it sends no audit message at all - an ordinary host has no way
to answer one, so a tool that sends anyway fails closed against a peer that has done nothing wrong -
and serves `tools/call` exactly as a build without this extension would.

Two postures are admissible. Under **degraded** (the default) the tool serves the call and records
into an audit host it provides for itself: the recording does not stop, the host's countersignature does, and
§5.2 makes that legible in the records. Under **mandatory** the tool declines to serve, which
[SEP-2133] permits for an extension a deployment treats as required.

A third posture - serving the call while recording nothing and reporting nothing about the omission -
is not conformant, so `transport_for` refuses to return a transport for it: taking the degraded
posture requires somewhere to record.
"""

from auditable_mcp.capability import NegotiationResult
from auditable_mcp.transport import AuditTransport

# How a tool spends an audit obligation it cannot discharge against the host (§6.2).
DEGRADED = 'degraded'  # serve the call, and record into an audit host the tool provides for itself
MANDATORY = 'mandatory'  # decline to serve, as [SEP-2133] permits for a mandatory extension


class UnnegotiatedCallError(Exception):
    """The call is not audit-negotiated and the tool's posture is `mandatory` (§6.2)."""

    def __init__(self, negotiation: NegotiationResult) -> None:
        """Carry the negotiation so the integrator can report which axis refused."""
        self.negotiation = negotiation
        super().__init__(f'call is not audit-negotiated ({negotiation.outcome}); posture is mandatory')


def transport_for(
    negotiation: NegotiationResult,
    negotiated: AuditTransport,
    fallback: AuditTransport | None = None,
    posture: str = DEGRADED,
) -> AuditTransport:
    """Return the transport §6.2 permits for this call, or refuse to serve it.

    Args:
        negotiation: The result of comparing the host's declaration against the tool's (§6.1).
        negotiated: The transport to the host, used only when the call is audit-negotiated.
        fallback: A transport over an audit host the tool provides for itself, required by the
            degraded posture.
        posture: What to do when the call is not audit-negotiated. Degraded by default.

    Returns:
        `negotiated` for an audit-negotiated call, otherwise `fallback`.

    Raises:
        UnnegotiatedCallError: The call is not audit-negotiated and the posture is mandatory.
        ValueError: The posture is degraded and no `fallback` was given, or the tool requires a
            countersignature. Serving a call while neither recording the operations nor reporting the
            omission is not conformant (§6.2), and a tool that requires `countersign: "host"` cannot
            degrade: the host it provides for itself holds no key a verifier's registry binds to a
            host (§5.2), so every action would abort `host-uncountersigned` (§7.2).
    """
    if negotiation.negotiated:
        return negotiated
    if posture == MANDATORY:
        raise UnnegotiatedCallError(negotiation)
    if negotiation.tool.countersign == 'host':
        raise ValueError('a tool that requires countersign "host" cannot degrade; use MANDATORY (§5.2, §6.2)')
    if fallback is None:
        raise ValueError('the degraded posture needs a fallback transport to record into (§6.2)')
    return fallback
