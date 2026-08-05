"""Tool-side Auditable MCP session.

Enforces the audit-before-act discipline:
1. Emit attempt event.
2. Await durable accept from host.
3. Perform internal domain action (not performed if rejected/unavailable).
4. Emit outcome event (success/failed).
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, TypeVar

from auditable_mcp.canonical import hash_canonical
from auditable_mcp.ledger import compute_record_hash
from auditable_mcp.transport import AuditTransport

SPEC_VERSION = 'auditable-mcp/0.2'
_BASE_EPOCH_SECONDS = 1000

T = TypeVar('T')


class EventSigner(Protocol):
    """Signs an event, stamping key_id, signer_seq, and signature (Level 2)."""

    def sign(self, event: dict) -> dict:
        """Return the signed event."""
        ...


class AmcpAbortedError(Exception):
    """Tool-side fail-closed halt: the domain action was not performed (outcome=aborted).

    Named for the tool's own abort, not host "blocking" - the host never prevents a domain
    action (§2).
    """

    def __init__(self, action_type: str, target_ref: str, reason: str) -> None:
        """Capture the aborted action for the tools/call result."""
        super().__init__(f'auditable-mcp aborted {action_type} on {target_ref}: {reason}')
        self.action_type = action_type
        self.target_ref = target_ref
        self.reason = reason


class DeterministicDeps:
    """Deterministic id and timestamp source for reproducible runs (no wall clock / uuid4)."""

    def __init__(self) -> None:
        """Start the counter at zero."""
        self._n = 0

    def new_id(self) -> str:
        """Return the next deterministic uuid-shaped id."""
        self._n += 1
        return f'00000000-0000-4000-8000-{self._n:012x}'

    def now(self) -> str:
        """Return a deterministic ISO-8601 timestamp string."""
        moment = datetime.fromtimestamp(_BASE_EPOCH_SECONDS + self._n, tz=UTC)
        return moment.strftime('%Y-%m-%dT%H:%M:%S.000Z')


class AmcpSession:
    """Wraps internal operations in the audit-before-act lifecycle.

    L1 and L2 emission are identical; L2 only adds a signer.
    """

    def __init__(
        self, transport: AuditTransport, call_id: str, deps: DeterministicDeps, signer: EventSigner | None = None
    ) -> None:
        """Bind the session to a transport, a parent call id, id/time deps, and optional signer."""
        self._transport = transport
        self._call_id = call_id
        self._deps = deps
        self._signer = signer

    def _stamp(self, event: dict) -> dict:
        """Sign the event if a signer is present (L2), else return it unchanged (L1)."""
        return self._signer.sign(event) if self._signer is not None else event

    def audited(
        self,
        action_type: str,
        target_resource: dict,
        perform: Callable[[], T],
        *,
        mutates: bool,
        egress: bool,
        disclose: dict | None = None,
        commit: object | None = None,
    ) -> T:
        """Emit attempt, await accept, perform the action, then emit the outcome.

        The effect axis (mutates, egress) is declared explicitly per operation. Confidentiality
        is the tool's choice (§4.3): ``disclose`` records cleartext params, ``commit`` records
        a hash of the exact input; either, both, or neither may be given.
        """
        base = {
            'id': self._deps.new_id(),
            'spec_version': SPEC_VERSION,
            'ts': self._deps.now(),
            'call_id': self._call_id,
            'action_type': action_type,
            'mutates': mutates,
            'egress': egress,
            'target_resource': target_resource,
        }
        if disclose is not None:
            base['action_context'] = disclose
        if commit is not None:
            base['action_context_hash'] = hash_canonical(commit)
        attempt = self._stamp({**base, 'outcome': 'attempted'})
        response = self._transport.send_attempt(attempt)
        if response.status != 'accept':
            # reject (invalid/forged) or unavailable (not persisted): do not act; signal aborted (§11.3).
            reason = 'host-rejected' if response.status == 'reject' else 'host-unavailable'
            self._abort(base, attempt['id'], reason)
            raise AmcpAbortedError(action_type, target_resource['ref'], reason)
        # Polluted Stop (§7.2): MUST under L2 (signer present), OPTIONAL under L1. Recompute
        # record_hash over the attempt bytes; mismatch means the host sealed a different record.
        if self._signer is not None:
            expected = compute_record_hash(attempt, response.seq, response.host_ts, response.previous_hash)
            if expected != response.record_hash:
                self._abort(base, attempt['id'], 'hash-mismatch')
                raise AmcpAbortedError(action_type, target_resource['ref'], 'hash-mismatch')
        try:
            result = perform()
            self._transport.send_outcome(self._stamp({**base, 'id': attempt['id'], 'outcome': 'success'}))
            return result
        except Exception:
            # Seal the failed outcome, then re-raise.
            self._transport.send_outcome(self._stamp({**base, 'id': attempt['id'], 'outcome': 'failed'}))
            raise

    def _abort(self, base: dict, event_id: str, reason: str) -> None:
        """Emit an aborted outcome recording why the domain action was not performed."""
        self._transport.send_outcome(self._stamp({**base, 'id': event_id, 'outcome': 'aborted', 'reason': reason}))
