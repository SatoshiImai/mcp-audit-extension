'''Tool-side A-MCP library: the audit-before-act discipline.

Emit ``attempt``, await a durable accept, only THEN perform the internal domain action, then
emit the outcome. If the record is rejected (a lie) or unavailable (infra), the action is not
performed -- fail-closed on record completeness, not on action authorization (design §6.1).
'''

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, TypeVar

from a_mcp.action_type import resolve_effect
from a_mcp.canonical import hash_params
from a_mcp.transport import AuditTransport

SPEC_VERSION = 'a-mcp/0.1'
_BASE_EPOCH_SECONDS = 1000

T = TypeVar('T')


class EventSigner(Protocol):
    '''Signs an event, stamping key_id, sequence, and signature (Level 2).'''

    def sign(self, event: dict) -> dict:
        '''Return the signed event.'''
        ...
        # end def
    # end class


class AmcpBlockedError(Exception):
    '''Raised when an internal action is blocked because no valid record was obtained.'''

    def __init__(self, action_type: str, target_ref: str, reason: str) -> None:
        '''Capture the blocked action for the CallTool result.'''
        super().__init__(f'a-mcp blocked {action_type} on {target_ref}: {reason}')
        self.action_type = action_type
        self.target_ref = target_ref
        self.reason = reason
        # end def
    # end class


class DeterministicDeps:
    '''Deterministic id and timestamp source for reproducible runs (no wall clock / uuid4).'''

    def __init__(self) -> None:
        '''Start the counter at zero.'''
        self._n = 0
        # end def

    def new_id(self) -> str:
        '''Return the next deterministic uuid-shaped id.'''
        self._n += 1
        return f'00000000-0000-4000-8000-{self._n:012x}'
        # end def

    def now(self) -> str:
        '''Return a deterministic ISO-8601 timestamp string.'''
        moment = datetime.fromtimestamp(_BASE_EPOCH_SECONDS + self._n, tz=UTC)
        return moment.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        # end def
    # end class


class AmcpSession:
    '''Wraps internal domain operations in the audit-before-act discipline.

    A signer's presence is the ONLY difference between L1 and L2 emission; the discipline is
    identical (design INV-1, portable escalation).
    '''

    def __init__(
        self, transport: AuditTransport, call_id: str, deps: DeterministicDeps, signer: EventSigner | None = None
    ) -> None:
        '''Bind the session to a transport, a parent call id, id/time deps, and optional signer.'''
        self._transport = transport
        self._call_id = call_id
        self._deps = deps
        self._signer = signer
        # end def

    def _stamp(self, event: dict) -> dict:
        '''Sign the event if a signer is present (L2), else return it unchanged (L1).'''
        return self._signer.sign(event) if self._signer is not None else event
        # end def

    def audited(
        self,
        action_type: str,
        target_resource: dict,
        params: object,
        perform: Callable[[], T],
        mutates: bool | None = None,
        egress: bool | None = None,
    ) -> T:
        '''Emit attempt, await accept, perform the action, then emit the outcome.'''
        resolved_mutates, resolved_egress = resolve_effect(action_type, mutates, egress)
        base = {
            'id': self._deps.new_id(),
            'spec_version': SPEC_VERSION,
            'ts': self._deps.now(),
            'call_id': self._call_id,
            'action_type': action_type,
            'mutates': resolved_mutates,
            'egress': resolved_egress,
            'target_resource': target_resource,
            'params_hash': hash_params(params),
        }
        attempt = self._stamp({**base, 'outcome': 'attempted'})
        response = self._transport.send_attempt(attempt)
        if response.status != 'accept':
            # No valid record -> do NOT perform the action.
            raise AmcpBlockedError(action_type, target_resource['ref'], response.reason or 'blocked')
            # end if
        try:
            result = perform()
            self._transport.send_outcome(self._stamp({**base, 'id': attempt['id'], 'outcome': 'success'}))
            return result
        except Exception:
            # Record the failed outcome, then re-raise (never swallow).
            self._transport.send_outcome(self._stamp({**base, 'id': attempt['id'], 'outcome': 'failed'}))
            raise
            # end try
        # end def
    # end class
