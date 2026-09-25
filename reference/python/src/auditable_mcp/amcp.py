"""Tool-side Auditable MCP session.

Enforces the audit-before-act discipline:
1. Emit attempt event.
2. Await durable accept from host.
3. Perform internal domain action (not performed if rejected/unavailable).
4. Emit outcome event (success/failed).
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, TypeVar

from auditable_mcp.canonical import hash_canonical
from auditable_mcp.ledger import compute_record_hash, countersignature_payload
from auditable_mcp.schema import validate_attempt_response
from auditable_mcp.transport import AttemptResponse, AuditTransport, AuditTransportError, response_members

logger = logging.getLogger(__name__)

SPEC_VERSION = 'auditable-mcp/0.3'
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


class CountersignatureVerifier(Protocol):
    """Resolves a `host_key_id` and verifies a countersignature over the host-assigned fields and log_id."""

    def __call__(self, host_key_id: str, signature: str, payload: str) -> bool:
        """Return True only if the signature verifies against the key the registry binds (§7.2)."""
        ...


class AmcpSession:
    """Wraps internal operations in the audit-before-act lifecycle.

    L1 and L2 emission are identical; L2 only adds a signer.
    """

    def __init__(
        self,
        transport: AuditTransport,
        session_id: str,
        deps: DeterministicDeps,
        signer: EventSigner | None = None,
        countersignature_verifier: CountersignatureVerifier | None = None,
        require_countersign: bool = False,
        attempt_retries: int = 0,
    ) -> None:
        """Bind the session to a transport, the call's audit session, id/time deps, and optional signer.

        `session_id` is the audit session the host issued for this call (§6.3), carried verbatim in
        every event. A tool that declares `countersign: "host"` (§5.2) requires every accept to carry
        a countersignature it can verify, so `require_countersign` needs a verifier: without one the
        tool would abort every action on a host that is countersigning correctly. `attempt_retries` is
        how many times the identical attempt is sent again after `unavailable` or no answer (§7.1).

        Raises:
            ValueError: `require_countersign` was set without a verifier.
        """
        if require_countersign and countersignature_verifier is None:
            raise ValueError('require_countersign needs a CountersignatureVerifier (§7.2, §11.3)')
        self._transport = transport
        self._session_id = session_id
        self._deps = deps
        self._signer = signer
        self._countersignature_verifier = countersignature_verifier
        self._require_countersign = require_countersign
        self._attempt_retries = attempt_retries

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
            'session_id': self._session_id,
            'action_type': action_type,
            'mutates': mutates,
            'egress': egress,
            'target_resource': target_resource,
        }
        if disclose is not None:
            base['action_context'] = disclose
        if commit is not None:
            base['action_context_hash'] = hash_canonical(commit)
        # Signed once: a retry sends the byte-identical attempt, which keeps its signer_seq (§6, §7.1).
        attempt = self._stamp({**base, 'outcome': 'attempted'})
        response = self._ask(attempt)
        for _ in range(self._attempt_retries):
            if response is not None and response.status != 'unavailable':
                break
            response = self._ask(attempt)
        if response is None or response.status != 'accept':
            # reject, unavailable, or unanswered: do not act; signal aborted (§7.2).
            reason = 'host-rejected' if response is not None and response.status == 'reject' else 'host-unavailable'
            self._abort(base, attempt['id'], reason)
            raise AmcpAbortedError(action_type, target_resource['ref'], reason)
        # §7.2 evaluates in precedence order: the response's status above, then the countersignature
        # that authenticates the host-assigned fields, then the hash computed over them.
        # The reason is sealed into the ledger and compared across implementations, so the order is
        # not incidental.
        if self._require_countersign and response.host_signature is None:
            self._abort(base, attempt['id'], 'host-uncountersigned')
            raise AmcpAbortedError(action_type, target_resource['ref'], 'host-uncountersigned')
        if response.host_signature is not None and self._countersignature_verifier is not None:
            payload = countersignature_payload(
                response.seq, response.host_ts, response.log_id, response.previous_hash, response.record_hash
            )
            if not self._countersignature_verifier(response.host_key_id, response.host_signature, payload):
                self._abort(base, attempt['id'], 'host-signature-invalid')
                raise AmcpAbortedError(action_type, target_resource['ref'], 'host-signature-invalid')
        # Polluted Stop (§7.2): MUST under L2 (signer present) and wherever a countersignature is
        # required, OPTIONAL otherwise. The countersignature binds the host-assigned fields to
        # record_hash and no further; recomputing record_hash over the attempt bytes is what binds it
        # to this attempt, so an accept for another record is refused.
        if self._signer is not None or self._require_countersign:
            expected = compute_record_hash(attempt, response.seq, response.host_ts, response.previous_hash)
            if expected != response.record_hash:
                self._abort(base, attempt['id'], 'hash-mismatch')
                raise AmcpAbortedError(action_type, target_resource['ref'], 'hash-mismatch')
        # `perform` runs at most once, and only after an accept that passed every check above (§6).
        try:
            result = perform()
        except Exception:
            self._emit_outcome({**base, 'id': attempt['id'], 'outcome': 'failed'})
            raise
        # Outside the `try`: an action that was performed is never recorded `failed`, and a lost outcome
        # is a completeness gap the host resolves (§10.8), not the caller's error to retry.
        self._emit_outcome({**base, 'id': attempt['id'], 'outcome': 'success'})
        return result

    def _emit_outcome(self, event: dict) -> None:
        """Send a terminal outcome, logging rather than raising if it cannot be delivered (§6, §10.8)."""
        try:
            self._transport.send_outcome(self._stamp(event))
        except Exception:
            logger.exception('could not deliver the %s outcome of %s; it is lost', event['outcome'], event['id'])

    def _ask(self, attempt: dict) -> AttemptResponse | None:
        """Send the attempt and return the Attempt Response, or None when it went unanswered.

        A transport fault, a protocol error, or an answer that does not validate against the Attempt
        Response schema - a partial countersignature triple among them - is not an Attempt Response,
        and the tool treats it exactly as `unavailable` (§6).
        """
        try:
            response = self._transport.send_attempt(attempt)
        except (AuditTransportError, OSError, TimeoutError):
            return None
        if (
            not isinstance(response, AttemptResponse)
            or validate_attempt_response(response_members(response)) is not None
        ):
            return None
        return response

    def _abort(self, base: dict, event_id: str, reason: str) -> None:
        """Emit an aborted outcome recording why the domain action was not performed."""
        self._transport.send_outcome(self._stamp({**base, 'id': event_id, 'outcome': 'aborted', 'reason': reason}))
