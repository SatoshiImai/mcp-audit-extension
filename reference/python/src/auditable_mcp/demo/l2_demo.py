"""L2 walkthrough: signature (non-repudiation) + sequence + reconciliation.

Blocking is on LIES into the ledger, never on the tool's domain action.
Run: ``PYTHONPATH=src python -m auditable_mcp.demo.l2_demo``.
"""

import logging

from auditable_mcp.amcp import AmcpSession, DeterministicDeps
from auditable_mcp.capability import AuditCapability
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.l2.keys import KeyRegistry, ToolKey, generate_tool_key
from auditable_mcp.l2.reconcile import BoundaryObserver, reconcile
from auditable_mcp.l2.signing import Ed25519Signer, sign_event
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.research_tool import ResearchTool
from auditable_mcp.verify import verify_ledger

logger = logging.getLogger('auditable_mcp.demo')
_RULE = '─' * 74
_ZERO_HASH = f'sha256:{"0" * 64}'
L2_CAP = AuditCapability(level='L2')


def _print_ledger(records: list[SealedRecord]) -> None:
    """Log each sealed record showing the L2 key/sequence/signature fields."""
    for r in records:
        e = r.event
        signature = (e.get('signature') or '')[:10]
        logger.info(
            f'  seq={r.seq} {e["action_type"]:<11} {e["outcome"]:<9} '
            f'key={e.get("key_id", "-")}#seq{e.get("sequence", "-")} sig={signature}…'
        )


def _attempt_for(key: ToolKey, seq: int, ref: str) -> dict:
    """Build and sign an attempt event with an explicit sequence."""
    base = {
        'id': f'00000000-0000-4000-8000-{seq + 1:012x}',
        'spec_version': 'auditable-mcp/0.1',
        'ts': '2026-07-16T00:00:00.000Z',
        'call_id': 'call_adv',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': ref},
        'outcome': 'attempted',
        'params_hash': _ZERO_HASH,
    }
    return sign_event(base, key.key_id, seq, key.private_key)


def main() -> None:
    """Run the five L2 demonstration scenarios."""
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logger.info(_RULE)
    logger.info('Auditable MCP L2 PoC (Python) — signature (non-repudiation) + sequence + reconciliation')
    logger.info("Blocking is on LIES into the ledger, never on the tool's domain action.")
    logger.info(_RULE)

    # Onboarding: register the tool's public key out-of-band.
    key = generate_tool_key('research-tool-key')
    registry = KeyRegistry()
    registry.register(key.key_id, key.public_key)

    logger.info('\n[1] Signed happy path — same tool code + a signer => L2 (portable escalation):')
    host = AuditHost('acme#2026-07-16', L2_CAP, registry)
    signer = Ed25519Signer(key.key_id, key.private_key)
    session = AmcpSession(InProcessTransport(host), 'call_abc', DeterministicDeps(), signer)
    tool = ResearchTool(session)
    tool.search('acme corp merger due diligence')
    tool.save_note('acme', 'merger rumour confirmed by two sources')
    _print_ledger(host.records())
    report = verify_ledger(host.records(), host.ledger.digest())
    verdict = '✅ VERIFIED' if report.ok else '❌ FAILURE'
    logger.info(f'  verify: {verdict}  (signatures accepted, chain intact)')

    logger.info('\n[2] Forgery — a signed record altered after signing is rejected:')
    h2 = AuditHost('acme#adv', L2_CAP, registry)
    forged = {**_attempt_for(key, 0, 'notes'), 'target_resource': {'kind': 'table', 'ref': 'salaries'}}
    res = h2.handle_attempt(forged)
    logger.info(f'  altered target notes->salaries → {res.status} ({res.reason})')
    logger.info(f'  ledger records: {len(h2.records())} (lie kept out)')

    logger.info('\n[3] Unsigned under L2 — an L1-style event without a signature is refused:')
    h3 = AuditHost('acme#adv', L2_CAP, registry)
    unsigned = {
        'id': '00000000-0000-4000-8000-0000000000aa',
        'spec_version': 'auditable-mcp/0.1',
        'ts': '2026-07-16T00:00:00.000Z',
        'call_id': 'call_adv',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'notes'},
        'outcome': 'attempted',
        'params_hash': _ZERO_HASH,
    }
    res = h3.handle_attempt(unsigned)
    logger.info(f'  unsigned attempt → {res.status} ({res.reason})')

    logger.info('\n[4] Sequence gap — a suppressed event leaves a hole the host detects:')
    h4 = AuditHost('acme#adv', L2_CAP, registry)
    h4.handle_attempt(_attempt_for(key, 0, 'notes'))
    res = h4.handle_attempt(_attempt_for(key, 2, 'notes'))
    kinds = ', '.join(a.kind for a in h4.anomalies())
    logger.info(f'  emit seq 0 then seq 2 → seq2 {res.status}; anomalies: {kinds}')

    logger.info('\n[5] Reconciliation — an egress the boundary saw but the tool never reported:')
    h5 = AuditHost('acme#adv', L2_CAP, registry)
    boundary = BoundaryObserver()
    # The gateway saw the search egress, but the tool emitted no matching audit event.
    boundary.observe_egress('call_adv', 'https://api.search.example/v1/search')
    for anomaly in reconcile(h5.records(), boundary.for_call('call_adv'), 'call_adv'):
        logger.info(f'  ❌ {anomaly.kind}: {anomaly.destination} ({anomaly.detail})')

    logger.info(_RULE)
    logger.info('L2 = evidentiary strength (non-repudiation + completeness), not action control.')
    logger.info(_RULE)


if __name__ == '__main__':
    main()
