'''L1 end-to-end walkthrough: tool-internal self-attestation -> tamper-evident ledger.

Run: ``PYTHONPATH=src python -m a_mcp.demo.demo``. Integrity failures shown are deliberate
demonstrations of detection.
'''

import logging

from a_mcp.amcp import AmcpBlockedError, AmcpSession, DeterministicDeps
from a_mcp.customer_db_tool import CustomerDbTool
from a_mcp.demo.scenario import run_clean_scenario
from a_mcp.host import AuditHost
from a_mcp.in_process import InProcessTransport
from a_mcp.ledger import SealedRecord
from a_mcp.verify import verify_ledger

logger = logging.getLogger('a_mcp.demo')
_RULE = '─' * 72
_ZERO_HASH = f'sha256:{"0" * 64}'


def _print_ledger(records: list[SealedRecord]) -> None:
    '''Log each sealed record in a compact one-line form.'''
    for r in records:
        e = r.event
        target = f'{e["target_resource"]["ref"]}#{e["target_resource"].get("scope_hint", "")}'
        logger.info(
            f'  seq={r.seq} {e["action_type"]:<11} {e["outcome"]:<9} '
            f'mut={int(e["mutates"])} egr={int(e["egress"])} {target} hash={r.record_hash[:12]}…'
        )
        # end for
    # end def


def _report(label: str, records: list[SealedRecord], anchored: str | None = None) -> None:
    '''Verify a ledger and log the result and any issues.'''
    report = verify_ledger(records, anchored)
    status = '✅ VERIFIED (non-tampered + complete)' if report.ok else '❌ INTEGRITY FAILURE'
    logger.info(f'  {label}: {status}  [{report.count} records, digest={report.computed_digest[:12]}…]')
    for issue in report.issues:
        logger.info(f'     ↳ seq={issue.seq} {issue.kind}: {issue.detail}')
        # end for
    # end def


def main() -> None:
    '''Run the five L1 demonstration scenarios.'''
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logger.info(_RULE)
    logger.info('A-MCP L1 PoC (Python) — tool-internal self-attestation -> tamper-evident ledger')
    logger.info(_RULE)

    host = run_clean_scenario()
    anchored = host.ledger.digest()
    logger.info('\n[1] Clean run — sealed ledger:')
    _print_ledger(host.records())
    logger.info('')
    _report('verify', host.records(), anchored)

    logger.info('\n[2] Tamper — flip a sealed field, then re-verify:')
    tampered = run_clean_scenario()
    tampered.records()[1].event['target_resource']['scope_hint'] = 'row:id=c_2'
    _report('verify', tampered.records(), anchored)

    logger.info('\n[3] Loss — drop a sealed record, then re-verify:')
    dropped = run_clean_scenario()
    records = dropped.records()
    del records[2]
    _report('verify', records, anchored)

    logger.info('\n[4] Reject — a replayed attempt id is refused, ledger stays clean:')
    h4 = AuditHost('acme#2026-07-16')
    tool4 = CustomerDbTool(AmcpSession(InProcessTransport(h4), 'call_abc', DeterministicDeps()))
    tool4.get_customer('c_1')
    replay = {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': 'a-mcp/0.1',
        'ts': '2026-07-16T00:00:01.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'customers', 'scope_hint': 'row:id=c_1'},
        'outcome': 'attempted',
        'params_hash': _ZERO_HASH,
    }
    res = h4.handle_attempt(replay)
    logger.info(f'  replay attempt → {res.status} ({res.reason})')
    _report('verify (ledger unpolluted)', h4.records())

    logger.info('\n[5] Fail-closed — Tier1 unavailable, the internal action is not performed:')
    h5 = AuditHost('acme#2026-07-16')
    h5.unavailable = True
    tool5 = CustomerDbTool(AmcpSession(InProcessTransport(h5), 'call_abc', DeterministicDeps()))
    try:
        tool5.update_email('c_1', 'blocked@acme.example')
        logger.info('  ❌ action proceeded despite no durable record (BUG)')
    except AmcpBlockedError as err:
        logger.info(f'  ✅ blocked: {err.action_type} on {err.target_ref} ({err.reason}) — no record, no action')
        # end try

    logger.info(_RULE)
    logger.info('Integrity failures above are DELIBERATE demonstrations of detection.')
    logger.info(_RULE)
    # end def


if __name__ == '__main__':
    main()
    # end if
