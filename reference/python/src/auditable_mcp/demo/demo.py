"""L1 end-to-end walkthrough: tool-internal self-attestation -> tamper-evident ledger.

Run: ``PYTHONPATH=src python -m auditable_mcp.demo.demo``. Integrity failures shown are deliberate
demonstrations of detection.
"""

import logging

from auditable_mcp.amcp import AmcpAbortedError, AmcpSession, DeterministicDeps
from auditable_mcp.demo.scenario import run_clean_scenario
from auditable_mcp.host import AuditHost
from auditable_mcp.in_process import InProcessTransport
from auditable_mcp.ledger import SealedRecord
from auditable_mcp.sql_analyst_tool import SqlAnalystTool
from auditable_mcp.verify import verify_ledger

logger = logging.getLogger('auditable_mcp.demo')
_RULE = '-' * 72


def _print_ledger(records: list[SealedRecord]) -> None:
    """Log each sealed record in a compact one-line form."""
    for r in records:
        e = r.event
        target = f'{e["target_resource"]["ref"]}#{e["target_resource"].get("scope_hint", "")}'
        logger.info(
            f'  seq={r.seq} {e["action_type"]:<11} {e["outcome"]:<9} '
            f'mut={int(e["mutates"])} egr={int(e["egress"])} {target} hash={r.record_hash[:12]}'
        )


def _report(label: str, records: list[SealedRecord], anchored: str | None = None) -> None:
    """Verify a ledger and log the result and any issues."""
    report = verify_ledger(records, anchored)
    status = 'VERIFIED (non-tampered + complete)' if report.ok else 'INTEGRITY FAILURE'
    logger.info(f'  {label}: {status}  [{report.count} records, digest={report.computed_digest[:12]}]')
    for issue in report.issues:
        logger.info(f'     - seq={issue.seq} {issue.kind}: {issue.detail}')


def main() -> None:
    """Run the five L1 demonstration scenarios."""
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logger.info(_RULE)
    logger.info('Auditable MCP L1 PoC (Python) - tool-internal self-attestation -> tamper-evident ledger')
    logger.info(_RULE)

    host = run_clean_scenario()
    anchored = host.ledger.digest()
    logger.info('\n[1] Clean run - sealed ledger (attempt + outcome per internal op):')
    _print_ledger(host.records())
    logger.info('      ext.geocode: mut=0 egr=1 - the external lookup egresses; the internal db.query does not.')
    logger.info('      Tables touched are disclosed; the exact SQL is sealed, not logged raw.')
    logger.info('')
    _report('verify', host.records(), anchored)

    logger.info('\n[2] Tamper - flip a sealed field, then re-verify:')
    tampered = run_clean_scenario()
    tampered.records()[1].event['target_resource']['ref'] = 'evil-db'
    _report('verify', tampered.records(), anchored)

    logger.info('\n[3] Loss - drop a sealed record, then re-verify:')
    dropped = run_clean_scenario()
    records = dropped.records()
    del records[2]
    _report('verify', records, anchored)

    logger.info('\n[4] Reject - a replayed (forged) attempt id is refused, ledger stays clean:')
    h4 = AuditHost('acme#2026-07-15')
    tool4 = SqlAnalystTool(AmcpSession(InProcessTransport(h4), 'call_abc', DeterministicDeps()))
    tool4.analyze('What were the high-value customer trends in the Tokyo area last month?')
    replay = {
        'id': '00000000-0000-4000-8000-000000000001',
        'spec_version': 'auditable-mcp/0.3',
        'ts': '1970-01-01T00:16:41.000Z',
        'call_id': 'call_abc',
        'action_type': 'db.write',
        'mutates': True,
        'egress': False,
        'target_resource': {'kind': 'table', 'ref': 'analysis_results'},
        'outcome': 'attempted',
    }
    res = h4.handle_attempt(replay)
    logger.info(f'  replay attempt -> {res.status} ({res.reason})')
    logger.info(f'  host anomalies: {", ".join(a.kind for a in h4.anomalies()) or "(none)"}')
    _report('verify (ledger unpolluted)', h4.records())

    logger.info('\n[5] Fail-closed - host unavailable, the internal action is not performed:')
    h5 = AuditHost('acme#2026-07-15')
    h5.unavailable = True
    tool5 = SqlAnalystTool(AmcpSession(InProcessTransport(h5), 'call_abc', DeterministicDeps()))
    try:
        tool5.analyze('What were the high-value customer trends in the Tokyo area last month?')
        logger.info('  action proceeded despite no durable record (BUG)')
    except AmcpAbortedError as err:
        logger.info(f'  aborted: {err.action_type} on {err.target_ref} ({err.reason}) - no record, no action')

    logger.info(_RULE)
    logger.info('The integrity failures above are intentional; they show detection working.')
    logger.info(_RULE)


if __name__ == '__main__':
    main()
