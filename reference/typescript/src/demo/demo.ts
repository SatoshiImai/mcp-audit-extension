import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, AmcpBlockedError, deterministicDeps } from '../tool/amcp.js';
import { SqlAnalystTool } from '../tool/sqlAnalystTool.js';
import { verifyLedger } from '../verify/verify.js';
import { runCleanScenario } from './scenario.js';
import type { SealedRecord } from '../ledger/ledger.js';

function line(): void {
  console.log('─'.repeat(72));
}

function printLedger(records: readonly SealedRecord[]): void {
  for (const r of records) {
    const e = r.event;
    console.log(
      `  seq=${r.seq} ${e.action_type.padEnd(11)} ${e.outcome.padEnd(9)} ` +
        `mut=${e.mutates ? 1 : 0} egr=${e.egress ? 1 : 0} ${e.target_resource.ref}#${e.target_resource.scope_hint ?? ''} ` +
        `hash=${r.record_hash.slice(0, 12)}…`,
    );
  }
}

function printReport(label: string, records: readonly SealedRecord[], anchored?: string): boolean {
  const report = verifyLedger(records, anchored);
  const status = report.ok ? '✅ VERIFIED (non-tampered + complete)' : '❌ INTEGRITY FAILURE';
  console.log(`  ${label}: ${status}  [${report.count} records, digest=${report.computedDigest.slice(0, 12)}…]`);
  for (const issue of report.issues) {
    console.log(`     ↳ seq=${issue.seq} ${issue.kind}: ${issue.detail}`);
  }
  return report.ok;
}

async function main(): Promise<void> {
  line();
  console.log('Auditable MCP L1 PoC — tool-internal self-attestation → tamper-evident ledger');
  line();

  // 1. Clean run: a first-party tool self-attests its internal db operations.
  const host = await runCleanScenario();
  const anchored = host.ledger.digest(); // Tier3 anchor taken once, out-of-band.
  console.log('\n[1] Clean run — sealed ledger (attempt + outcome per internal op):');
  printLedger(host.records());
  console.log('      db.query: mut=0 egr=1 — a read-only SELECT still egresses to the DB.');
  console.log('      Tables touched are disclosed; the exact SQL is sealed, not logged raw.');
  console.log('');
  printReport('verify', host.records(), anchored);

  // 2. Tamper: mutate a sealed field. The chain recomputation catches it.
  console.log('\n[2] Tamper — flip a sealed field, then re-verify:');
  const tampered = await runCleanScenario();
  const rec = tampered.ledger.unsafeMutableRecords()[1]; // the db.query record
  if (rec) rec.event.target_resource.ref = 'evil-db'; // forge the target
  printReport('verify', tampered.records(), anchored);

  // 3. Loss: drop a sealed record. The sequence gap is detected.
  console.log('\n[3] Loss — drop a sealed record, then re-verify:');
  const dropped = await runCleanScenario();
  dropped.ledger.unsafeMutableRecords().splice(2, 1); // remove one record
  printReport('verify', dropped.records(), anchored);

  // 4. A replayed attempt id is rejected and never sealed.
  console.log('\n[4] Reject — a replayed (forged) attempt id is refused, ledger stays clean:');
  const h4 = new AuditHost('acme#2026-07-15');
  const t4 = new InProcessTransport(h4);
  const s4 = new AmcpSession(t4, 'call_abc', deterministicDeps());
  const tool4 = new SqlAnalystTool(s4);
  await tool4.analyze('What were the high-value customer trends in the Tokyo area last month?');
  const replay = {
    id: '00000000-0000-4000-8000-000000000001', // reuse the first attempt id
    spec_version: 'auditable-mcp/0.1',
    ts: new Date(1001000).toISOString(),
    call_id: 'call_abc',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref: 'analysis_results' },
    outcome: 'attempted',
  };
  const resp = h4.handleAttempt(replay);
  console.log(`  replay attempt → ${resp.status}${resp.status !== 'accept' ? ` (${resp.reason})` : ''}`);
  console.log(`  host anomalies: ${h4.getAnomalies().map((a) => a.kind).join(', ') || '(none)'}`);
  printReport('verify (ledger unpolluted)', h4.records());

  // 5. Fail-closed: infra unavailable ⇒ the tool must not perform the action.
  console.log('\n[5] Fail-closed — Tier1 unavailable, the internal action is not performed:');
  const h5 = new AuditHost('acme#2026-07-15');
  h5.unavailable = true;
  const t5 = new InProcessTransport(h5);
  const s5 = new AmcpSession(t5, 'call_abc', deterministicDeps());
  const tool5 = new SqlAnalystTool(s5);
  try {
    await tool5.analyze('What were the high-value customer trends in the Tokyo area last month?');
    console.log('  ❌ action proceeded despite no durable record (BUG)');
  } catch (err) {
    if (err instanceof AmcpBlockedError) {
      console.log(`  ✅ blocked: ${err.action_type} on ${err.target_ref} (${err.reason}) — no record, no action`);
    } else {
      throw err;
    }
  }

  line();
  console.log('The integrity failures above are intentional; they show detection working.');
  line();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
