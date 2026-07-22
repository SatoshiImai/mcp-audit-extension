import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { verifyLedger } from '../verify/verify.js';
import { generateToolKey, KeyRegistry, type ToolKey } from '../l2/keys.js';
import { KeySigner, signEvent } from '../l2/signing.js';
import { BoundaryObserver, reconcile } from '../l2/reconcile.js';
import { SqlAnalystTool } from '../tool/sqlAnalystTool.js';
import type { AuditEvent } from '../schema/event.js';
import type { SealedRecord } from '../ledger/ledger.js';

const L2_CAP = {
  spec_version: 'auditable-mcp/0.1.1' as const,
  level: 'L2' as const,
  attempt: 'request' as const,
};

function line(): void {
  console.log('-'.repeat(74));
}

function printLedger(records: readonly SealedRecord[]): void {
  for (const r of records) {
    const e = r.event;
    console.log(
      `  seq=${r.seq} ${e.action_type.padEnd(11)} ${e.outcome.padEnd(9)} ` +
        `key=${e.key_id ?? '-'}#seq${e.signer_seq ?? '-'} sig=${(e.signature ?? '').slice(0, 10)}`,
    );
  }
}

function attemptFor(key: ToolKey, seq: number, ref: string): AuditEvent {
  const base: AuditEvent = {
    id: `00000000-0000-4000-8000-${(seq + 1).toString(16).padStart(12, '0')}`,
    spec_version: 'auditable-mcp/0.1.1',
    ts: '2026-07-16T00:00:00.000Z',
    call_id: 'call_adv',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref },
    outcome: 'attempted',
    action_context_hash: `sha256:${'0'.repeat(64)}`,
  };
  return signEvent(base, key.keyId, seq, key.alg, key.privateKey);
}

async function main(): Promise<void> {
  line();
  console.log('Auditable MCP L2 PoC - signature (non-repudiation) + sequence + reconciliation');
  console.log('Blocking targets forged/invalid records, never the tool\'s domain action.');
  line();

  // Onboarding: the host registers the tool's public key out-of-band (the trust anchor).
  const key = generateToolKey('sql-analyst-key');
  const registry = new KeyRegistry();
  registry.register(key.keyId, key.publicKey, key.alg);

  console.log('\n[1] Signed path - same tool code + a signer => L2 (portable escalation):');
  const host = new AuditHost('acme#2026-07-16', L2_CAP, registry);
  const signer = new KeySigner(key.keyId, key.alg, key.privateKey);
  const session = new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps(), signer);
  const tool = new SqlAnalystTool(session);
  await tool.analyze('What were the high-value customer trends in the Tokyo area last month?');
  printLedger(host.records());
  const v = verifyLedger(host.records(), host.ledger.digest());
  console.log(`  verify: ${v.ok ? 'VERIFIED' : 'FAILURE'}  (signatures accepted, chain intact)`);

  console.log('\n[2] Forgery - a signed record altered after signing is rejected:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    const signed = attemptFor(key, 0, 'notes');
    const forged: AuditEvent = { ...signed, target_resource: { kind: 'table', ref: 'salaries' } };
    const res = h.handleAttempt(forged);
    console.log(`  altered target notes->salaries -> ${res.status}${res.status !== 'accept' ? ` (${res.reason})` : ''}`);
    console.log(`  ledger records: ${h.records().length} (invalid record kept out)`);
  }

  console.log('\n[3] Unsigned under L2 - an L1-style event without a signature is refused:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    const unsigned: AuditEvent = {
      id: '00000000-0000-4000-8000-0000000000aa', spec_version: 'auditable-mcp/0.1.1', ts: '2026-07-16T00:00:00.000Z',
      call_id: 'call_adv', action_type: 'db.write', mutates: true, egress: false,
      target_resource: { kind: 'table', ref: 'notes' }, outcome: 'attempted', action_context_hash: `sha256:${'0'.repeat(64)}`,
    };
    const res = h.handleAttempt(unsigned);
    console.log(`  unsigned attempt -> ${res.status}${res.status !== 'accept' ? ` (${res.reason})` : ''}`);
  }

  console.log('\n[4] Sequence gap - a suppressed event leaves a hole the host detects:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    h.handleAttempt(attemptFor(key, 0, 'notes'));
    const res = h.handleAttempt(attemptFor(key, 2, 'notes')); // seq 1 suppressed
    console.log(`  emit seq 0 then seq 2 -> seq2 ${res.status}; anomalies: ${h.getAnomalies().map((a) => a.kind).join(', ')}`);
  }

  console.log('\n[5] Reconciliation - an egress the boundary saw but the tool never reported:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    const boundary = new BoundaryObserver();
    // The gateway saw an egress, but the tool emitted no matching audit event.
    boundary.observeEgress('call_adv', 'https://external-llm.example/v1/chat');
    const anomalies = reconcile(h.records(), boundary.forCall('call_adv'), 'call_adv');
    for (const a of anomalies) console.log(`  ${a.kind}: ${a.destination} (${a.detail})`);
  }

  line();
  console.log('L2 = evidentiary strength (non-repudiation + completeness), not action control.');
  console.log('The rejections and flags above are intentional; they show detection working.');
  line();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
