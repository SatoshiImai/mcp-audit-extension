import { AuditHost } from '../host/auditHost.js';
import { InProcessTransport } from '../transport/inProcess.js';
import { AmcpSession, deterministicDeps } from '../tool/amcp.js';
import { CustomerDbTool } from '../tool/customerDbTool.js';
import { verifyLedger } from '../verify/verify.js';
import { generateToolKey, KeyRegistry, type ToolKey } from '../l2/keys.js';
import { Ed25519Signer, signEvent } from '../l2/signing.js';
import { BoundaryObserver, reconcile } from '../l2/reconcile.js';
import type { AuditEvent } from '../schema/event.js';
import type { SealedRecord } from '../ledger/ledger.js';

const L2_CAP = {
  level: 'L2' as const,
  attempt: 'request' as const,
  attempt_ack_deadline_ms: 500,
  block_disposition: ['abort' as const],
  outcome_mode: 'batched' as const,
  outcome_batch_window_ms: 200,
};

function line(): void {
  console.log('─'.repeat(74));
}

function printLedger(records: readonly SealedRecord[]): void {
  for (const r of records) {
    const e = r.event;
    console.log(
      `  seq=${r.seq} ${e.action_type.padEnd(11)} ${e.outcome.padEnd(9)} ` +
        `key=${e.key_id ?? '-'}#seq${e.sequence ?? '-'} sig=${(e.signature ?? '').slice(0, 10)}…`,
    );
  }
}

function attemptFor(key: ToolKey, seq: number, ref: string): AuditEvent {
  const base: AuditEvent = {
    id: `00000000-0000-4000-8000-${(seq + 1).toString(16).padStart(12, '0')}`,
    spec_version: 'a-mcp/0.1',
    ts: '2026-07-16T00:00:00.000Z',
    call_id: 'call_adv',
    action_type: 'db.write',
    mutates: true,
    egress: false,
    target_resource: { kind: 'table', ref },
    outcome: 'attempted',
    params_hash: `sha256:${'0'.repeat(64)}`,
  };
  return signEvent(base, key.keyId, seq, key.privateKey);
}

async function main(): Promise<void> {
  line();
  console.log('A-MCP L2 PoC — signature (non-repudiation) + sequence + reconciliation');
  console.log('Blocking is on LIES into the ledger, never on the tool\'s domain action.');
  line();

  // Onboarding: the host registers the tool's public key out-of-band (the trust anchor).
  const key = generateToolKey('customer-db-tool-key');
  const registry = new KeyRegistry();
  registry.register(key.keyId, key.publicKey);

  // [1] Portable escalation (L1 ⊆ L2): the SAME tool code, now with a signer attached.
  console.log('\n[1] Signed happy path — same tool code + a signer ⇒ L2 (portable escalation):');
  const host = new AuditHost('acme#2026-07-16', L2_CAP, registry);
  const signer = new Ed25519Signer(key.keyId, key.privateKey);
  const session = new AmcpSession(new InProcessTransport(host), 'call_abc', deterministicDeps(), signer);
  const tool = new CustomerDbTool(session);
  await tool.getCustomer('c_1');
  await tool.updateEmail('c_1', 'new@acme.example');
  printLedger(host.records());
  const v = verifyLedger(host.records(), host.ledger.digest());
  console.log(`  verify: ${v.ok ? '✅ VERIFIED' : '❌ FAILURE'}  (signatures accepted, chain intact)`);

  // [2] Forgery — sign, then tamper a field. The host refuses the lie; the ledger stays clean.
  console.log('\n[2] Forgery — a signed record altered after signing is rejected:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    const signed = attemptFor(key, 0, 'customers');
    const forged: AuditEvent = { ...signed, target_resource: { kind: 'table', ref: 'salaries' } };
    const res = h.handleAttempt(forged);
    console.log(`  altered target customers→salaries → ${res.status}${res.status !== 'accept' ? ` (${res.reason})` : ''}`);
    console.log(`  ledger records: ${h.records().length} (lie kept out)`);
  }

  // [3] Unsigned under L2 — needs escalation; refused.
  console.log('\n[3] Unsigned under L2 — an L1-style event without a signature is refused:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    const unsigned: AuditEvent = {
      id: '00000000-0000-4000-8000-0000000000aa', spec_version: 'a-mcp/0.1', ts: '2026-07-16T00:00:00.000Z',
      call_id: 'call_adv', action_type: 'db.write', mutates: true, egress: false,
      target_resource: { kind: 'table', ref: 'customers' }, outcome: 'attempted', params_hash: `sha256:${'0'.repeat(64)}`,
    };
    const res = h.handleAttempt(unsigned);
    console.log(`  unsigned attempt → ${res.status}${res.status !== 'accept' ? ` (${res.reason})` : ''}`);
  }

  // [4] Suppression via sequence gap — a skipped tool sequence exposes a hidden event.
  console.log('\n[4] Sequence gap — a suppressed event leaves a hole the host detects:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    h.handleAttempt(attemptFor(key, 0, 'customers'));
    const res = h.handleAttempt(attemptFor(key, 2, 'customers')); // seq 1 suppressed
    console.log(`  emit seq 0 then seq 2 → seq2 ${res.status}; anomalies: ${h.getAnomalies().map((a) => a.kind).join(', ')}`);
  }

  // [5] Suppression by omission — reconciliation vs the boundary catches what signing cannot.
  console.log('\n[5] Reconciliation — an egress the boundary saw but the tool never reported:');
  {
    const h = new AuditHost('acme#adv', L2_CAP, registry);
    const boundary = new BoundaryObserver();
    const stripe = 'https://api.stripe.com/v1/refunds';
    boundary.observeEgress('call_adv', stripe); // gateway saw the egress
    // ...the tool emitted no matching audit event (perfect signatures on everything else
    // cannot help — the lie is the omission).
    const anomalies = reconcile(h.records(), boundary.forCall('call_adv'), 'call_adv');
    for (const a of anomalies) console.log(`  ❌ ${a.kind}: ${a.destination} (${a.detail})`);
  }

  line();
  console.log('L2 = evidentiary strength (non-repudiation + completeness), not action control.');
  console.log('Rejections/flags above are DELIBERATE demonstrations of lie-detection.');
  line();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
