import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SPEC_VECTORS_DIR } from '../paths.js';
import { canonicalize, sha256Hex } from '../ledger/canonical.js';
import { computeRecordHash, GENESIS_HASH } from '../ledger/ledger.js';
import { runCleanScenario } from '../demo/scenario.js';
import type { AuditEvent } from '../schema/event.js';
import { CANONICALIZATION_CASES, ERROR_CASES, EVENT_CASES, SIGNED_CHAIN_EVENTS } from './fixtures.js';

// Generate the committed golden vectors. Any independent implementation must reproduce
// these byte-for-byte: canonical serialization, per-event hashes, and a full sealed chain
// (seq + previous_hash + record_hash + anchored digest). This is the Auditable MCP analogue of
// SEP-3004's conformance test vectors.

interface CanonicalizationVector {
  name: string;
  value: unknown;
  canonical: string;
  sha256: string;
}

interface EventVector {
  name: string;
  event: unknown;
  canonical: string;
  sha256: string;
}

interface ChainVector {
  records: Array<{ event: unknown; seq: number; host_ts: string; previous_hash: string; record_hash: string }>;
  digest: string;
}

// Seal a list of events into a chain with deterministic host_ts, computing record_hash over the
// full event (including `signature` under Level 2, §8.2).
function sealChain(events: AuditEvent[]): ChainVector {
  let prev = GENESIS_HASH;
  const records = events.map((event, i) => {
    const host_ts = new Date(Date.UTC(2026, 6, 15, 0, 0, 20 + i)).toISOString();
    const record_hash = computeRecordHash(event, i, host_ts, prev);
    const rec = { event, seq: i, host_ts, previous_hash: prev, record_hash };
    prev = record_hash;
    return rec;
  });
  return { records, digest: prev };
}

async function build(): Promise<{
  canonicalization: CanonicalizationVector[];
  events: EventVector[];
  chain: ChainVector;
  chainSigned: ChainVector;
}> {
  const canonicalization: CanonicalizationVector[] = CANONICALIZATION_CASES.map((c) => {
    const canonical = canonicalize(c.value);
    return { name: c.name, value: c.value, canonical, sha256: sha256Hex(canonical) };
  });

  const events: EventVector[] = EVENT_CASES.map((c) => {
    const canonical = canonicalize(c.event);
    return { name: c.name, event: c.event, canonical, sha256: sha256Hex(canonical) };
  });

  const host = await runCleanScenario();
  const chain: ChainVector = {
    records: host.records().map((r) => ({
      event: r.event,
      seq: r.seq,
      host_ts: r.host_ts,
      previous_hash: r.previous_hash,
      record_hash: r.record_hash,
    })),
    digest: host.ledger.digest(),
  };

  // Self-check the chain fixture against an independent recomputation before committing it.
  let prev = GENESIS_HASH;
  for (const r of chain.records) {
    const recomputed = computeRecordHash(r.event as never, r.seq, r.host_ts, prev);
    if (recomputed !== r.record_hash) throw new Error(`chain self-check failed at seq ${r.seq}`);
    prev = recomputed;
  }
  if (prev !== chain.digest) throw new Error('chain digest self-check failed');

  const chainSigned = sealChain(SIGNED_CHAIN_EVENTS);

  return { canonicalization, events, chain, chainSigned };
}

async function main(): Promise<void> {
  const outDir = SPEC_VECTORS_DIR;
  mkdirSync(outDir, { recursive: true });
  const { canonicalization, events, chain, chainSigned } = await build();

  const files: Array<[string, unknown]> = [
    ['canonicalization.json', canonicalization],
    ['events.json', events],
    ['chain.json', chain],
    ['chain-signed.json', chainSigned],
    ['error-cases.json', ERROR_CASES],
  ];
  for (const [file, data] of files) {
    const path = resolve(outDir, file);
    writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
    console.log(`wrote ${path}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
