import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SPEC_VECTORS_DIR } from '../paths.js';
import { canonicalize, sha256Hex } from '../ledger/canonical.js';
import { computeRecordHash, GENESIS_HASH } from '../ledger/ledger.js';
import { runCleanScenario } from '../demo/scenario.js';
import { CANONICALIZATION_CASES, EVENT_CASES } from './fixtures.js';

// Generate the committed golden vectors. Any independent implementation must reproduce
// these byte-for-byte: canonical serialization, per-event hashes, and a full sealed chain
// (sequence + prev_hash + record_hash + anchored digest). This is the A-MCP analogue of
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
  records: Array<{ event: unknown; seq: number; host_ts: string; prev_hash: string; record_hash: string }>;
  digest: string;
}

async function build(): Promise<{ canonicalization: CanonicalizationVector[]; events: EventVector[]; chain: ChainVector }> {
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
      prev_hash: r.prev_hash,
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

  return { canonicalization, events, chain };
}

async function main(): Promise<void> {
  const outDir = SPEC_VECTORS_DIR;
  mkdirSync(outDir, { recursive: true });
  const { canonicalization, events, chain } = await build();

  const files: Array<[string, unknown]> = [
    ['canonicalization.json', canonicalization],
    ['events.json', events],
    ['chain.json', chain],
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
