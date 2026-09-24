import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SPEC_VECTORS_DIR } from '../paths.js';
import { canonicalize, sha256Hex } from '../ledger/canonical.js';
import { computeRecordHash, GENESIS_HASH, witnessPayload } from '../ledger/ledger.js';

// A fixed stand-in for a real witness signature. The vector pins the preimage and the field
// placement, not the signature scheme, so any implementation reproduces the file byte-for-byte
// without sharing a private key (§8.4).
const WITNESS_KEY_ID = 'host-key-2026';
const WITNESS_SIGNATURE = Buffer.from('fake-witness-signature', 'utf8').toString('base64');
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
  records: Array<{
    event: unknown;
    seq: number;
    host_ts: string;
    previous_hash: string;
    record_hash: string;
    // Present only in the witnessed chain (§5.2, §7.1).
    host_key_id?: string;
    host_signature?: string;
    witness_preimage?: { canonical: string; sha256: string };
  }>;
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
  chainWitnessed: ChainVector;
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

  // The witnessed chain is the L1 chain plus what a signing host adds (§5.2, §7.1). The witness
  // signature is not part of the §8.2 preimage, so the record hashes and the digest are unchanged;
  // what this vector pins is the preimage the host signs over and where the pair sits. The
  // signature itself is a fixed stand-in, so any implementation reproduces the file without
  // sharing a private key.
  const chainWitnessed: ChainVector = {
    records: chain.records.map((r) => {
      const canonical = witnessPayload(r.seq, r.host_ts, r.previous_hash, r.record_hash);
      return {
        ...r,
        host_key_id: WITNESS_KEY_ID,
        host_signature: WITNESS_SIGNATURE,
        witness_preimage: { canonical, sha256: sha256Hex(canonical) },
      };
    }),
    digest: chain.digest,
  };

  return { canonicalization, events, chain, chainSigned, chainWitnessed };
}

async function main(): Promise<void> {
  const outDir = SPEC_VECTORS_DIR;
  mkdirSync(outDir, { recursive: true });
  const { canonicalization, events, chain, chainSigned, chainWitnessed } = await build();

  const files: Array<[string, unknown]> = [
    ['canonicalization.json', canonicalization],
    ['events.json', events],
    ['chain.json', chain],
    ['chain-signed.json', chainSigned],
    ['chain-witnessed.json', chainWitnessed],
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
