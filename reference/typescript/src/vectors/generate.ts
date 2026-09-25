import { createPrivateKey, createPublicKey, sign, type KeyObject } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SPEC_VECTORS_DIR } from '../paths.js';
import { canonicalDomainError, canonicalize, sha256Hex } from '../ledger/canonical.js';
import { computeRecordHash, countersignaturePayload, GENESIS_HASH } from '../ledger/ledger.js';
import { KeySigner, signEvent } from '../l2/signing.js';
import { runCleanScenario } from '../demo/scenario.js';
import type { AuditEvent } from '../schema/event.js';
import {
  ACCOUNTING_CASES,
  CANONICALIZATION_CASES,
  ERROR_CASES,
  EVENT_CASES,
  HOST_KEY_ID,
  HOST_KEY_SEED_HEX,
  OTHER_HOST_KEY_ID,
  OTHER_HOST_KEY_SEED_HEX,
  REPLAY_STEPS,
  SIGNED_CHAIN_EVENTS,
  TOOL_KEY_ID,
  TOOL_KEY_SEED_HEX,
  VERIFIER_CASES,
  VERIFIER_LOG_ID,
} from './fixtures.js';

// Generate the committed golden vectors. Any independent implementation must reproduce
// these byte-for-byte: canonical serialization, per-event hashes, and a full sealed chain
// (seq + previous_hash + record_hash + anchored digest).

// The ledger the countersigned vector names (§7.1). It is the clean scenario's partition.
const LOG_ID = 'acme#2026-07-15';

// RFC 8410 PKCS#8 for an Ed25519 private key is this fixed prefix followed by the 32-byte seed.
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function ed25519FromSeed(seedHex: string): { privateKey: KeyObject; jwk: Record<string, unknown> } {
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const { kty, crv, x } = createPublicKey(privateKey).export({ format: 'jwk' });
  return { privateKey, jwk: { kty, crv, x } };
}

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

interface ChainRecord {
  event: unknown;
  seq: number;
  host_ts: string;
  previous_hash: string;
  record_hash: string;
  // Present only in the countersigned chain (§5.2, §7.1).
  host_signature?: string;
  host_key_id?: string;
  log_id?: string;
  countersignature_preimage?: { canonical: string; sha256: string };
}

interface ChainVector {
  // The public half of each key a record in the chain is signed with, as a JWK (§5.1).
  keys?: Record<string, { alg: string; jwk: Record<string, unknown> }>;
  records: ChainRecord[];
  digest: string;
}

// Seal a list of events into a chain with deterministic host_ts, computing record_hash over the
// full event (including `signature` under Level 2, §8.2).
function sealChain(events: AuditEvent[]): { records: ChainRecord[]; digest: string } {
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

async function build(): Promise<Array<[string, unknown]>> {
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

  const tool = ed25519FromSeed(TOOL_KEY_SEED_HEX);
  const signer = new KeySigner(TOOL_KEY_ID, 'Ed25519', tool.privateKey);
  const chainSigned: ChainVector = {
    keys: { [TOOL_KEY_ID]: { alg: 'Ed25519', jwk: tool.jwk } },
    ...sealChain(SIGNED_CHAIN_EVENTS.map((e) => signer.sign(e))),
  };

  // The countersigned chain is the L1 chain plus what a countersigning host adds (§5.2, §7.1). The
  // countersignature is not part of the §8.2 preimage, so the record hashes and the digest are
  // unchanged; this vector pins the preimage the host signs over, where the triple sits, and a
  // signature a verifier checks against the published key.
  const countersigning = ed25519FromSeed(HOST_KEY_SEED_HEX);
  const chainCountersigned: ChainVector = {
    keys: { [HOST_KEY_ID]: { alg: 'Ed25519', jwk: countersigning.jwk } },
    records: chain.records.map((r) => {
      const canonical = countersignaturePayload(r.seq, r.host_ts, LOG_ID, r.previous_hash, r.record_hash);
      return {
        ...r,
        host_signature: sign(null, Buffer.from(canonical, 'utf8'), countersigning.privateKey).toString('base64url'),
        host_key_id: HOST_KEY_ID,
        log_id: LOG_ID,
        countersignature_preimage: { canonical, sha256: sha256Hex(canonical) },
      };
    }),
    digest: chain.digest,
  };

  // The replay window (§7.4) as a sequence of steps against one Level-2 host; each port replays it.
  const replay = {
    keys: { [TOOL_KEY_ID]: { alg: 'Ed25519', jwk: tool.jwk } },
    steps: REPLAY_STEPS.map(({ signer_seq, event, ...step }) => ({
      ...step,
      event: signEvent(event, TOOL_KEY_ID, signer_seq, 'Ed25519', tool.privateKey),
    })),
  };

  // Verifier findings (§11.4): each case's events sealed into a chain, countersigned per record by the
  // key it names. A record with no computable hash stores the zero hash, and the chain continues from it.
  const other = ed25519FromSeed(OTHER_HOST_KEY_SEED_HEX);
  const hostKeys = { host: [HOST_KEY_ID, countersigning.privateKey], 'other-host': [OTHER_HOST_KEY_ID, other.privateKey] } as const;
  const verifier = {
    keys: {
      [HOST_KEY_ID]: { alg: 'Ed25519', jwk: countersigning.jwk },
      [OTHER_HOST_KEY_ID]: { alg: 'Ed25519', jwk: other.jwk },
    },
    cases: VERIFIER_CASES.map(({ name, events: caseEvents, countersign, options, expect_kinds }) => {
      let previous = GENESIS_HASH;
      const records = caseEvents.map((event, i) => {
        const host_ts = new Date(Date.UTC(2026, 6, 15, 0, 0, 30 + i)).toISOString();
        const record_hash = canonicalDomainError(event) === undefined ? computeRecordHash(event as never, i, host_ts, previous) : '0'.repeat(64);
        const rec: ChainRecord = { event, seq: i, host_ts, previous_hash: previous, record_hash };
        const signer = countersign[i];
        if (signer !== undefined && signer !== 'none') {
          const [host_key_id, privateKey] = hostKeys[signer];
          const payload = countersignaturePayload(i, host_ts, VERIFIER_LOG_ID, previous, record_hash);
          rec.host_signature = sign(null, Buffer.from(payload, 'utf8'), privateKey).toString('base64url');
          rec.host_key_id = host_key_id;
          rec.log_id = VERIFIER_LOG_ID;
        }
        previous = record_hash;
        return rec;
      });
      return { name, records, options, expect_kinds };
    }),
  };

  return [
    ['canonicalization.json', canonicalization],
    ['events.json', events],
    ['chain.json', chain],
    ['chain-signed.json', chainSigned],
    ['chain-countersigned.json', chainCountersigned],
    ['error-cases.json', ERROR_CASES],
    ['signer-seq-accounting.json', ACCOUNTING_CASES],
    ['signer-seq-replay.json', replay],
    ['verifier-cases.json', verifier],
  ];
}

async function main(): Promise<void> {
  mkdirSync(SPEC_VECTORS_DIR, { recursive: true });
  for (const [file, data] of await build()) {
    const path = resolve(SPEC_VECTORS_DIR, file);
    writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
    console.log(`wrote ${path}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
