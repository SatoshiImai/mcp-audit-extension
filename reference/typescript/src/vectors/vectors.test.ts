import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SPEC_VECTORS_DIR } from '../paths.js';
import { canonicalize, sha256Hex } from '../ledger/canonical.js';
import { createPublicKey, verify } from 'node:crypto';
import { computeRecordHash, countersignaturePayload, GENESIS_HASH, type SealedRecord } from '../ledger/ledger.js';
import { verifyEventSignature } from '../l2/signing.js';
import { unaccountedSignerSeq, verifyLedger } from '../verify/verify.js';
import type { AuditEvent } from '../schema/event.js';
import { AuditHost } from '../host/auditHost.js';
import { KeyRegistry } from '../l2/keys.js';

// Conformance fence: recompute canonical bytes and hashes from the INPUTS stored in the
// committed golden files and assert they equal the stored outputs. If canonicalization or
// hashing ever changes without regenerating (`npm run vectors`), this fails - the wire
// contract cannot drift silently. The same golden files let a cross-language port self-check.

function load<T>(file: string): T {
  return JSON.parse(readFileSync(resolve(SPEC_VECTORS_DIR, file), 'utf8')) as T;
}

describe('conformance vectors - canonicalization', () => {
  const cases = load<Array<{ name: string; value: unknown; canonical: string; sha256: string }>>('canonicalization.json');

  it('has vectors committed', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  for (const c of cases) {
    it(`reproduces canonical + sha256 for "${c.name}"`, () => {
      expect(canonicalize(c.value)).toBe(c.canonical);
      expect(sha256Hex(c.canonical)).toBe(c.sha256);
    });
  }
});

describe('conformance vectors - events', () => {
  const cases = load<Array<{ name: string; event: AuditEvent; canonical: string; sha256: string }>>('events.json');

  for (const c of cases) {
    it(`reproduces canonical + sha256 for event "${c.name}"`, () => {
      expect(canonicalize(c.event)).toBe(c.canonical);
      expect(sha256Hex(c.canonical)).toBe(c.sha256);
    });
  }
});

type ChainVector = {
  keys?: Record<string, { alg: 'Ed25519'; jwk: Record<string, string> }>;
  records: Array<{
    event: AuditEvent;
    seq: number;
    host_ts: string;
    previous_hash: string;
    record_hash: string;
    host_signature?: string;
    host_key_id?: string;
    log_id?: string;
    countersignature_preimage?: { canonical: string; sha256: string };
  }>;
  digest: string;
};

function publicKey(chain: ChainVector, keyId: string) {
  const entry = chain.keys?.[keyId];
  if (entry === undefined) throw new Error(`the vector publishes no key ${keyId}`);
  return createPublicKey({ key: entry.jwk, format: 'jwk' });
}

function recomputeChain(chain: ChainVector): void {
  let prev = GENESIS_HASH;
  chain.records.forEach((r, i) => {
    expect(r.seq).toBe(i);
    expect(r.previous_hash).toBe(prev);
    const recomputed = computeRecordHash(r.event, r.seq, r.host_ts, prev);
    expect(recomputed).toBe(r.record_hash);
    prev = recomputed;
  });
  expect(prev).toBe(chain.digest);
}

describe('conformance vectors - sealed chain', () => {
  it('recomputes every record_hash and the final digest from the record inputs (L1)', () => {
    recomputeChain(load<ChainVector>('chain.json'));
  });

  // The signed chain pins that record_hash is computed over the full event INCLUDING `signature`
  // (§8.2) - the case that forks Level-2 interop, and the one chain.json (L1, unsigned) never covers.
  it('recomputes a Level-2 signed chain, hashing the signature into each record (L2)', () => {
    const signed = load<ChainVector>('chain-signed.json');
    expect(signed.records.every((r) => typeof r.event.signature === 'string')).toBe(true);
    recomputeChain(signed);
  });
});

describe('conformance vectors - signatures verify against the published keys', () => {
  it('verifies every Level-2 signature in chain-signed.json, numbered from 0 in its session (§5.1, §7.4)', () => {
    const signed = load<ChainVector>('chain-signed.json');
    signed.records.forEach((r, i) => {
      expect(r.event.signer_seq).toBe(i);
      const key = { publicKey: publicKey(signed, r.event.key_id as string), alg: 'Ed25519' as const };
      expect(verifyEventSignature(r.event, key)).toBe(true);
    });
  });

  it('reproduces and verifies every countersignature, with record hashes identical to chain.json (§5.2, §7.1)', () => {
    const plain = load<ChainVector>('chain.json');
    const countersigned = load<ChainVector>('chain-countersigned.json');
    expect(countersigned.records.map((r) => r.record_hash)).toEqual(plain.records.map((r) => r.record_hash));
    expect(countersigned.digest).toBe(plain.digest);
    for (const r of countersigned.records) {
      const canonical = countersignaturePayload(r.seq, r.host_ts, r.log_id as string, r.previous_hash, r.record_hash);
      expect(canonical).toBe(r.countersignature_preimage?.canonical);
      expect(sha256Hex(canonical)).toBe(r.countersignature_preimage?.sha256);
      const signature = Buffer.from(r.host_signature as string, 'base64url');
      expect(verify(null, Buffer.from(canonical, 'utf8'), publicKey(countersigned, r.host_key_id as string), signature)).toBe(true);
    }
  });
});

describe('conformance vectors - accounting for signer_seq (§11.4)', () => {
  const cases = load<
    Array<{
      name: string;
      records: Array<Partial<AuditEvent> & { id: string; key_id: string; session_id: string; signer_seq: number }>;
      unaccounted: Array<{ key_id: string; session_id: string; signer_seq: number }>;
    }>
  >('signer-seq-accounting.json');

  for (const c of cases) {
    it(`reports exactly the pinned values for "${c.name}"`, () => {
      const records = c.records.map((event) => ({ event }) as unknown as SealedRecord);
      expect(unaccountedSignerSeq(records)).toEqual(c.unaccounted);
    });
  }
});

describe('conformance vectors - the Level-2 replay window (§7.4)', () => {
  const vector = load<{
    keys: Record<string, { alg: 'Ed25519'; jwk: Record<string, string> }>;
    steps: Array<{
      name: string;
      channel: 'attempt' | 'outcome';
      host_available: boolean;
      event: AuditEvent;
      expect: { status?: string; reason?: string; seq?: number; sealed?: boolean; anomalies: string[] };
    }>;
  }>('signer-seq-replay.json');

  it('reproduces every step against one Level-2 host', () => {
    const registry = new KeyRegistry();
    for (const [keyId, { alg, jwk }] of Object.entries(vector.keys)) registry.registerJwk(keyId, jwk, alg);
    const host = new AuditHost('replay', { spec_version: 'auditable-mcp/0.3', level: 'L2', attempt: 'request', countersign: 'none' }, registry);
    host.openSession(vector.steps[0]!.event.session_id);
    for (const step of vector.steps) {
      host.unavailable = !step.host_available;
      const anomaliesBefore = host.getAnomalies().length;
      const recordsBefore = host.records().length;
      if (step.channel === 'attempt') {
        const res = host.handleAttempt(step.event);
        expect(res.status, step.name).toBe(step.expect.status);
        if (step.expect.reason !== undefined) expect(res, step.name).toMatchObject({ reason: step.expect.reason });
        if (step.expect.seq !== undefined) expect(res, step.name).toMatchObject({ seq: step.expect.seq });
      } else {
        host.handleOutcome(step.event);
        expect(host.records().length - recordsBefore, step.name).toBe(step.expect.sealed ? 1 : 0);
      }
      expect(host.getAnomalies().slice(anomaliesBefore).map((a) => a.kind), step.name).toEqual(step.expect.anomalies);
    }
  });
});

describe('conformance vectors - verifier findings (§11.4)', () => {
  const vector = load<{
    keys: Record<string, { alg: 'Ed25519'; jwk: Record<string, string> }>;
    cases: Array<{
      name: string;
      records: SealedRecord[];
      options: { countersignature_required?: boolean; expected_identity?: { log_id: string; host_key_ids: string[] } };
      expect_kinds: string[];
    }>;
  }>('verifier-cases.json');
  const hostKeyRegistry = new KeyRegistry();
  for (const [keyId, { alg, jwk }] of Object.entries(vector.keys)) hostKeyRegistry.registerJwk(keyId, jwk, alg);

  for (const c of vector.cases) {
    it(`reports exactly the pinned kinds for "${c.name}"`, () => {
      const identity = c.options.expected_identity;
      const report = verifyLedger(c.records, undefined, undefined, {
        hostKeyRegistry,
        countersignatureRequired: c.options.countersignature_required ?? false,
        ...(identity === undefined ? {} : { expectedIdentity: { logId: identity.log_id, hostKeyIds: identity.host_key_ids } }),
      });
      expect(report.issues.map((i) => i.kind).sort()).toEqual(c.expect_kinds);
      expect(report.unchecked).toEqual([]);
    });
  }
});
