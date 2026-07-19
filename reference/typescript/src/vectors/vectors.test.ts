import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SPEC_VECTORS_DIR } from '../paths.js';
import { canonicalize, sha256Hex } from '../ledger/canonical.js';
import { computeRecordHash, GENESIS_HASH } from '../ledger/ledger.js';
import type { AuditEvent } from '../schema/event.js';

// Conformance fence: recompute canonical bytes and hashes from the INPUTS stored in the
// committed golden files and assert they equal the stored outputs. If canonicalization or
// hashing ever changes without regenerating (`npm run vectors`), this fails — the wire
// contract cannot drift silently. The same golden files let a cross-language port self-check.

function load<T>(file: string): T {
  return JSON.parse(readFileSync(resolve(SPEC_VECTORS_DIR, file), 'utf8')) as T;
}

describe('conformance vectors — canonicalization', () => {
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

describe('conformance vectors — events', () => {
  const cases = load<Array<{ name: string; event: AuditEvent; canonical: string; sha256: string }>>('events.json');

  for (const c of cases) {
    it(`reproduces canonical + sha256 for event "${c.name}"`, () => {
      expect(canonicalize(c.event)).toBe(c.canonical);
      expect(sha256Hex(c.canonical)).toBe(c.sha256);
    });
  }
});

describe('conformance vectors — sealed chain', () => {
  const chain = load<{
    records: Array<{ event: AuditEvent; seq: number; host_ts: string; previous_hash: string; record_hash: string }>;
    digest: string;
  }>('chain.json');

  it('recomputes every record_hash and the final digest from the record inputs', () => {
    let prev = GENESIS_HASH;
    chain.records.forEach((r, i) => {
      expect(r.seq).toBe(i);
      expect(r.previous_hash).toBe(prev);
      const recomputed = computeRecordHash(r.event, r.seq, r.host_ts, prev);
      expect(recomputed).toBe(r.record_hash);
      prev = recomputed;
    });
    expect(prev).toBe(chain.digest);
  });
});
