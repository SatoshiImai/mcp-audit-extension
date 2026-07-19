import { describe, it, expect } from 'vitest';
import { runCleanScenario } from '../demo/scenario.js';
import { verifyLedger } from './verify.js';

describe('verifyLedger - proof of non-tampering + completeness', () => {
  it('a clean ledger VERIFIES (zero issues) and matches the anchored digest', async () => {
    const host = await runCleanScenario();
    const anchored = host.ledger.digest();
    const report = verifyLedger(host.records(), anchored);
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
    expect(report.computedDigest).toBe(anchored);
  });

  it('detects tampering of a sealed field via record-hash mismatch', async () => {
    const host = await runCleanScenario();
    const anchored = host.ledger.digest();
    const rec = host.ledger.unsafeMutableRecords()[1];
    if (!rec) throw new Error('fixture missing record');
    rec.event.target_resource.ref = 'https://evil.example/exfil'; // forge the target
    const report = verifyLedger(host.records(), anchored);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === 'record-hash-mismatch')).toBe(true);
    expect(report.issues.some((i) => i.kind === 'digest-mismatch')).toBe(true);
  });

  it('detects a dropped record via a sequence gap (completeness)', async () => {
    const host = await runCleanScenario();
    host.ledger.unsafeMutableRecords().splice(2, 1);
    const report = verifyLedger(host.records());
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === 'seq-gap' || i.kind === 'prev-hash-mismatch')).toBe(true);
  });

  it('detects a swapped anchor digest (anchor consistency)', async () => {
    const host = await runCleanScenario();
    const report = verifyLedger(host.records(), 'deadbeef');
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === 'digest-mismatch')).toBe(true);
  });
});
