import { readFileSync } from 'node:fs';
import { verifyLedger } from './verify.js';
import { runCleanScenario } from '../demo/scenario.js';
import type { SealedRecord } from '../ledger/ledger.js';

// Verifier CLI. With a path arg, verifies a sealed ledger JSON (array of SealedRecord).
// With no arg, runs the built-in clean scenario and verifies it. Exit code reflects ok.
async function main(): Promise<void> {
  const path = process.argv[2];
  let records: readonly SealedRecord[];

  if (path) {
    records = JSON.parse(readFileSync(path, 'utf8')) as SealedRecord[];
  } else {
    const host = await runCleanScenario();
    records = host.records();
  }

  const report = verifyLedger(records);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exit(report.ok ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
