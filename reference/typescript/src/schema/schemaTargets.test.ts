import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect } from 'vitest';
import { SCHEMA_TARGETS } from './schemaTargets.js';
import { SPEC_SCHEMA_DIR } from '../paths.js';

// Drift fence: the committed JSON Schemas under spec/schema/ must equal the Zod SoT emission. A Zod
// change without `npm run schema:json` fails here, so the wire contract cannot drift silently -
// the schema analogue of vectors.test.ts. audit-capability / audit-attempt-response have no runtime
// consumer, so this test is their only drift guard.
describe('JSON Schema conformance: committed schemas match the Zod source of truth', () => {
  for (const [file, schema] of SCHEMA_TARGETS) {
    it(`${file} は Zod SoT と一致する`, () => {
      const committed = JSON.parse(readFileSync(resolve(SPEC_SCHEMA_DIR, file), 'utf8'));
      expect(committed).toEqual(schema);
    });
  }
});
