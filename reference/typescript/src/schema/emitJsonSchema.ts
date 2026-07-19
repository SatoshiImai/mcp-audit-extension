import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SCHEMA_TARGETS } from './schemaTargets.js';
import { SPEC_SCHEMA_DIR } from '../paths.js';

// Materialize JSON Schema from the Zod SoT (schemaTargets.ts) into the shared spec/. JSON Schema is
// a generated, committed artifact; schemaTargets.test.ts fences it against the SoT.
function main(): void {
  mkdirSync(SPEC_SCHEMA_DIR, { recursive: true });
  for (const [file, schema] of SCHEMA_TARGETS) {
    const path = resolve(SPEC_SCHEMA_DIR, file);
    writeFileSync(path, `${JSON.stringify(schema, null, 2)}\n`, 'utf8');
    console.log(`wrote ${path}`);
  }
}

main();
