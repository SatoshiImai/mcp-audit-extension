import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod/v4';
import { auditEventSchema } from './event.js';
import { auditCapabilitySchema } from './capability.js';
import { SPEC_SCHEMA_DIR } from '../paths.js';

// Materialize JSON Schema from the Zod SoT using zod/v4's native z.toJSONSchema (Zod is the
// source of truth; JSON Schema is a generated, committed artifact under the shared spec/).
// Stable output, so a diff reveals any wire change.
function main(): void {
  const outDir = SPEC_SCHEMA_DIR;
  mkdirSync(outDir, { recursive: true });

  const targets: Array<[string, unknown]> = [
    ['audit-event.schema.json', z.toJSONSchema(auditEventSchema)],
    ['audit-capability.schema.json', z.toJSONSchema(auditCapabilitySchema)],
  ];

  for (const [file, schema] of targets) {
    const path = resolve(outDir, file);
    writeFileSync(path, `${JSON.stringify(schema, null, 2)}\n`, 'utf8');
    console.log(`wrote ${path}`);
  }
}

main();
