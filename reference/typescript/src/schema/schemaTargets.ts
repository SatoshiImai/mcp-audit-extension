import { z } from 'zod/v4';
import { auditEventSchema } from './event.js';
import { auditCapabilitySchema } from './capability.js';
import { AuditAttemptResultSchema } from '../transport/mcpWire.js';

// JSON Schema materialized from the Zod source of truth. The emitter (emitJsonSchema.ts) and the
// drift fence (schemaTargets.test.ts) consume this single definition, so the committed
// spec/schema/*.json cannot diverge from the Zod SoT undetected. Capability uses io:'input' so
// defaulted fields are not marked required.
export const SCHEMA_TARGETS: ReadonlyArray<readonly [string, unknown]> = [
  ['audit-event.schema.json', z.toJSONSchema(auditEventSchema)],
  ['audit-capability.schema.json', z.toJSONSchema(auditCapabilitySchema, { io: 'input' })],
  ['audit-attempt-response.schema.json', z.toJSONSchema(AuditAttemptResultSchema)],
];
