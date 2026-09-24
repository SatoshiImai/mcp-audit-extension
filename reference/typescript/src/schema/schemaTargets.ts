import { z } from 'zod/v4';
import { auditEventSchema } from './event.js';
import { auditCapabilitySchema } from './capability.js';
import { AuditAttemptResultSchema } from '../transport/mcpWire.js';

// The `reason` enum pins the VALUE (§7.6), but a value enum cannot express "required when
// outcome=aborted." This conditional adds that presence rule to the emitted JSON Schema, so any
// conformant validator (e.g. the Python port's jsonschema) rejects a reason-less aborted event.
// Zod does not emit refinements to JSON Schema, so this is applied post-emission; the TS host also
// enforces it in code (auditHost.handleOutcome).
function withAbortedReasonRule(schema: unknown): Record<string, unknown> {
  return {
    ...(schema as Record<string, unknown>),
    allOf: [{ if: { required: ['outcome'], properties: { outcome: { const: 'aborted' } } }, then: { required: ['reason'] } }],
  };
}

// §7.1 pins `host_signature` and `host_key_id` to appear together or not at all. That is a presence
// rule between two optional fields, which Zod expresses as a refinement and does not emit to JSON
// Schema, so it is applied post-emission on the accept branch - the same treatment the aborted
// reason rule gets above. The TS host also enforces it in code (it returns both or neither).
function withWitnessPairRule(schema: unknown): Record<string, unknown> {
  const emitted = schema as { anyOf?: Record<string, unknown>[] };
  const accept = emitted.anyOf?.find(
    (branch) => (branch.properties as { status?: { const?: string } } | undefined)?.status?.const === 'accept',
  );
  if (accept !== undefined) {
    accept.dependentRequired = { host_signature: ['host_key_id'], host_key_id: ['host_signature'] };
  }
  return emitted as Record<string, unknown>;
}

// JSON Schema materialized from the Zod source of truth. The emitter (emitJsonSchema.ts) and the
// drift fence (schemaTargets.test.ts) consume this single definition, so the committed
// spec/schema/*.json cannot diverge from the Zod SoT undetected. Capability uses io:'input' so
// defaulted fields are not marked required.
export const SCHEMA_TARGETS: ReadonlyArray<readonly [string, unknown]> = [
  ['audit-event.schema.json', withAbortedReasonRule(z.toJSONSchema(auditEventSchema))],
  ['audit-capability.schema.json', z.toJSONSchema(auditCapabilitySchema, { io: 'input' })],
  ['audit-attempt-response.schema.json', withWitnessPairRule(z.toJSONSchema(AuditAttemptResultSchema))],
];
