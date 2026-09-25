import { z } from 'zod/v4';
import { auditEventSchema } from './event.js';
import { auditCapabilitySchema } from './capability.js';
import { AuditAttemptResultSchema, AuditRequestMetaSchema, AuditResultMetaSchema } from '../transport/mcpWire.js';

// The `reason` enum pins the VALUE (§7.6), but a value enum cannot express "required when
// outcome=aborted." This conditional adds that presence rule to the emitted JSON Schema, so any
// conformant validator (e.g. the Python port's jsonschema) rejects a reason-less aborted event.
// Zod does not emit refinements to JSON Schema, so this is applied post-emission; the Zod schema
// carries the same rule as a refinement (event.ts).
const ABORTED_REASON_RULE = [
  { if: { required: ['outcome'], properties: { outcome: { const: 'aborted' } } }, then: { required: ['reason'] } },
];

// §4 pins the Level-2 fields to appear together or not at all, a presence rule Zod does not emit
// (the Zod schema carries it as a refinement).
const LEVEL_2_FIELDS = { signature: ['key_id', 'signer_seq'], key_id: ['signature', 'signer_seq'], signer_seq: ['signature', 'key_id'] };

function withEventRules(schema: unknown): Record<string, unknown> {
  return { ...(schema as Record<string, unknown>), allOf: ABORTED_REASON_RULE, dependentRequired: LEVEL_2_FIELDS };
}

// The result-side `events` items are plain objects: each is validated as an event on its own (§6.4).
// Zod emits a loose object with empty `properties` and `additionalProperties`, which say nothing.
function withPlainObjectEvents(schema: unknown): Record<string, unknown> {
  const emitted = schema as { properties: { events: { items: Record<string, unknown> } } };
  emitted.properties.events.items = { type: 'object' };
  return emitted as unknown as Record<string, unknown>;
}

// §7.1 pins `host_signature`, `host_key_id`, and `log_id` to appear together or not at all. That is
// a presence rule among optional fields, which Zod expresses as a refinement and does not emit to
// JSON Schema, so it is applied post-emission on every accept branch - the same treatment the
// aborted reason rule gets above. The TS host also enforces it in code (it returns all or none).
const COUNTERSIGNATURE_TRIPLE = { host_signature: ['host_key_id', 'log_id'], host_key_id: ['host_signature', 'log_id'], log_id: ['host_signature', 'host_key_id'] };

function withCountersignatureRule(schema: unknown): Record<string, unknown> {
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const obj = node as Record<string, unknown>;
    const status = (obj.properties as { status?: { const?: string } } | undefined)?.status?.const;
    if (status === 'accept') obj.dependentRequired = COUNTERSIGNATURE_TRIPLE;
    Object.values(obj).forEach(visit);
  };
  visit(schema);
  return schema as Record<string, unknown>;
}

// JSON Schema materialized from the Zod source of truth. The emitter (emitJsonSchema.ts) and the
// drift fence (schemaTargets.test.ts) consume this single definition, so the committed
// spec/schema/*.json cannot diverge from the Zod SoT undetected. Capability uses io:'input' so
// defaulted fields are not marked required.
export const SCHEMA_TARGETS: ReadonlyArray<readonly [string, unknown]> = [
  ['audit-event.schema.json', withEventRules(z.toJSONSchema(auditEventSchema))],
  ['audit-capability.schema.json', z.toJSONSchema(auditCapabilitySchema, { io: 'input' })],
  ['audit-attempt-response.schema.json', withCountersignatureRule(z.toJSONSchema(AuditAttemptResultSchema))],
  ['audit-request-meta.schema.json', withCountersignatureRule(z.toJSONSchema(AuditRequestMetaSchema))],
  ['audit-result-meta.schema.json', withPlainObjectEvents(z.toJSONSchema(AuditResultMetaSchema))],
];
