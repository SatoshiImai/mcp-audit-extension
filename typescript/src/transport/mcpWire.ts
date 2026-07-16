// The whole project is on zod/v4, so the wire-framing schemas compose directly with the MCP
// SDK's RequestSchema/NotificationSchema AND reuse the domain source-of-truth (auditEventSchema)
// as the params payload — one schema, validated at both the wire and host layers.
import { z } from 'zod/v4';
import { RequestSchema, NotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { auditEventSchema } from '../schema/event.js';

// A-MCP wire methods on the MCP protocol. audit/attempt is a server→client REQUEST (the
// elicitation-shaped, blocking, fail-closed primitive); audit/outcome is a server→client
// NOTIFICATION (design §6). We reuse the elicitation WIRE FORM, not its HITL semantics.

export const AUDIT_ATTEMPT_METHOD = 'audit/attempt';
export const AUDIT_OUTCOME_METHOD = 'audit/outcome';

// Request: the tool (MCP server) asks the host (MCP client) to durably record the attempt.
export const AuditAttemptRequestSchema = RequestSchema.extend({
  method: z.literal(AUDIT_ATTEMPT_METHOD),
  params: auditEventSchema,
});
export type AuditAttemptRequest = z.infer<typeof AuditAttemptRequestSchema>;

// Notification: the tool reports the outcome after acting. Not a completeness gate.
export const AuditOutcomeNotificationSchema = NotificationSchema.extend({
  method: z.literal(AUDIT_OUTCOME_METHOD),
  params: auditEventSchema,
});
export type AuditOutcomeNotification = z.infer<typeof AuditOutcomeNotificationSchema>;

// Result of audit/attempt: accept (recorded) / reject (a lie, refused) / unavailable (infra).
export const AuditAttemptResultSchema = z.discriminatedUnion('status', [
  z.object({ status: z.literal('accept'), seq: z.number().int().nonnegative(), record_hash: z.string() }),
  z.object({ status: z.literal('reject'), reason: z.string() }),
  z.object({ status: z.literal('unavailable'), reason: z.string(), retryable: z.literal(true) }),
]);
export type AuditAttemptResult = z.infer<typeof AuditAttemptResultSchema>;
