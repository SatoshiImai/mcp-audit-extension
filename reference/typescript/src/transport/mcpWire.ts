// Wire-framing schemas use zod/v4 (MCP SDK) and reuse auditEventSchema as the params payload:
// one schema validated at both wire and host layers.
import { z } from 'zod/v4';
import { RequestSchema, NotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { auditEventSchema } from '../schema/event.js';

// Wire methods. audit/attempt: server->client request (blocking, fail-closed). audit/outcome:
// server->client notification. Reuses the elicitation wire shape, not its human-in-the-loop semantics.

export const AUDIT_ATTEMPT_METHOD = 'audit/attempt';
export const AUDIT_OUTCOME_METHOD = 'audit/outcome';

// Request: tool (MCP server) asks host (MCP client) to durably record the attempt.
export const AuditAttemptRequestSchema = RequestSchema.extend({
  method: z.literal(AUDIT_ATTEMPT_METHOD),
  params: auditEventSchema,
});
export type AuditAttemptRequest = z.infer<typeof AuditAttemptRequestSchema>;

// Notification: outcome reported after acting. Not a completeness gate.
export const AuditOutcomeNotificationSchema = NotificationSchema.extend({
  method: z.literal(AUDIT_OUTCOME_METHOD),
  params: auditEventSchema,
});
export type AuditOutcomeNotification = z.infer<typeof AuditOutcomeNotificationSchema>;

// audit/attempt result: accept (recorded) / reject (refused) / unavailable (infra).
export const AuditAttemptResultSchema = z.discriminatedUnion('status', [
  z.object({
    status: z.literal('accept'),
    seq: z.number().int().nonnegative(),
    record_hash: z.string(),
    host_ts: z.string(),
    previous_hash: z.string(),
  }),
  z.object({ status: z.literal('reject'), reason: z.string() }),
  z.object({ status: z.literal('unavailable'), reason: z.string(), retryable: z.literal(true) }),
]);
export type AuditAttemptResult = z.infer<typeof AuditAttemptResultSchema>;
