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

// Tier-1 reject reason codes (§7.6). The wire reason is pinned to this closed set so a tool can
// branch on it mechanically; finer cause is a host-local diagnostic, not carried on the wire.
export const REJECT_REASONS = ['schema-invalid', 'replay-detected', 'signature-invalid', 'l2-unsigned', 'unknown-key'] as const;

// audit/attempt result: accept (recorded) / reject (refused) / unavailable (infra).
export const AuditAttemptResultSchema = z.discriminatedUnion('status', [
  z.strictObject({
    status: z.literal('accept'),
    seq: z.number().int().nonnegative(),
    record_hash: z.string().regex(/^[0-9a-f]{64}$/),
    host_ts: z.iso.datetime(),
    previous_hash: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  z.strictObject({ status: z.literal('reject'), reason: z.enum(REJECT_REASONS) }),
  z.strictObject({ status: z.literal('unavailable'), reason: z.literal('internal-error'), retryable: z.literal(true) }),
]);
export type AuditAttemptResult = z.infer<typeof AuditAttemptResultSchema>;
