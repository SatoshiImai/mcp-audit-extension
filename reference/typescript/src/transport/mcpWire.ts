// Wire schemas, in zod/v4 as the MCP SDK uses. The audit event is the params payload of the §6.5
// methods and an element of the §6.4 `events` array.
import { z } from 'zod/v4';
import { RequestSchema, NotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { SESSION_ID_PATTERN, UUID_PATTERN } from '../schema/event.js';

export const EXTENSION_ID = 'com.timberlandchapel/auditable-mcp';

// §6.5: the binding for MCP protocol versions with an initialization handshake. audit/attempt is a
// server->client request; audit/outcome a server->client notification.
export const AUDIT_ATTEMPT_METHOD = 'audit/attempt';
export const AUDIT_OUTCOME_METHOD = 'audit/outcome';

// The params reach the host as received. The host validates them (§7.1) and answers a malformed
// attempt with a reject, which validating here would turn into a protocol error (§6); and a parsed
// copy is not the structure that arrived, which is what the host hashes (§8).
const receivedEvent = z.custom<Record<string, unknown>>(
  (value) => typeof value === 'object' && value !== null && !Array.isArray(value),
);

export const AuditAttemptRequestSchema = RequestSchema.extend({
  method: z.literal(AUDIT_ATTEMPT_METHOD),
  params: receivedEvent,
});
export type AuditAttemptRequest = z.infer<typeof AuditAttemptRequestSchema>;

export const AuditOutcomeNotificationSchema = NotificationSchema.extend({
  method: z.literal(AUDIT_OUTCOME_METHOD),
  params: receivedEvent,
});
export type AuditOutcomeNotification = z.infer<typeof AuditOutcomeNotificationSchema>;

// Tier-1 reject reason codes (§7.6). The wire reason is pinned to this closed set so a tool can
// branch on it mechanically; finer cause is a host-local diagnostic, not carried on the wire.
export const REJECT_REASONS = ['schema-invalid', 'replay-detected', 'signature-invalid', 'l2-unsigned', 'unknown-key'] as const;

const BASE64URL = /^[A-Za-z0-9_-]+$/;

export const AuditAttemptResultSchema = z.discriminatedUnion('status', [
  z
    .strictObject({
      status: z.literal('accept'),
      seq: z.number().int().nonnegative(),
      record_hash: z.string().regex(/^[0-9a-f]{64}$/),
      host_ts: z.iso.datetime(),
      previous_hash: z.string().regex(/^[0-9a-f]{64}$/),
      // The countersignature triple (§5.2, §7.1): base64url over the canonical host-assigned fields
      // and log_id, the key id a verifier's registry resolves, and the ledger it names.
      host_signature: z.string().regex(BASE64URL).optional(),
      host_key_id: z.string().min(1).optional(),
      log_id: z.string().min(1).optional(),
    })
    // §7.1: all three or none. A partial triple is not a conformant response.
    .refine(
      (r) =>
        (r.host_signature === undefined) === (r.host_key_id === undefined) &&
        (r.host_signature === undefined) === (r.log_id === undefined),
    ),
  z.strictObject({ status: z.literal('reject'), reason: z.enum(REJECT_REASONS) }),
  z.strictObject({ status: z.literal('unavailable'), reason: z.literal('internal-error') }),
]);
export type AuditAttemptResult = z.infer<typeof AuditAttemptResultSchema>;

// §6.4: the binding for MCP protocol version 2026-07-28. The exchange rides the tools/call in
// `_meta[EXTENSION_ID]`. The request side carries the session, and on a retry the responses to the
// attempts of the round before; the result side carries the events of the round.
export const AuditRequestMetaSchema = z.strictObject({
  session_id: z.string().regex(SESSION_ID_PATTERN),
  responses: z.record(z.string().regex(UUID_PATTERN), AuditAttemptResultSchema).optional(),
});
export type AuditRequestMeta = z.infer<typeof AuditRequestMetaSchema>;

// Each element of `events` is an object and nothing more here: the host validates each event on its
// own (§6.4), so one malformed element is refused alone and does not invalidate the round.
export const AuditResultMetaSchema = z.strictObject({
  session_id: z.string().regex(SESSION_ID_PATTERN),
  events: z.array(z.looseObject({})).min(1),
});
export type AuditResultMeta = z.infer<typeof AuditResultMetaSchema>;
