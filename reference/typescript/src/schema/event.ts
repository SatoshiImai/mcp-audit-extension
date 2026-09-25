import { z } from 'zod/v4';

// Core audit event - one schema for L1 and L2. The trust-establishing fields
// (signer_seq/key_id/signature) are optional, so an L2 event also validates as an L1 event; an
// unsigned L1 event is rejected by an L2 host (§7.4).

export const SPEC_VERSION = 'auditable-mcp/0.3';

// Tool-internal events emit only attempted/success/failed/aborted; denied/expired are
// host tools/call-boundary outcomes.
export const OUTCOME = ['attempted', 'success', 'failed', 'aborted'] as const;
export type Outcome = (typeof OUTCOME)[number];

// A UUID in its lowercase output form ([RFC-9562] §4), compared as a string (§4). Version digits 1-8,
// or the nil UUID; a session id is never nil (§6.3).
export const UUID_PATTERN = /^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/;
export const SESSION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const targetResourceSchema = z.strictObject({
  kind: z.string().min(1), // e.g. "table" | "file" | "endpoint"
  ref: z.string().min(1), // e.g. "customers" | "/etc/hosts" | "https://api.stripe.com/..."
  scope_hint: z.string().optional(), // domain meaning, e.g. "row:consent_basis=marketing"
});

export const auditEventSchema = z
  .strictObject({
    // --- identity / correlation ---
    id: z.string().regex(UUID_PATTERN), // idempotency, tool-generated
    spec_version: z.literal(SPEC_VERSION),
    ts: z.iso.datetime(), // tool-observed time (advisory; host time is authoritative)
    session_id: z.string().regex(SESSION_ID_PATTERN), // the audit session the host issued for the parent tools/call (§6.3)
    traceparent: z.string().optional(), // W3C Trace Context

    // --- domain action ---
    // action_type is an opaque, non-empty identifier; its vocabulary is out of scope (§4.1).
    action_type: z.string().min(1),
    mutates: z.boolean(), // required effect axis, orthogonal to action_type
    egress: z.boolean(), // required effect axis
    target_resource: targetResourceSchema,
    outcome: z.enum(OUTCOME),
    // The Tier-1 abort code on an `aborted` outcome (§7.6). Pinned so the sealed reason vocabulary is
    // closed; domain-specific failure detail belongs in action_context, not here.
    // §7.6 Tier-1 abort codes, two of them from the countersignature axis: a record no distinct party
    // confirmed, and one whose countersignature did not verify (§5.2, §7.2).
    reason: z
      .enum(['hash-mismatch', 'host-rejected', 'host-unavailable', 'host-uncountersigned', 'host-signature-invalid'])
      .optional(),

    // --- audit context (confidentiality is the tool's choice; §4.3) ---
    // action_context: cleartext metadata about the internal operation, redacted at the tool's
    // discretion. action_context_hash: a commitment to the exact internal context. Independent
    // and both optional; a host must not require them to correspond.
    action_context: z.record(z.string(), z.unknown()).optional(),
    action_context_hash: z
      .string()
      .regex(/^sha256:[0-9a-f]{64}$/)
      .optional(),

    // --- Level 2 only (optional; a single schema covers both levels) ---
    signer_seq: z.number().int().nonnegative().optional(), // per (key_id, session_id), from 0 (§7.4)
    key_id: z.string().min(1).optional(), // non-empty; binds the signature algorithm via the registry (§5.1)
    signature: z
      .string()
      .regex(/^[A-Za-z0-9_-]+$/)
      .optional(), // base64url without padding, as JWS writes a signature (§5.1)
  })
  // Presence rules JSON Schema carries as `allOf`/`dependentRequired` (schemaTargets.ts), which Zod
  // does not emit: an aborted outcome names its abort code (§7.2), and the Level-2 fields appear
  // together or not at all (§4).
  .superRefine((event, ctx) => {
    if (event.outcome === 'aborted' && event.reason === undefined) {
      ctx.addIssue({ code: 'custom', path: ['reason'], message: 'an aborted outcome carries a Tier-1 abort code (§7.2)' });
    }
    const level2 = [event.signature, event.key_id, event.signer_seq].filter((v) => v !== undefined).length;
    if (level2 !== 0 && level2 !== 3) {
      ctx.addIssue({ code: 'custom', message: 'signature, key_id, and signer_seq appear together or not at all (§4)' });
    }
  });

export type AuditEvent = z.infer<typeof auditEventSchema>;
