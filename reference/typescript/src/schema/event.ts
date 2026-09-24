import { z } from 'zod/v4';

// Core audit event - one schema for L1 and L2. The trust-establishing fields
// (signer_seq/key_id/signature) are optional, so an L2 event also validates as an L1 event; an
// unsigned L1 event is rejected by an L2 host (§7.4).

export const SPEC_VERSION = 'auditable-mcp/0.3';

// Tool-internal events emit only attempted/success/failed/aborted; denied/expired are
// host tools/call-boundary outcomes.
export const OUTCOME = ['attempted', 'success', 'failed', 'aborted'] as const;
export type Outcome = (typeof OUTCOME)[number];

export const targetResourceSchema = z.strictObject({
  kind: z.string().min(1), // e.g. "table" | "file" | "endpoint"
  ref: z.string().min(1), // e.g. "customers" | "/etc/hosts" | "https://api.stripe.com/..."
  scope_hint: z.string().optional(), // domain meaning, e.g. "row:consent_basis=marketing"
});

export const auditEventSchema = z.strictObject({
  // --- identity / correlation ---
  id: z.uuid(), // idempotency, tool-generated (v4 top-level format validator)
  spec_version: z.literal(SPEC_VERSION),
  ts: z.iso.datetime(), // tool-observed time (advisory; host time is authoritative)
  call_id: z.string().min(1), // parent tools/call JSON-RPC request id
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
  // §7.6 Tier-1 abort codes. The witness axis adds two: a record no distinct party
  // confirmed, and one whose witness signature did not verify (§5.2, §7.2).
  reason: z
    .enum(['hash-mismatch', 'host-rejected', 'host-unavailable', 'host-unwitnessed', 'host-signature-invalid'])
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
  signer_seq: z.number().int().nonnegative().optional(), // per-key_id monotonic signer counter (gap detection)
  key_id: z.string().min(1).optional(), // non-empty; binds the signature algorithm via the registry (§5.1)
  signature: z
    .string()
    .regex(/^[A-Za-z0-9+/]+={0,2}$/)
    .optional(), // standard base64 with padding, not base64url (§5.1)
});

export type AuditEvent = z.infer<typeof auditEventSchema>;
