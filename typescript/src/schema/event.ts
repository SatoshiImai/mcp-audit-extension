import { z } from 'zod/v4';
import { ACTION_TYPE_RE } from './actionType.js';

// Auditable MCP core audit event — single schema for Level 1 & Level 2 (design §3.1 INV-1).
// Trust-establishing fields (sequence/key_id/signature) are optional at the schema level
// so a Level-1 event (no signature) still validates as a Level-2 event: L1 ⊆ L2.

export const SPEC_VERSION = 'auditable-mcp/0.1';

// Tool-internal events emit only attempted/success/failed/aborted.
// denied/expired are Tyr CallTool-boundary outcomes, not Auditable MCP internal responses (§5).
export const OUTCOME = ['attempted', 'success', 'failed', 'aborted'] as const;
export type Outcome = (typeof OUTCOME)[number];

export const targetResourceSchema = z.object({
  kind: z.string().min(1), // e.g. "table" | "file" | "endpoint"
  ref: z.string().min(1), // e.g. "customers" | "/etc/hosts" | "https://api.stripe.com/..."
  scope_hint: z.string().optional(), // domain meaning, e.g. "row:consent_basis=marketing"
});

export const auditEventSchema = z.object({
  // --- identity / correlation ---
  id: z.uuid(), // idempotency, tool-generated (v4 top-level format validator)
  spec_version: z.literal(SPEC_VERSION),
  ts: z.iso.datetime(), // tool-observed time (advisory; host time is authoritative)
  call_id: z.string().min(1), // parent CallTool JSON-RPC request id
  traceparent: z.string().optional(), // W3C Trace Context

  // --- domain action ---
  action_type: z.string().regex(ACTION_TYPE_RE), // syntax only; core-ness is a soft classification
  mutates: z.boolean(), // required effect axis (orthogonal to action_type, §4.1 ①)
  egress: z.boolean(), // required effect axis; unknown fails safe to true (§4.1 ②)
  target_resource: targetResourceSchema,
  outcome: z.enum(OUTCOME),
  params_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/), // hashed, never raw (§4)

  // --- Level 2 only (optional at schema level to preserve INV-1) ---
  sequence: z.number().int().nonnegative().optional(), // per-tool monotonic (gap detection)
  key_id: z.string().optional(),
  signature: z.string().optional(),
});

export type AuditEvent = z.infer<typeof auditEventSchema>;
