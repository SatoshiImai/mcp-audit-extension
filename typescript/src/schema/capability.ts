import { z } from 'zod/v4';

// Host-declared audit capability. The host owns the guarantee level; the tool complies or
// fails observably. Declaration flows host->tool only.
export const auditCapabilitySchema = z.object({
  level: z.enum(['L1', 'L2']),
  attempt: z.literal('request'), // attempt is always a blocking request (fail-closed)
  attempt_ack_deadline_ms: z.number().int().positive().default(500),
  // How a blocked (reject/unavailable) internal action is surfaced in the CallTool result.
  // "abort" is the safe floor; "partial" is opt-in.
  block_disposition: z.array(z.enum(['abort', 'partial'])).default(['abort']),
  outcome_mode: z.enum(['batched', 'request']).default('batched'),
  outcome_batch_window_ms: z.number().int().nonnegative().default(200),
});

export type AuditCapability = z.infer<typeof auditCapabilitySchema>;

export const DEFAULT_L1_CAPABILITY: AuditCapability = {
  level: 'L1',
  attempt: 'request',
  attempt_ack_deadline_ms: 500,
  block_disposition: ['abort'],
  outcome_mode: 'batched',
  outcome_batch_window_ms: 200,
};
