import { z } from 'zod/v4';
import { SPEC_VERSION } from './event.js';

// An audit capability object. It is read as a requirement when the host declares it and as a
// supported capability when the tool declares it; both directions are exchanged during the MCP
// initialize phase (§6.1). spec_version carries the supported Auditable MCP version so a common
// version is established before events (which carry spec_version) are exchanged.
export const auditCapabilitySchema = z.strictObject({
  spec_version: z.string(), // supported Auditable MCP version, e.g. auditable-mcp/0.1.1
  level: z.enum(['L1', 'L2']),
  attempt: z.literal('request'), // attempt is always a blocking request (fail-closed)
});

export type AuditCapability = z.infer<typeof auditCapabilitySchema>;

export const DEFAULT_L1_CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: 'L1',
  attempt: 'request',
};

// Level ordering: L2 obligations are a superset of L1, so an L2-capable tool satisfies an L1
// requirement (a safe downgrade), while an L1-only tool does not satisfy an L2 requirement.
const LEVEL_RANK: Record<string, number> = { L1: 1, L2: 2 };

export interface NegotiationResult {
  required: AuditCapability; // what the host requires
  satisfied: boolean; // whether the tool's offered capability meets it
}

// Truthfulness is not verified here; runtime validation (§7) enforces the required level. A
// spec_version mismatch is unsatisfiable at negotiation: events are version-specific, so there is
// no common wire format to fall back to (§6.1).
export function capabilitySatisfies(offered: AuditCapability, required: AuditCapability): boolean {
  if (offered.spec_version !== required.spec_version) return false;
  return (LEVEL_RANK[offered.level] ?? 0) >= (LEVEL_RANK[required.level] ?? 0);
}

// Compare a tool's offered capability against a host requirement (§6.1).
export function negotiateCapability(required: AuditCapability, offered: AuditCapability): NegotiationResult {
  return { required, satisfied: capabilitySatisfies(offered, required) };
}
