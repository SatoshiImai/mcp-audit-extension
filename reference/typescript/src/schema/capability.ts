import { z } from 'zod/v4';
import { SPEC_VERSION } from './event.js';

// An audit capability object. It is read as a requirement when the host declares it and as a
// supported capability when the tool declares it. Where each travels is the binding's concern
// (§6.4, §6.5); what it holds and how two compare is §6.1's. spec_version carries the supported Auditable MCP version so a common
// version is established before events (which carry spec_version) are exchanged. All four fields
// are REQUIRED.
export const auditCapabilitySchema = z.strictObject({
  spec_version: z.string(), // supported Auditable MCP version, e.g. auditable-mcp/0.3
  level: z.enum(['L1', 'L2']),
  attempt: z.literal('request'), // attempt is always a blocking request (fail-closed)
  countersign: z.enum(['none', 'host']), // the host offers it, the tool requires it (§5.2)
});

export type AuditCapability = z.infer<typeof auditCapabilitySchema>;

export const DEFAULT_L1_CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: 'L1',
  attempt: 'request',
  countersign: 'none',
};

// The two axes run in opposite directions. On `level` the tool produces and the host requires, so
// an L2-capable tool satisfies an L1 requirement (a safe downgrade). On `countersign` (§5.2) the host
// produces and the tool requires, so a host offering `host` satisfies a tool requiring `none`.
const LEVEL_RANK: Record<string, number> = { L1: 1, L2: 2 };
const COUNTERSIGN_RANK: Record<string, number> = { none: 1, host: 2 };

// Why a call is or is not audit-negotiated (§6.2). `undeclared` is not a mismatch: nothing was
// offered to compare, and collapsing the two would brick the tool against ordinary MCP hosts.
export const NEGOTIATED = 'negotiated';
export const UNDECLARED = 'undeclared';
export const MISMATCH = 'mismatch';

export interface NegotiationResult {
  tool: AuditCapability;
  host: AuditCapability | undefined; // undefined when the peer declared no auditable-mcp extension
  outcome: typeof NEGOTIATED | typeof UNDECLARED | typeof MISMATCH;
  versionMatch: boolean;
  levelFit: boolean;
  countersignFit: boolean;
  negotiated: boolean; // true only for an audit-negotiated call; §6.2 governs every other case
}

// True if the tool offers at least the level the host requires (§6.1).
export function levelSatisfies(tool: AuditCapability, host: AuditCapability): boolean {
  return (LEVEL_RANK[tool.level] ?? 0) >= (LEVEL_RANK[host.level] ?? 0);
}

// True if the host provides at least the countersignature the tool requires (§5.2, §6.1).
export function countersignSatisfies(host: AuditCapability, tool: AuditCapability): boolean {
  return (COUNTERSIGN_RANK[host.countersign] ?? 0) >= (COUNTERSIGN_RANK[tool.countersign] ?? 0);
}

// Compare a host and a tool declaration (§6.1). A 0.x draft has no on-the-wire compatibility
// window, so a fit requires an exact spec_version match as well as both axes; the per-axis flags
// surface which one failed. Truthfulness is not verified here; runtime validation (§7) enforces the
// required level.
export function negotiateCapability(
  host: AuditCapability | undefined,
  tool: AuditCapability,
): NegotiationResult {
  if (host === undefined) {
    return {
      tool,
      host: undefined,
      outcome: UNDECLARED,
      versionMatch: false,
      levelFit: false,
      countersignFit: false,
      negotiated: false,
    };
  }
  const versionMatch = tool.spec_version === host.spec_version;
  const levelFit = levelSatisfies(tool, host);
  const countersignFit = countersignSatisfies(host, tool);
  const fits = versionMatch && levelFit && countersignFit;
  return {
    tool,
    host,
    outcome: fits ? NEGOTIATED : MISMATCH,
    versionMatch,
    levelFit,
    countersignFit,
    negotiated: fits,
  };
}
