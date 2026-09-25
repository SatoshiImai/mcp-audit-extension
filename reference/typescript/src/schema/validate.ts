import { auditEventSchema, type AuditEvent } from './event.js';
import { canonicalDomainError } from '../ledger/canonical.js';

export type StructureCheck = { ok: true; event: AuditEvent } | { ok: false; detail: string };

// Structural validity (§7.1 step 1): the shared schema with its presence rules, and the §8.1
// canonicalization domain. The event returned is a copy of the RECEIVED structure, never Zod's parsed
// output: Zod rebuilds objects, and the rebuild can differ from what arrived (it drops a `__proto__`
// member of action_context), which would hash a different event than the one received (§8).
export function checkEventStructure(raw: unknown): StructureCheck {
  const parsed = auditEventSchema.safeParse(raw);
  if (!parsed.success) return { ok: false, detail: parsed.error.message };
  const domain = canonicalDomainError(raw);
  if (domain !== undefined) return { ok: false, detail: domain };
  return { ok: true, event: structuredClone(raw) as AuditEvent };
}
