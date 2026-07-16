// action_type vocabulary — Core Enum + ext.<vendor>.<op> hybrid (design §4.1).
// Two design rules encoded here:
//  - Syntax is validated strictly; "is it core?" is a soft classification, never a
//    validation reject. This keeps a v0.1 host from rejecting a future v0.2 core value
//    (forward-compat, §4.1 ⑤).
//  - The (mutates, egress) effect axis is orthogonal to action_type. When effect cannot
//    be positively established as non-mutating/internal, it fails safe to mutating+egress
//    (§4.1 ②), because ext.* and api.request hide the security axis in the verb.

// Syntactically valid dotted lowercase token. Two shapes:
//  - ext form: `ext.<vendor>.<op...>` — the literal `ext` prefix requires >= 3 segments.
//  - other:    `<domain>.<op...>` — >= 2 segments, and must NOT start with the reserved
//    `ext.` prefix (so `ext.stripe` cannot sneak through as a plain 2-segment token).
export const ACTION_TYPE_RE = /^(ext(\.[a-z0-9_]+){2,}|(?!ext(\.|$))[a-z0-9_]+(\.[a-z0-9_]+)+)$/;

// Core Enum v0.1 — 7 values. Only "semantically pure" internal operations live here;
// queue/pubsub and compute-provisioning deliberately stay in ext.* (design §4.1).
export const CORE_ACTION_TYPES = [
  'db.read',
  'db.write',
  'fs.read',
  'fs.write',
  'api.request',
  'os.exec',
  'secret.read',
] as const;

export type CoreActionType = (typeof CORE_ACTION_TYPES)[number];

const CORE_SET: ReadonlySet<string> = new Set(CORE_ACTION_TYPES);

export function isSyntacticallyValid(actionType: string): boolean {
  return ACTION_TYPE_RE.test(actionType);
}

export function isCore(actionType: string): actionType is CoreActionType {
  return CORE_SET.has(actionType);
}

export function isExtension(actionType: string): boolean {
  return actionType.startsWith('ext.');
}

export interface Effect {
  mutates: boolean;
  egress: boolean;
}

// Effect the tool self-declares is advisory; the host may override with its own
// classification (design §4.1 ③). This resolves the declared effect against the
// fail-safe floor: anything not positively known to be non-mutating/internal is treated
// as mutating+egress so unknown/ext actions never look lower-risk than they are.
export function resolveEffect(actionType: string, declared: Partial<Effect> | undefined): Effect {
  if (declared?.mutates !== undefined && declared?.egress !== undefined) {
    return { mutates: declared.mutates, egress: declared.egress };
  }
  // Only well-known non-mutating core reads may relax to a benign effect.
  const benignReads: ReadonlySet<string> = new Set(['db.read', 'fs.read', 'secret.read']);
  if (benignReads.has(actionType)) {
    return { mutates: declared?.mutates ?? false, egress: declared?.egress ?? false };
  }
  // Fail-safe: unknown / ext.* / api.request without a full declaration → highest scrutiny.
  return { mutates: declared?.mutates ?? true, egress: declared?.egress ?? true };
}
