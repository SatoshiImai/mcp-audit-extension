// action_type vocabulary: Core Enum + ext.<vendor>.<op> hybrid.
// Syntax is validated strictly; core membership is a soft classification (unknown values are
// accepted for forward-compat). The (mutates, egress) effect axis is orthogonal to the verb
// and fails safe to mutating+egress when it cannot be positively established.

// Dotted lowercase token. ext form requires >= 3 segments; other forms >= 2 and must not
// start with the reserved ext. prefix.
export const ACTION_TYPE_RE = /^(ext(\.[a-z0-9_]+){2,}|(?!ext(\.|$))[a-z0-9_]+(\.[a-z0-9_]+)+)$/;

// Core Enum v0.1 — 7 values. Queue/pubsub and compute-provisioning stay in ext.*.
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

// The declared effect is advisory; the host may override it. Resolves against the fail-safe
// floor: anything not known to be non-mutating/internal becomes mutating+egress.
export function resolveEffect(actionType: string, declared: Partial<Effect> | undefined): Effect {
  if (declared?.mutates !== undefined && declared?.egress !== undefined) {
    return { mutates: declared.mutates, egress: declared.egress };
  }
  // Well-known non-mutating core reads relax to a benign effect.
  const benignReads: ReadonlySet<string> = new Set(['db.read', 'fs.read', 'secret.read']);
  if (benignReads.has(actionType)) {
    return { mutates: declared?.mutates ?? false, egress: declared?.egress ?? false };
  }
  // Fail-safe: unknown / ext.* / api.request without a full declaration.
  return { mutates: declared?.mutates ?? true, egress: declared?.egress ?? true };
}
