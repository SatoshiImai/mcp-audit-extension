import { createHash } from 'node:crypto';

// Deterministic canonical JSON serialization for hashing (design audit-integrity §2:
// "決定的なフィールド順の canonical serialization に対してハッシュ" for verification
// reproducibility). Keys sorted recursively; no insignificant whitespace. Numbers and
// strings use JSON.stringify's canonical forms. undefined-valued keys are omitted.
export function canonicalize(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('cannot canonicalize non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    const body = keys.map((k) => `${JSON.stringify(k)}:${serialize(obj[k])}`).join(',');
    return `{${body}}`;
  }
  throw new Error(`cannot canonicalize value of type ${typeof value}`);
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// params_hash helper — tools hash their (masked) params, never the raw values (§4).
export function hashParams(params: unknown): string {
  return `sha256:${sha256Hex(canonicalize(params))}`;
}
