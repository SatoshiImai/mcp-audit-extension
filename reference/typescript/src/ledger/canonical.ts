import { createHash } from 'node:crypto';
import canonicalizeJcs from 'canonicalize';

// Canonical JSON per the JSON Canonicalization Scheme (JCS, RFC 8785), delegated to the
// `canonicalize` package rather than a hand-rolled serializer. The Python port uses the
// `rfc8785` package; both implement RFC 8785 and produce byte-identical output (verified against
// the shared conformance vectors under spec/vectors).

// Numbers outside the §8.1 canonicalization domain: non-finite (no JCS form) or integer-valued
// beyond +/-(2^53-1). A runtime cannot tell an exact integer (which would not round-trip as an
// IEEE-754 double) from an integer-valued float, so all are conservatively rejected for cross-
// language identity. A host uses hasUnsafeNumber to reject such an event gracefully (§7.1) instead
// of letting canonicalize() round silently (TS) or throw at seal time (both ports).
export function hasUnsafeNumber(value: unknown): boolean {
  if (typeof value === 'number') return !Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value));
  if (Array.isArray(value)) return value.some(hasUnsafeNumber);
  if (value !== null && typeof value === 'object') return Object.values(value).some(hasUnsafeNumber);
  return false;
}

function assertSafeNumbers(value: unknown): void {
  if (hasUnsafeNumber(value)) {
    throw new RangeError('a numeric value is not canonicalizable (non-finite or outside +/-(2^53-1)) (§8.1)');
  }
}

export function canonicalize(value: unknown): string {
  assertSafeNumbers(value);
  return canonicalizeJcs(value) as string;
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// Hash a value into an action_context_hash: sha256 over its canonical bytes (§8).
export function hashCanonical(value: unknown): string {
  return `sha256:${sha256Hex(canonicalize(value))}`;
}
