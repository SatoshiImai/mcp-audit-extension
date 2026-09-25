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

// A lone surrogate has no UTF-8 encoding, so JCS cannot serialize it and ports diverge on it (§8.1).
// With the `u` flag a paired surrogate reads as one astral code point, so only a lone one matches.
const LONE_SURROGATE = /\p{Cs}/u;

export function hasLoneSurrogate(value: unknown): boolean {
  if (typeof value === 'string') return LONE_SURROGATE.test(value);
  if (Array.isArray(value)) return value.some(hasLoneSurrogate);
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).some(([key, item]) => LONE_SURROGATE.test(key) || hasLoneSurrogate(item));
  }
  return false;
}

// Why a value lies outside the §8.1 canonicalization domain, or undefined when it lies inside it.
export function canonicalDomainError(value: unknown): string | undefined {
  if (hasUnsafeNumber(value)) return 'numeric-domain: a number is non-finite or outside +/-(2^53-1) (§8.1)';
  if (hasLoneSurrogate(value)) return 'lone-surrogate: a string is not a sequence of Unicode scalar values (§8.1)';
  return undefined;
}

export function canonicalize(value: unknown): string {
  const error = canonicalDomainError(value);
  if (error !== undefined) throw new RangeError(`not canonicalizable: ${error}`);
  return canonicalizeJcs(value) as string;
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// Hash a value into an action_context_hash: sha256 over its canonical bytes (§8).
export function hashCanonical(value: unknown): string {
  return `sha256:${sha256Hex(canonicalize(value))}`;
}
