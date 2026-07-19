import { createHash } from 'node:crypto';
import canonicalizeJcs from 'canonicalize';

// Canonical JSON per the JSON Canonicalization Scheme (JCS, RFC 8785), delegated to the
// `canonicalize` package rather than a hand-rolled serializer. The Python port uses the
// `rfc8785` package; both implement RFC 8785 and produce byte-identical output (verified against
// the shared conformance vectors under spec/vectors).
export function canonicalize(value: unknown): string {
  return canonicalizeJcs(value) as string;
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// Hash a value into an action_context_hash: sha256 over its canonical bytes (§8).
export function hashCanonical(value: unknown): string {
  return `sha256:${sha256Hex(canonicalize(value))}`;
}
