import { createHash, randomBytes } from 'node:crypto';

// The salted hash of an internal context (§4.3): the construction of SD-JWT [RFC-9901] §4.2.2 and
// §4.2.3, applied to the whole context as one array-element Disclosure. The Disclosure is
// base64url(UTF-8(JSON [salt, context])) and the salted hash is base64url(SHA-256(ASCII(Disclosure))).
// The digest is taken over the Disclosure string as the tool encoded it, so its JSON need not be
// canonical: whoever opens the hash is handed that exact string.

// RFC 9901 §4.2.1 recommends at least 128 bits of salt.
const SALT_BYTES = 16;

export const SALTED_HASH_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function newSalt(): string {
  return randomBytes(SALT_BYTES).toString('base64url');
}

export function disclosureOf(salt: string, context: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify([salt, context]), 'utf8').toString('base64url');
}

export function saltedHashOf(disclosure: string): string {
  return createHash('sha256').update(disclosure, 'ascii').digest('base64url');
}

// The context a Disclosure opens, if it is the one the salted hash commits to; undefined otherwise.
export function openSaltedHash(disclosure: string, saltedHash: string): Record<string, unknown> | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(disclosure) || saltedHashOf(disclosure) !== saltedHash) return undefined;
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(disclosure, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
  if (!Array.isArray(decoded) || decoded.length !== 2 || typeof decoded[0] !== 'string') return undefined;
  const context = decoded[1];
  if (context === null || typeof context !== 'object' || Array.isArray(context)) return undefined;
  return context as Record<string, unknown>;
}
