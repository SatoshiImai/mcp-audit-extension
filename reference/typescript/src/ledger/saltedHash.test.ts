import { describe, expect, it } from 'vitest';
import { disclosureOf, newSalt, openSaltedHash, SALTED_HASH_PATTERN, saltedHashOf } from './saltedHash.js';

describe('salted hash (§4.3)', () => {
  it('reproduces the digest of RFC 9901 §4.2.2', () => {
    expect(saltedHashOf('WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0')).toBe('pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo');
  });

  it('opens with the Disclosure it was taken over, and with nothing else', () => {
    const context = { table: 'customers', rows: 3 };
    const disclosure = disclosureOf(newSalt(), context);
    const hash = saltedHashOf(disclosure);
    expect(hash).toMatch(SALTED_HASH_PATTERN);
    expect(openSaltedHash(disclosure, hash)).toEqual(context);
    expect(openSaltedHash(disclosureOf(newSalt(), context), hash)).toBeUndefined();
  });

  it('gives two Disclosures of one context different hashes', () => {
    const context = { amount: 1 };
    expect(saltedHashOf(disclosureOf(newSalt(), context))).not.toBe(saltedHashOf(disclosureOf(newSalt(), context)));
  });

  it('refuses a Disclosure that is not a two-element array of a salt and an object', () => {
    for (const decoded of [['s'], ['s', 'US'], [1, {}], ['s', {}, 'x']]) {
      const disclosure = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');
      expect(openSaltedHash(disclosure, saltedHashOf(disclosure))).toBeUndefined();
    }
  });
});
