import { describe, it, expect } from 'vitest';
import { isSyntacticallyValid, isCore, isExtension, resolveEffect } from './actionType.js';

describe('action_type syntax validation', () => {
  it('accepts core and ext dotted lowercase tokens', () => {
    expect(isSyntacticallyValid('db.write')).toBe(true);
    expect(isSyntacticallyValid('ext.stripe.refund_charge')).toBe(true);
    expect(isSyntacticallyValid('ext.aws.s3.put_object')).toBe(true);
  });

  it('rejects uppercase, whitespace, and malformed separators (canonicalization)', () => {
    expect(isSyntacticallyValid('DB.Write')).toBe(false);
    expect(isSyntacticallyValid('db write')).toBe(false);
    expect(isSyntacticallyValid('db')).toBe(false);
    expect(isSyntacticallyValid('ext.stripe')).toBe(false); // ext requires >= 3 segments
  });

  it('accepts an unknown core value syntactically (forward-compat: never rejects)', () => {
    // A value that a future v0.2 might add. A v0.1 host must not reject it at the wire;
    // core-membership is a separate classification layer.
    expect(isSyntacticallyValid('cloud.provision')).toBe(true);
    expect(isCore('cloud.provision')).toBe(false);
  });

  it('classifies core vs ext', () => {
    expect(isCore('secret.read')).toBe(true);
    expect(isExtension('ext.iot.valve_open')).toBe(true);
    expect(isExtension('db.read')).toBe(false);
  });
});

describe('effect axis fail-safe resolution', () => {
  it('honors a full declaration as-is', () => {
    expect(resolveEffect('db.write', { mutates: true, egress: false })).toEqual({ mutates: true, egress: false });
  });

  it('relaxes well-known non-mutating reads to a benign effect', () => {
    expect(resolveEffect('db.read', undefined)).toEqual({ mutates: false, egress: false });
    expect(resolveEffect('secret.read', undefined)).toEqual({ mutates: false, egress: false });
  });

  it('fails safe to mutating+egress for unknown / ext / api.request without a full declaration', () => {
    expect(resolveEffect('ext.stripe.refund_charge', undefined)).toEqual({ mutates: true, egress: true });
    expect(resolveEffect('api.request', undefined)).toEqual({ mutates: true, egress: true });
    expect(resolveEffect('cloud.provision', undefined)).toEqual({ mutates: true, egress: true });
  });
});
