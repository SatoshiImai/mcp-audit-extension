import { describe, expect, it } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import { type AuditCapability, DEFAULT_L1_CAPABILITY, negotiateCapability } from '../schema/capability.js';
import { InProcessTransport } from './inProcess.js';
import { MANDATORY, transportFor, UnnegotiatedSessionError } from './degradation.js';

// The §6.2 postures: what a tool does with a session that was not audit-negotiated.
const TOOL = DEFAULT_L1_CAPABILITY;
const REQUIRES_WITNESS: AuditCapability = { ...DEFAULT_L1_CAPABILITY, witness: 'host' };
const wire = () => new InProcessTransport(new AuditHost('tenant-a'));
const selfHosted = () => new InProcessTransport(new AuditHost('tool-local'));

describe('degradation postures (§6.2)', () => {
  it('a negotiated session uses the host', () => {
    const negotiated = wire();
    expect(transportFor(negotiateCapability(TOOL, TOOL), negotiated, selfHosted())).toBe(negotiated);
  });

  it('an undeclared host degrades to the tool’s own', () => {
    const fallback = selfHosted();
    expect(transportFor(negotiateCapability(undefined, TOOL), wire(), fallback)).toBe(fallback);
  });

  it('a mismatched host degrades the same way', () => {
    const older: AuditCapability = { ...DEFAULT_L1_CAPABILITY, spec_version: 'auditable-mcp/0.1' };
    const fallback = selfHosted();
    expect(transportFor(negotiateCapability(older, TOOL), wire(), fallback)).toBe(fallback);
  });

  it('the mandatory posture declines to serve', () => {
    expect(() => transportFor(negotiateCapability(undefined, TOOL), wire(), selfHosted(), MANDATORY)).toThrow(
      UnnegotiatedSessionError,
    );
  });

  it('the third posture is not available', () => {
    expect(() => transportFor(negotiateCapability(undefined, TOOL), wire())).toThrow('fallback');
  });

  it('a tool that requires a witness cannot degrade', () => {
    expect(() => transportFor(negotiateCapability(undefined, REQUIRES_WITNESS), wire(), selfHosted())).toThrow(
      'MANDATORY',
    );
  });
});
