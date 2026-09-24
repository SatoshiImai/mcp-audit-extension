import { describe, expect, it } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import {
  type AuditCapability,
  DEFAULT_L1_CAPABILITY,
  MISMATCH,
  NEGOTIATED,
  negotiateCapability,
  UNDECLARED,
} from './capability.js';

// Capability negotiation on both axes (§6.1) and the absent declaration §6.2 governs.
const L2_REQUIRED: AuditCapability = { ...DEFAULT_L1_CAPABILITY, level: 'L2' };
const TOOL_L1: AuditCapability = { ...DEFAULT_L1_CAPABILITY, level: 'L1' };
const TOOL_L2: AuditCapability = { ...DEFAULT_L1_CAPABILITY, level: 'L2' };
const WITNESSING: AuditCapability = { ...DEFAULT_L1_CAPABILITY, witness: 'host' };

describe('capability negotiation (§6.1)', () => {
  it('an L1 host is satisfied by an L1 tool', () => {
    const result = new AuditHost('t#d').negotiate(TOOL_L1);
    expect(result.negotiated).toBe(true);
    expect(result.outcome).toBe(NEGOTIATED);
  });

  it('an L1 host is satisfied by an L2 tool', () => {
    expect(new AuditHost('t#d').negotiate(TOOL_L2).negotiated).toBe(true);
  });

  it('an L2 host is not satisfied by an L1 tool', () => {
    const result = new AuditHost('t#l2', L2_REQUIRED).negotiate(TOOL_L1);
    expect(result.negotiated).toBe(false);
    expect(result.outcome).toBe(MISMATCH);
    expect(result.levelFit).toBe(false);
  });

  it('an L2 host is satisfied by an L2 tool', () => {
    expect(new AuditHost('t#l2', L2_REQUIRED).negotiate(TOOL_L2).negotiated).toBe(true);
  });

  it('a spec_version mismatch is unsatisfiable', () => {
    const older: AuditCapability = { ...DEFAULT_L1_CAPABILITY, spec_version: 'auditable-mcp/0.1' };
    const result = new AuditHost('t#d').negotiate(older);
    expect(result.negotiated).toBe(false);
    expect(result.versionMatch).toBe(false);
  });

  it('a signing host satisfies a tool that requires a witness (§5.2)', () => {
    expect(negotiateCapability(WITNESSING, WITNESSING).negotiated).toBe(true);
  });

  it('a non-signing host cannot satisfy a tool that requires a witness', () => {
    const result = negotiateCapability(TOOL_L1, WITNESSING);
    expect(result.outcome).toBe(MISMATCH);
    expect(result.witnessFit).toBe(false);
    expect(result.levelFit).toBe(true);
  });

  it('the axes run in opposite directions', () => {
    expect(negotiateCapability(TOOL_L1, TOOL_L2).negotiated).toBe(true);
    expect(negotiateCapability(L2_REQUIRED, TOOL_L1).negotiated).toBe(false);
    expect(negotiateCapability(WITNESSING, TOOL_L1).negotiated).toBe(true);
    expect(negotiateCapability(TOOL_L1, WITNESSING).negotiated).toBe(false);
  });

  it('a host that declared nothing is not a mismatch (§6.2)', () => {
    const result = negotiateCapability(undefined, TOOL_L1);
    expect(result.outcome).toBe(UNDECLARED);
    expect(result.negotiated).toBe(false);
    expect(result.host).toBeUndefined();
  });
});
